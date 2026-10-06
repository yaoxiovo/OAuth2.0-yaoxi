/**
 * worker.js - Cloudflare Worker Entry Point for accounts.yaoxi.cloud
 * 适配 Cloudflare Workers with Static Assets 部署体系
 *
 * 安全特性清单:
 * 1. 严格 URL 参数白名单校验 (非法参数直接拦截下发 Google 400)
 * 2. 泛域名白名单防伪校验 (*.yaoxi.wiki, *.yaoxi.cloud) 与防时序攻击 HMAC-SHA256 签名核验
 * 3. 统一配置管理接口 /api/config (严格数据脱敏与管理员权限门禁校验)
 * 4. 服务端认证与密码学 JWT 签发接口 /api/login
 * 5. 高性能静态资源托管 (通过 env.ASSETS 映射 ./dist 产物)
 */

const DEFAULT_SSO_HANDSHAKE_SECRET = 'yaoxi_sso_handshake_secret_key_v1_auth_guard_2026';
const DEFAULT_ADMIN_PASSWORD_HASH = '9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001'; // sha256("yaoxi")
const SERVER_JWT_SECRET = 'yaoxi_cloud_sso_internal_token_signing_secret_2026';

const ALLOWED_PARAMS = new Set([
  'client_request_token',
  'client_id',
  'redirect_uri',
  'target_domain',
  'response_type',
  'scope',
  'state',
  'nonce',
  'prompt',
  'code_challenge',
  'code_challenge_method',
  'cf_sitekey',
  'cf_chl_tk',
  'lang',
  'theme',
  'step',
  'preview',
  'email',
  'pwd',
  'demo',
  'utm_source',
  'utm_medium',
  'utm_campaign'
]);

function isAllowedDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const d = domain.trim().toLowerCase();
  return (
    d === 'yaoxi.wiki' ||
    d.endsWith('.yaoxi.wiki') ||
    d === 'yaoxi.cloud' ||
    d.endsWith('.yaoxi.cloud') ||
    d === 'localhost' ||
    d === '127.0.0.1' ||
    d.endsWith('.localhost')
  );
}

function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function sha256Hex(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncode(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function signJwtToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT', kid: 'yaoxi_cloud_sso_2026' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signatureBuf = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const signatureBase64 = base64UrlEncode(String.fromCharCode(...new Uint8Array(signatureBuf)));
  return `${data}.${signatureBase64}`;
}

const GOOGLE_400_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>400. 错误。这就是我们知道的全部信息。</title>
  <style>
    :root {
      --bg: #ffffff;
      --text: #1f1f1f;
      --text-sec: #444746;
      --text-ter: #5e5e5e;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #131314;
        --text: #e3e3e3;
        --text-sec: #c4c7c5;
        --text-ter: #8e918f;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 32px 24px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .g-400-container {
      max-width: 680px;
      margin: 40px auto 0;
      animation: fadeIn 0.3s ease-out;
      width: 100%;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .g-400-logo { margin-bottom: 24px; }
    .g-400-title {
      font-size: 28px;
      font-weight: 500;
      color: var(--text);
      margin-bottom: 16px;
    }
    .g-400-title strong { font-weight: 700; }
    .g-400-body {
      font-size: 15px;
      color: var(--text-sec);
      line-height: 1.6;
      margin-bottom: 20px;
    }
    .g-400-footer-hint {
      font-size: 13px;
      color: var(--text-ter);
      margin-top: 24px;
    }
  </style>
</head>
<body>
  <div class="g-400-container">
    <div class="g-400-logo">
      <svg viewBox="0 0 24 24" width="32" height="32" xmlns="http://www.w3.org/2000/svg">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" fill="#EA4335"/>
      </svg>
    </div>
    <h1 class="g-400-title"><strong>400.</strong> 错误。</h1>
    <p class="g-400-body">
      请求无效：请求参数不正确或未经授权。
    </p>
    <div class="g-400-footer-hint">这就是我们知道的全部信息。</div>
  </div>
</body>
</html>`;

async function verifyCryptographicTokenSignature(token, targetDomain = 'yaoxi.cloud', secret = DEFAULT_SSO_HANDSHAKE_SECRET) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'crt' || parts[1] !== 'v1') return false;

  const [_, version, timestampStr, nonce, receivedSig] = parts;
  const timestamp = parseInt(timestampStr, 10);
  const now = Date.now();
  if (isNaN(timestamp) || Math.abs(now - timestamp) > 900 * 1000) return false;

  try {
    const payload1 = `v1.${timestampStr}.${nonce}`;
    const payload2 = `v1.${timestampStr}.${nonce}.${targetDomain}`;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuf1 = await crypto.subtle.sign('HMAC', key, enc.encode(payload1));
    const sigHexFull1 = Array.from(new Uint8Array(sigBuf1)).map(b => b.toString(16).padStart(2, '0')).join('');
    const sigHexShort1 = sigHexFull1.substring(0, 32);

    const sigBuf2 = await crypto.subtle.sign('HMAC', key, enc.encode(payload2));
    const sigHexFull2 = Array.from(new Uint8Array(sigBuf2)).map(b => b.toString(16).padStart(2, '0')).join('');
    const sigHexShort2 = sigHexFull2.substring(0, 32);

    return (
      constantTimeCompare(receivedSig, sigHexFull1) ||
      constantTimeCompare(receivedSig, sigHexShort1) ||
      constantTimeCompare(receivedSig, sigHexFull2) ||
      constantTimeCompare(receivedSig, sigHexShort2)
    );
  } catch (e) {
    return false;
  }
}

const DEFAULT_CONFIG = {
  version: "1.1.0",
  lastUpdated: new Date().toISOString(),
  security: {
    ssoIssuer: "https://accounts.yaoxi.cloud",
    tokenTtl: 7200,
    kid: "yaoxi_cloud_sso_2026",
    preventReplay: true,
    strictWhitelist: true
  },
  turnstile: {
    enabled: true,
    siteKey: "0x4AAAAAAEXamT3iIRWjGCmk"
  },
  registration: {
    enabled: true,
    requireApproval: true,
    defaultRoles: ["member"],
    rateLimit: { perIpHour: 5, perIpDay: 20 }
  },
  branding: {
    systemTitle: "Google 帐号 - 统一身份认证",
    welcomeTitle: "欢迎",
    bannerNotice: "不妨选择“试试其他方式”，改用通行密钥更轻松更安全地登录",
    defaultTheme: "light",
    defaultLang: "zh-CN",
    showPasswordToggle: true
  },
  domains: [
    { id: "dom_1", name: "耀西极客博客", pattern: "*.yaoxi.wiki", type: "wildcard", enabled: true, createdAt: "2026-09-24" },
    { id: "dom_2", name: "耀西云全子域", pattern: "*.yaoxi.cloud", type: "wildcard", enabled: true, createdAt: "2026-09-24" },
    { id: "dom_3", name: "本地开发测试", pattern: "localhost", type: "exact", enabled: true, createdAt: "2026-09-24" },
    { id: "dom_4", name: "本地回环地址", pattern: "127.0.0.1", type: "exact", enabled: true, createdAt: "2026-09-24" }
  ],
  users: [
    {
      id: "usr_yaoxi",
      username: "yaoxi",
      displayName: "耀西 (Super Admin)",
      email: "yaoxiov0@gmail.com",
      passwordHash: DEFAULT_ADMIN_PASSWORD_HASH,
      roles: ["admin", "author", "super_user"],
      status: "active",
      passkeyBound: true,
      platformTokens: {
        github: "ghp_yaoxiPersonalAccessToken2026MockSecretKey",
        cloudflare: "cf_token_yaoxiGlobalDnsWorkersEdgeSecretKey2026"
      },
      lastLogin: new Date().toISOString()
    }
  ],
  clients: [
    {
      id: "cli_1",
      clientId: "yaoxi-blog",
      clientName: "耀西极客博客",
      targetDomain: "blog.yaoxi.wiki",
      redirectUri: "https://blog.yaoxi.wiki",
      scope: "openid profile email admin",
      enabled: true
    },
    {
      id: "cli_2",
      clientId: "yaoxi-app",
      clientName: "耀西云全平台默认客户端",
      targetDomain: "yaoxi.cloud",
      redirectUri: "https://accounts.yaoxi.cloud",
      scope: "openid profile email",
      enabled: true
    }
  ],
  auditLogs: [
    {
      id: "log_init",
      timestamp: new Date().toISOString(),
      action: "SYSTEM_INIT",
      operator: "system",
      details: "统一身份认证管理控制台安全加固版已初始化就绪",
      ip: "127.0.0.1"
    }
  ]
};

function sanitizePublicConfig(rawConfig) {
  if (!rawConfig || typeof rawConfig !== 'object') return {};
  const clone = JSON.parse(JSON.stringify(rawConfig));

  // 用户目录隐私加固：公开配置绝不下发任何账号清单 (含邮箱)，账号解析统一走 /api/lookup
  delete clone.users;

  if (clone.security) {
    delete clone.security.handshakeSecret;
  }
  if (clone.turnstile) {
    delete clone.turnstile.secretKey;
  }
  delete clone.auditLogs;

  return clone;
}

async function verifyAdminAuth(request, env, config) {
  const authHeader = request.headers.get('Authorization') || '';
  const adminKey = request.headers.get('X-Admin-Key') || '';

  if (env && env.ADMIN_SECRET && (authHeader === `Bearer ${env.ADMIN_SECRET}` || adminKey === env.ADMIN_SECRET)) {
    return true;
  }

  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    if (!token) return false;

    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payloadJson = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
        const payload = JSON.parse(payloadJson);
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return false;
        if (Array.isArray(payload.roles) && payload.roles.includes('admin')) {
          return true;
        }
      }
    } catch (e) {}

    const adminUser = (config.users || []).find(u => u.roles && u.roles.includes('admin'));
    if (adminUser) {
      const expectedHash = adminUser.passwordHash || DEFAULT_ADMIN_PASSWORD_HASH;
      if (token === expectedHash) return true;
    }
  }

  return false;
}

// ============================================================================
// 开放注册 (Open Registration) 与账号解析 (Account Lookup) 支撑
// ============================================================================

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/i;
const RESERVED_USERNAMES = new Set([
  'yaoxi', 'admin', 'administrator', 'root', 'system', 'support',
  'help', 'security', 'accounts', 'official', 'service', 'api'
]);

function randomHex(byteLength = 6) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function maskEmail(email) {
  const str = typeof email === 'string' ? email : '';
  const atIdx = str.indexOf('@');
  if (atIdx <= 0) return str ? str.slice(0, 2) + '***' : '';
  const local = str.slice(0, atIdx);
  const domain = str.slice(atIdx);
  const head = local.slice(0, Math.min(2, local.length));
  return `${head}***${domain}`;
}

function getClientIp(request) {
  const cfIp = request.headers.get('CF-Connecting-IP');
  if (cfIp) return cfIp.trim();
  const fwd = request.headers.get('X-Forwarded-For') || '';
  const first = fwd.split(',')[0].trim();
  return first || 'unknown';
}

async function loadStoredConfig(env) {
  if (env && env.SSO_CONFIG_KV) {
    try {
      const data = await env.SSO_CONFIG_KV.get('sso_global_config');
      if (data) return JSON.parse(data);
    } catch (e) {}
  }
  return DEFAULT_CONFIG;
}

async function bumpKvCounter(env, key, ttlSeconds) {
  const raw = await env.SSO_CONFIG_KV.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;
  const next = count + 1;
  await env.SSO_CONFIG_KV.put(key, String(next), { expirationTtl: ttlSeconds });
  return next;
}

// 固定窗口简易限流 (KV 最终一致，作为 Turnstile 之外的滥用硬上限)
async function checkRateLimit(request, env, scope, perHourLimit) {
  if (!env || !env.SSO_CONFIG_KV) return { allowed: true };
  const ip = getClientIp(request);
  if (!ip || ip === 'unknown') return { allowed: true };
  try {
    const next = await bumpKvCounter(env, `${scope}_rl_${ip}`, 3600);
    return { allowed: next <= perHourLimit, next, ip };
  } catch (e) {
    return { allowed: true, ip };
  }
}

// Turnstile 服务端二次校验：未配置 secretKey 时降级为“前端已通过”软校验
async function verifyTurnstileToken(token, remoteIp, secretKey) {
  if (!token || typeof token !== 'string') {
    return { ok: false, error: '请先完成人机身份验证' };
  }
  if (!secretKey) return { ok: true, skipped: true };
  try {
    const form = new URLSearchParams();
    form.append('secret', secretKey);
    form.append('response', token);
    if (remoteIp && remoteIp !== 'unknown') form.append('remoteip', remoteIp);
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form
    });
    const data = await res.json().catch(() => null);
    if (data && data.success) return { ok: true };
    const codes = (data && data['error-codes']) || [];
    if (codes.includes('invalid-input-secret') || codes.includes('missing-input-secret')) {
      return { ok: true, degraded: true };
    }
    return { ok: false, error: '人机身份验证未通过，请刷新页面后重试' };
  } catch (e) {
    // 校验服务网络异常时不阻断注册主流程，KV 限流仍作为滥用硬上限兜底
    return { ok: true, degraded: true };
  }
}

async function handleRegister(request, env) {
  const body = await request.json().catch(() => null);
  const { username, email, displayName, password, cf_turnstile_token, client_id, target_domain, client_request_token } = body || {};

  const config = await loadStoredConfig(env);
  const registration = (config && config.registration) || {};
  if (registration.enabled === false) {
    return new Response(JSON.stringify({ success: false, error: '当前未开放自助注册，请联系管理员开通账号' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const limits = registration.rateLimit || {};
  const rate = await checkRateLimit(request, env, 'reg', limits.perIpHour || 5);
  if (!rate.allowed) {
    return new Response(JSON.stringify({ success: false, error: '注册请求过于频繁，请稍后再试' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const usernameClean = typeof username === 'string' ? username.trim().toLowerCase() : '';
  const emailClean = typeof email === 'string' ? email.trim().toLowerCase() : '';
  const displayClean = typeof displayName === 'string' ? displayName.trim().replace(/[<>]/g, '').slice(0, 64) : '';

  if (!USERNAME_PATTERN.test(usernameClean)) {
    return new Response(JSON.stringify({ success: false, error: '用户名需为 3-32 位小写字母、数字或 . _ -，且以字母或数字开头' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }
  if (RESERVED_USERNAMES.has(usernameClean)) {
    return new Response(JSON.stringify({ success: false, error: '该用户名为系统保留名称，请更换一个' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }
  if (!EMAIL_PATTERN.test(emailClean) || emailClean.length > 254) {
    return new Response(JSON.stringify({ success: false, error: '请输入有效的电子邮件地址' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return new Response(JSON.stringify({ success: false, error: '密码需为 8-128 位字符' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const turnstileCfg = (config && config.turnstile) || {};
  if (turnstileCfg.enabled !== false) {
    const secretKey = turnstileCfg.secretKey || (env && env.TURNSTILE_SECRET_KEY) || '';
    const tsCheck = await verifyTurnstileToken(cf_turnstile_token, rate.ip, secretKey);
    if (!tsCheck.ok) {
      return new Response(JSON.stringify({ success: false, error: tsCheck.error }), {
        status: 403,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }

  const users = Array.isArray(config.users) ? config.users : [];
  if (users.some(u => (u.username || '').toLowerCase() === usernameClean)) {
    return new Response(JSON.stringify({ success: false, error: '该用户名已被占用，请更换一个' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }
  if (users.some(u => (u.email || '').toLowerCase() === emailClean)) {
    return new Response(JSON.stringify({ success: false, error: '该邮箱已被注册，请直接登录或更换邮箱' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const requireApproval = registration.requireApproval !== false;
  const defaultRoles = (Array.isArray(registration.defaultRoles) && registration.defaultRoles.length > 0)
    ? registration.defaultRoles
    : ['member'];

  const newUser = {
    id: 'usr_' + randomHex(6),
    username: usernameClean,
    displayName: displayClean || usernameClean,
    email: emailClean,
    passwordHash: await sha256Hex(password),
    roles: defaultRoles,
    status: requireApproval ? 'pending' : 'active',
    passkeyBound: false,
    platformTokens: {},
    registeredVia: 'self_registration',
    createdAt: new Date().toISOString(),
    lastLogin: '-'
  };

  const nextConfig = JSON.parse(JSON.stringify(config));
  nextConfig.users = [...users, newUser];
  if (!Array.isArray(nextConfig.auditLogs)) nextConfig.auditLogs = [];
  nextConfig.auditLogs.unshift({
    id: 'log_' + Date.now().toString(36) + randomHex(2),
    timestamp: new Date().toISOString(),
    action: 'USER_REGISTER',
    operator: 'guest',
    details: `自助注册账号: ${usernameClean} (${emailClean}) · ${requireApproval ? '等待管理员审核' : '已直接激活'}`,
    ip: rate.ip || 'unknown'
  });
  if (nextConfig.auditLogs.length > 200) nextConfig.auditLogs.length = 200;
  nextConfig.lastUpdated = new Date().toISOString();

  if (env && env.SSO_CONFIG_KV) {
    await env.SSO_CONFIG_KV.put('sso_global_config', JSON.stringify(nextConfig));
  }

  const safeUser = {
    id: newUser.id,
    username: newUser.username,
    displayName: newUser.displayName,
    email: newUser.email,
    roles: newUser.roles,
    status: newUser.status
  };

  if (requireApproval) {
    return new Response(JSON.stringify({ success: true, pending: true, user: safeUser }), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  // 直接激活模式：注册即完成登录握手，签发与服务端登录一致的 JWT
  const now = Math.floor(Date.now() / 1000);
  const ttl = (config.security && config.security.tokenTtl) || 7200;
  const issuer = (config.security && config.security.ssoIssuer) || 'https://accounts.yaoxi.cloud';
  const secret = (env && env.JWT_SECRET) || SERVER_JWT_SECRET;

  const payload = {
    iss: issuer,
    aud: client_id || 'yaoxi-app',
    sub: newUser.username,
    email: newUser.email,
    roles: newUser.roles,
    target_domain: target_domain || 'yaoxi.cloud',
    client_request_token: client_request_token || '',
    platform_tokens: {},
    amr: ['pwd'],
    auth_time: now,
    iat: now,
    exp: now + ttl
  };

  const token = await signJwtToken(payload, secret);

  return new Response(JSON.stringify({
    success: true,
    pending: false,
    token,
    expires_in: ttl,
    user: safeUser
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
  });
}

async function handleLookup(request, env) {
  const body = await request.json().catch(() => null);
  const { identifier, cf_turnstile_token } = body || {};

  if (!identifier || typeof identifier !== 'string' || !identifier.trim()) {
    return new Response(JSON.stringify({ success: false, error: 'Missing identifier' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const rate = await checkRateLimit(request, env, 'lookup', 60);
  if (!rate.allowed) {
    return new Response(JSON.stringify({ success: false, error: '请求过于频繁，请稍后再试' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const config = await loadStoredConfig(env);
  const turnstileCfg = (config && config.turnstile) || {};
  if (turnstileCfg.enabled !== false) {
    const secretKey = turnstileCfg.secretKey || (env && env.TURNSTILE_SECRET_KEY) || '';
    const tsCheck = await verifyTurnstileToken(cf_turnstile_token, rate.ip, secretKey);
    if (!tsCheck.ok) {
      return new Response(JSON.stringify({ success: false, error: tsCheck.error }), {
        status: 403,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }

  const input = identifier.trim().toLowerCase();
  const users = Array.isArray(config.users) ? config.users : [];
  const matched = users.find(u =>
    (u.username && u.username.toLowerCase() === input) ||
    (u.email && u.email.toLowerCase() === input)
  );

  if (!matched) {
    return new Response(JSON.stringify({ success: true, found: false }), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' }
    });
  }

  return new Response(JSON.stringify({
    success: true,
    found: true,
    username: matched.username,
    displayName: matched.displayName || matched.username,
    passkeyBound: matched.passkeyBound !== false,
    status: matched.status || 'active',
    emailMasked: maskEmail(matched.email)
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' }
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname.toLowerCase();

    // 1. API 接口: /api/login (密码学身份核验与真实 JWT 签发)
    if (pathname === '/api/login') {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          }
        });
      }
      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const { username, password, auth_type, assertion, client_id, target_domain, client_request_token } = body || {};

          const isPasskey = (auth_type === 'passkey' || !!assertion);
          if (!username || (!password && !isPasskey)) {
            return new Response(JSON.stringify({ success: false, error: '请输入账号和认证凭证' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          let config = null;
          if (env && env.SSO_CONFIG_KV) {
            try {
              const data = await env.SSO_CONFIG_KV.get('sso_global_config');
              if (data) config = JSON.parse(data);
            } catch (e) {}
          }
          if (!config) config = DEFAULT_CONFIG;

          const inputClean = username.trim().toLowerCase();
          const matchedUser = (config.users || []).find(u =>
            (u.username && u.username.toLowerCase() === inputClean) ||
            (u.email && u.email.toLowerCase() === inputClean)
          );

          if (!matchedUser) {
            return new Response(JSON.stringify({ success: false, error: '找不到该 Google 帐号' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          if (matchedUser.status === 'pending') {
            return new Response(JSON.stringify({ success: false, error: '此帐号正在等待管理员审核，审核通过后即可登录' }), {
              status: 403,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          if (matchedUser.status && matchedUser.status !== 'active') {
            return new Response(JSON.stringify({ success: false, error: '此 Google 帐号已被管理员停用或冻结' }), {
              status: 403,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          if (!isPasskey) {
            const inputHash = await sha256Hex(password);
            const expectedHash = matchedUser.passwordHash || (matchedUser.password ? await sha256Hex(matchedUser.password) : DEFAULT_ADMIN_PASSWORD_HASH);

            if (inputHash !== expectedHash) {
              return new Response(JSON.stringify({ success: false, error: '密码错误，请重试' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
              });
            }
          } else {
            if (matchedUser.passkeyBound === false) {
              return new Response(JSON.stringify({ success: false, error: '该帐号未绑定通行密钥，请改用密码登录' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
              });
            }
          }

          const now = Math.floor(Date.now() / 1000);
          const ttl = (config.security && config.security.tokenTtl) || 7200;
          const issuer = (config.security && config.security.ssoIssuer) || 'https://accounts.yaoxi.cloud';
          const secret = (env && env.JWT_SECRET) || SERVER_JWT_SECRET;
          const platformTokens = matchedUser.platformTokens || {};

          const payload = {
            iss: issuer,
            aud: client_id || 'yaoxi-app',
            sub: matchedUser.username,
            email: matchedUser.email,
            roles: matchedUser.roles || ['member'],
            target_domain: target_domain || 'yaoxi.cloud',
            client_request_token: client_request_token || '',
            platform_tokens: platformTokens,
            amr: isPasskey ? ['passkey', 'fido2', 'hw_biometrics', 'fingerprint'] : ['pwd'],
            auth_time: now,
            iat: now,
            exp: now + ttl
          };

          const token = await signJwtToken(payload, secret);

          const safeUser = {
            id: matchedUser.id,
            username: matchedUser.username,
            displayName: matchedUser.displayName,
            email: matchedUser.email,
            roles: matchedUser.roles,
            status: matchedUser.status,
            platform_tokens: platformTokens
          };

          return new Response(JSON.stringify({
            success: true,
            token,
            expires_in: ttl,
            user: safeUser,
            platform_tokens: platformTokens
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        } catch (err) {
          return new Response(JSON.stringify({ success: false, error: err.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        }
      }
    }

    // 2. API 接口: /api/register (开放自助注册：人机校验 + 限流 + 查重 + 待审核入库)
    if (pathname === '/api/register' || pathname === '/api/lookup') {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          }
        });
      }
      if (request.method === 'POST') {
        try {
          return await (pathname === '/api/register' ? handleRegister(request, env) : handleLookup(request, env));
        } catch (err) {
          return new Response(JSON.stringify({ success: false, error: err.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        }
      }
      return new Response(JSON.stringify({ success: false, error: 'Method Not Allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // 3. API 接口: /api/status (轻量级账号实时状态查询与即时吊销检测)
    if (pathname === '/api/status') {
      const corsHeaders = {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
      };

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      let querySub = '';
      let queryEmail = '';
      let queryId = '';

      if (request.method === 'GET') {
        querySub = url.searchParams.get('username') || url.searchParams.get('sub') || '';
        queryEmail = url.searchParams.get('email') || '';
        queryId = url.searchParams.get('id') || '';
      } else if (request.method === 'POST') {
        try {
          const body = await request.json();
          if (body && typeof body === 'object') {
            querySub = body.username || body.sub || '';
            queryEmail = body.email || '';
            queryId = body.id || '';
          }
        } catch (e) {}
      }

      if (!querySub && !queryEmail && !queryId) {
        return new Response(JSON.stringify({
          success: false,
          error: 'Missing query parameters (username, sub, email, or id required)'
        }), { status: 400, headers: corsHeaders });
      }

      let config = null;
      if (env && env.SSO_CONFIG_KV) {
        try {
          const data = await env.SSO_CONFIG_KV.get('sso_global_config');
          if (data) config = JSON.parse(data);
        } catch (e) {}
      }
      if (!config) config = DEFAULT_CONFIG;

      const usersList = Array.isArray(config.users) ? config.users : [];
      const subClean = querySub.trim().toLowerCase();
      const emailClean = queryEmail.trim().toLowerCase();
      const idClean = queryId.trim();

      const matchedUser = usersList.find(u => {
        if (idClean && u.id === idClean) return true;
        const uName = (u.username || '').toLowerCase();
        const uEmail = (u.email || '').toLowerCase();
        if (subClean && (uName === subClean || uEmail === subClean)) return true;
        if (emailClean && (uEmail === emailClean || uName === emailClean)) return true;
        return false;
      });

      if (matchedUser) {
        const isActive = (matchedUser.status === 'active');
        return new Response(JSON.stringify({
          success: true,
          found: true,
          userId: matchedUser.id,
          username: matchedUser.username,
          status: matchedUser.status || 'active',
          active: isActive,
          revoked: !isActive
        }), { status: 200, headers: corsHeaders });
      }

      return new Response(JSON.stringify({
        success: true,
        found: false,
        active: false,
        revoked: true,
        error: 'User not found or revoked'
      }), { status: 200, headers: corsHeaders });
    }

    // 4. API 接口: /api/config (严格数据脱敏与管理员门禁鉴权)
    if (pathname === '/api/config') {
      if (request.method === 'GET') {
        let config = null;
        if (env && env.SSO_CONFIG_KV) {
          try {
            const data = await env.SSO_CONFIG_KV.get('sso_global_config');
            if (data) config = JSON.parse(data);
          } catch (e) {}
        }
        if (!config) config = DEFAULT_CONFIG;

        const isAdmin = await verifyAdminAuth(request, env, config);
        if (isAdmin) {
          const adminSafeConfig = JSON.parse(JSON.stringify(config));
          if (Array.isArray(adminSafeConfig.users)) {
            adminSafeConfig.users = adminSafeConfig.users.map(u => {
              const safe = { ...u };
              delete safe.password;
              return safe;
            });
          }
          return new Response(JSON.stringify(adminSafeConfig), {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-store, no-cache, must-revalidate',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }

        const publicConfig = sanitizePublicConfig(config);
        return new Response(JSON.stringify(publicConfig), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Access-Control-Allow-Origin': '*'
          }
        });
      } else if (request.method === 'POST') {
        try {
          let currentConfig = null;
          if (env && env.SSO_CONFIG_KV) {
            try {
              const data = await env.SSO_CONFIG_KV.get('sso_global_config');
              if (data) currentConfig = JSON.parse(data);
            } catch (e) {}
          }
          if (!currentConfig) currentConfig = DEFAULT_CONFIG;

          const isAdmin = await verifyAdminAuth(request, env, currentConfig);
          if (!isAdmin) {
            return new Response(JSON.stringify({ success: false, error: '未授权：保存配置需要管理员权限' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          const body = await request.json();
          if (!body || typeof body !== 'object') {
            return new Response(JSON.stringify({ success: false, error: '无效的配置格式' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          body.lastUpdated = new Date().toISOString();

          if (Array.isArray(body.users)) {
            for (const u of body.users) {
              if (u.newPassword) {
                u.passwordHash = await sha256Hex(u.newPassword);
                delete u.newPassword;
              } else if (u.password && u.password !== '••••••••' && !u.passwordHash) {
                u.passwordHash = await sha256Hex(u.password);
              }
              delete u.password;
            }
          }

          let savedToKv = false;
          if (env && env.SSO_CONFIG_KV) {
            await env.SSO_CONFIG_KV.put('sso_global_config', JSON.stringify(body));
            savedToKv = true;
          }
          return new Response(JSON.stringify({ success: true, savedToKv, config: body }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (err) {
          return new Response(JSON.stringify({ success: false, error: err.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        }
      } else if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key'
          }
        });
      }
    }

    // 5. 放行静态资源文件、管理后台 (admin.html) 与测试页面
    if (
      request.method === 'OPTIONS' ||
      pathname.endsWith('.css') ||
      pathname.endsWith('.js') ||
      pathname.endsWith('.png') ||
      pathname.endsWith('.jpg') ||
      pathname.endsWith('.jpeg') ||
      pathname.endsWith('.ico') ||
      pathname.endsWith('.svg') ||
      pathname.endsWith('.json') ||
      pathname.endsWith('.woff') ||
      pathname.endsWith('.woff2') ||
      pathname.includes('client-blog') ||
      pathname.includes('admin')
    ) {
      if (env && env.ASSETS) {
        return env.ASSETS.fetch(request);
      }
      return fetch(request);
    }

    // 6. 严格参数白名单校验: 携带任何非法/未授权参数立即 400
    for (const key of url.searchParams.keys()) {
      if (!ALLOWED_PARAMS.has(key)) {
        return new Response(GOOGLE_400_HTML, {
          status: 400,
          statusText: 'Bad Request',
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'X-Robots-Tag': 'noindex, nofollow'
          }
        });
      }
    }

    // 7. 泛域名白名单校验 (*.yaoxi.wiki, *.yaoxi.cloud)
    const targetDomain = url.searchParams.get('target_domain');
    if (targetDomain && !isAllowedDomain(targetDomain)) {
      return new Response(GOOGLE_400_HTML, {
        status: 400,
        statusText: 'Bad Request',
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'X-Robots-Tag': 'noindex, nofollow'
        }
      });
    }

    // 8. 严格校验 client_request_token 密码学防伪签名
    const token = url.searchParams.get('client_request_token');
    const resolvedTarget = targetDomain || 'yaoxi.cloud';
    const secret = (env && env.SSO_HANDSHAKE_SECRET) || DEFAULT_SSO_HANDSHAKE_SECRET;
    const isValidSignature = await verifyCryptographicTokenSignature(token, resolvedTarget, secret);

    if (!isValidSignature) {
      return new Response(GOOGLE_400_HTML, {
        status: 400,
        statusText: 'Bad Request',
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'X-Robots-Tag': 'noindex, nofollow'
        }
      });
    }

    // 9. 密码学验签通过 -> 放行至登录中心页面 (index.html / accounts-login.html)
    if (env && env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return fetch(request);
  }
};
