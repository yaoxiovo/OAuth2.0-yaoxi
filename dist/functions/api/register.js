/**
 * Cloudflare Pages Functions API: /api/register
 * 开放自助注册 (Open Self-Service Registration)
 * 安全特性：
 * 1. 注册总开关 (registration.enabled) 与审核模式 (registration.requireApproval) 由管理后台控制
 * 2. 用户名/邮箱/密码服务端严格校验 + 保留名保护 + 大小写不敏感查重
 * 3. Turnstile 人机校验服务端 siteverify (未配置 secretKey 时降级为软校验)
 * 4. KV 固定窗口 IP 限流，作为自动化批量注册的滥用硬上限
 * 5. 审核模式下账号以 pending 状态入库，需管理员在后台通过后方可登录
 */

const DEFAULT_ADMIN_PASSWORD_HASH = "9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001";
const SERVER_JWT_SECRET = "yaoxi_cloud_sso_internal_token_signing_secret_2026";

const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const EMAIL_PATTERN = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/i;
const RESERVED_USERNAMES = new Set([
  'yaoxi', 'admin', 'administrator', 'root', 'system', 'support',
  'help', 'security', 'accounts', 'official', 'service', 'api'
]);

const DEFAULT_CONFIG = {
  security: {
    ssoIssuer: "https://accounts.yaoxi.cloud",
    tokenTtl: 7200
  },
  turnstile: { enabled: true },
  registration: {
    enabled: true,
    requireApproval: true,
    defaultRoles: ["member"],
    rateLimit: { perIpHour: 5, perIpDay: 20 }
  },
  users: [{
    id: "usr_yaoxi",
    username: "yaoxi",
    displayName: "耀西 (Super Admin)",
    email: "yaoxiov0@gmail.com",
    passwordHash: DEFAULT_ADMIN_PASSWORD_HASH,
    roles: ["admin", "author", "super_user"],
    status: "active",
    passkeyBound: true
  }]
};

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

function randomHex(byteLength = 6) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
    return { ok: true, degraded: true };
  }
}

export async function onRequestPost(context) {
  const jsonHeaders = { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' };
  try {
    const body = await context.request.json().catch(() => null);
    const { username, email, displayName, password, cf_turnstile_token, client_id, target_domain, client_request_token } = body || {};

    const config = await loadStoredConfig(context.env);
    const registration = (config && config.registration) || {};
    if (registration.enabled === false) {
      return new Response(JSON.stringify({ success: false, error: '当前未开放自助注册，请联系管理员开通账号' }), {
        status: 403, headers: jsonHeaders
      });
    }

    const limits = registration.rateLimit || {};
    const rate = await checkRateLimit(context.request, context.env, 'reg', limits.perIpHour || 5);
    if (!rate.allowed) {
      return new Response(JSON.stringify({ success: false, error: '注册请求过于频繁，请稍后再试' }), {
        status: 429, headers: jsonHeaders
      });
    }

    const usernameClean = typeof username === 'string' ? username.trim().toLowerCase() : '';
    const emailClean = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const displayClean = typeof displayName === 'string' ? displayName.trim().replace(/[<>]/g, '').slice(0, 64) : '';

    if (!USERNAME_PATTERN.test(usernameClean)) {
      return new Response(JSON.stringify({ success: false, error: '用户名需为 3-32 位小写字母、数字或 . _ -，且以字母或数字开头' }), {
        status: 400, headers: jsonHeaders
      });
    }
    if (RESERVED_USERNAMES.has(usernameClean)) {
      return new Response(JSON.stringify({ success: false, error: '该用户名为系统保留名称，请更换一个' }), {
        status: 400, headers: jsonHeaders
      });
    }
    if (!EMAIL_PATTERN.test(emailClean) || emailClean.length > 254) {
      return new Response(JSON.stringify({ success: false, error: '请输入有效的电子邮件地址' }), {
        status: 400, headers: jsonHeaders
      });
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      return new Response(JSON.stringify({ success: false, error: '密码需为 8-128 位字符' }), {
        status: 400, headers: jsonHeaders
      });
    }

    const turnstileCfg = (config && config.turnstile) || {};
    if (turnstileCfg.enabled !== false) {
      const secretKey = turnstileCfg.secretKey || (context.env && context.env.TURNSTILE_SECRET_KEY) || '';
      const tsCheck = await verifyTurnstileToken(cf_turnstile_token, rate.ip, secretKey);
      if (!tsCheck.ok) {
        return new Response(JSON.stringify({ success: false, error: tsCheck.error }), {
          status: 403, headers: jsonHeaders
        });
      }
    }

    const users = Array.isArray(config.users) ? config.users : [];
    if (users.some(u => (u.username || '').toLowerCase() === usernameClean)) {
      return new Response(JSON.stringify({ success: false, error: '该用户名已被占用，请更换一个' }), {
        status: 409, headers: jsonHeaders
      });
    }
    if (users.some(u => (u.email || '').toLowerCase() === emailClean)) {
      return new Response(JSON.stringify({ success: false, error: '该邮箱已被注册，请直接登录或更换邮箱' }), {
        status: 409, headers: jsonHeaders
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

    if (context.env && context.env.SSO_CONFIG_KV) {
      await context.env.SSO_CONFIG_KV.put('sso_global_config', JSON.stringify(nextConfig));
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
        status: 200, headers: jsonHeaders
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const ttl = (config.security && config.security.tokenTtl) || 7200;
    const issuer = (config.security && config.security.ssoIssuer) || 'https://accounts.yaoxi.cloud';
    const secret = (context.env && context.env.JWT_SECRET) || SERVER_JWT_SECRET;

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
      status: 200, headers: jsonHeaders
    });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}
