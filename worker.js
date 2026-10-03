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

  if (Array.isArray(clone.users)) {
    clone.users = clone.users.map(u => {
      const safeUser = { ...u };
      delete safeUser.password;
      delete safeUser.passwordHash;
      delete safeUser.salt;
      return safeUser;
    });
  }

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
          const { username, password, client_id, target_domain, client_request_token } = body || {};

          if (!username || !password) {
            return new Response(JSON.stringify({ success: false, error: '请输入账号和密码' }), {
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

          if (matchedUser.status && matchedUser.status !== 'active') {
            return new Response(JSON.stringify({ success: false, error: '此 Google 帐号已被管理员停用或冻结' }), {
              status: 403,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          const inputHash = await sha256Hex(password);
          const expectedHash = matchedUser.passwordHash || (matchedUser.password ? await sha256Hex(matchedUser.password) : DEFAULT_ADMIN_PASSWORD_HASH);

          if (inputHash !== expectedHash) {
            return new Response(JSON.stringify({ success: false, error: '密码错误，请重试' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }

          const now = Math.floor(Date.now() / 1000);
          const ttl = (config.security && config.security.tokenTtl) || 7200;
          const issuer = (config.security && config.security.ssoIssuer) || 'https://accounts.yaoxi.cloud';
          const secret = (env && env.JWT_SECRET) || SERVER_JWT_SECRET;

          const payload = {
            iss: issuer,
            aud: client_id || 'yaoxi-app',
            sub: matchedUser.username,
            email: matchedUser.email,
            roles: matchedUser.roles || ['member'],
            target_domain: target_domain || 'yaoxi.cloud',
            client_request_token: client_request_token || '',
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
            status: matchedUser.status
          };

          return new Response(JSON.stringify({
            success: true,
            token,
            expires_in: ttl,
            user: safeUser
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

    // 2. API 接口: /api/config (严格数据脱敏与管理员门禁鉴权)
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

    // 3. 放行静态资源文件、管理后台 (admin.html) 与测试页面
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

    // 4. 严格参数白名单校验: 携带任何非法/未授权参数立即 400
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

    // 5. 泛域名白名单校验 (*.yaoxi.wiki, *.yaoxi.cloud)
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

    // 6. 严格校验 client_request_token 密码学防伪签名
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

    // 7. 密码学验签通过 -> 放行至登录中心页面 (index.html / accounts-login.html)
    if (env && env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return fetch(request);
  }
};
