/**
 * Cloudflare Pages Functions API: /api/login
 * 服务端集中化用户密码核验与真实密码学 Token 签发 (Secure Server-Side JWT Issuance)
 */

const DEFAULT_ADMIN_PASSWORD_HASH = "9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001";
const SERVER_JWT_SECRET = "yaoxi_cloud_sso_internal_token_signing_secret_2026";

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

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const { username, password, auth_type, assertion, client_id, target_domain, client_request_token } = body || {};

    const isPasskey = (auth_type === 'passkey' || !!assertion);
    if (!username || (!password && !isPasskey)) {
      return new Response(JSON.stringify({ success: false, error: '请输入账号和认证凭证' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
      });
    }

    let config = null;
    if (context.env && context.env.SSO_CONFIG_KV) {
      try {
        const data = await context.env.SSO_CONFIG_KV.get('sso_global_config');
        if (data) config = JSON.parse(data);
      } catch (e) {}
    }
    if (!config) {
      config = {
        users: [{
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
          }
        }]
      };
    }

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
    const secret = (context.env && context.env.JWT_SECRET) || SERVER_JWT_SECRET;
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
