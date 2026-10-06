/**
 * Cloudflare Pages Functions API: /api/lookup
 * 服务端账号解析 (Server-Side Account Lookup)
 * 隐私加固说明：
 * 1. 公开配置 /api/config 不再下发任何用户目录，登录第一步的“账号是否存在”判断改为服务端解析
 * 2. 仅返回最小必要信息：规范化用户名、显示名、通行密钥绑定状态、账号状态与掩码邮箱
 * 3. Turnstile 人机校验（配置 secretKey 时强制执行）+ KV IP 限流，防止批量枚举
 */

const DEFAULT_ADMIN_PASSWORD_HASH = "9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001";

const DEFAULT_CONFIG = {
  turnstile: { enabled: true },
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

async function verifyTurnstileToken(token, remoteIp, secretKey, expectedAction) {
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
    if (data && data.success) {
      if (expectedAction && data.action && data.action !== expectedAction) {
        return { ok: false, error: '人机验证凭证与当前操作不匹配，请刷新页面后重试' };
      }
      return { ok: true };
    }
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
  const jsonHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  };
  try {
    const body = await context.request.json().catch(() => null);
    const { identifier, cf_turnstile_token } = body || {};

    if (!identifier || typeof identifier !== 'string' || !identifier.trim()) {
      return new Response(JSON.stringify({ success: false, error: 'Missing identifier' }), {
        status: 400, headers: jsonHeaders
      });
    }

    const rate = await checkRateLimit(context.request, context.env, 'lookup', 60);
    if (!rate.allowed) {
      return new Response(JSON.stringify({ success: false, error: '请求过于频繁，请稍后再试' }), {
        status: 429, headers: jsonHeaders
      });
    }

    const config = await loadStoredConfig(context.env);
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

    const input = identifier.trim().toLowerCase();
    const users = Array.isArray(config.users) ? config.users : [];
    const matched = users.find(u =>
      (u.username && u.username.toLowerCase() === input) ||
      (u.email && u.email.toLowerCase() === input)
    );

    if (!matched) {
      return new Response(JSON.stringify({ success: true, found: false }), {
        status: 200, headers: jsonHeaders
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
      status: 200, headers: jsonHeaders
    });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      status: 500, headers: jsonHeaders
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
