/**
 * Cloudflare Pages Functions API: /api/status
 * 轻量级账号实时状态查询接口 (0-Delay Account Status & Revocation Checker)
 * 供各类客户端 SDK、单页系统进行超低开销的心跳检测与前置操作鉴权
 */

const DEFAULT_USERS = [
  {
    id: "usr_yaoxi",
    username: "yaoxi",
    displayName: "耀西 (Super Admin)",
    email: "yaoxiov0@gmail.com",
    roles: ["admin", "author", "super_user"],
    status: "active"
  }
];

function getCorsHeaders() {
  return {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
  };
}

async function resolveUserStatus(request, env) {
  let querySub = '';
  let queryEmail = '';
  let queryId = '';

  const url = new URL(request.url);
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
    }), {
      status: 400,
      headers: getCorsHeaders()
    });
  }

  // Load config from Cloudflare KV
  let config = null;
  if (env && env.SSO_CONFIG_KV) {
    try {
      const data = await env.SSO_CONFIG_KV.get('sso_global_config');
      if (data) config = JSON.parse(data);
    } catch (e) {}
  }

  const usersList = (config && Array.isArray(config.users)) ? config.users : DEFAULT_USERS;

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
    }), {
      status: 200,
      headers: getCorsHeaders()
    });
  }

  return new Response(JSON.stringify({
    success: true,
    found: false,
    active: false,
    revoked: true,
    error: 'User not found or revoked'
  }), {
    status: 200,
    headers: getCorsHeaders()
  });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders()
  });
}

export async function onRequestGet(context) {
  return resolveUserStatus(context.request, context.env);
}

export async function onRequestPost(context) {
  return resolveUserStatus(context.request, context.env);
}
