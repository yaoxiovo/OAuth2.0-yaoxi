// One strongly consistent Durable Object per identity. Never use the global
// configuration KV as a revocation ledger: its cached reads can be stale.
const DAY = 86_400_000;
const initialState = () => ({ violationCount: 0, tokenVersion: 0, frozenAt: null, frozenUntil: null, permanent: false });
const validText = value => typeof value === 'string' && value.length > 0 && value.length <= 300 && !/[\u0000-\u001f]/.test(value);
const json = (body, status = 200) => Response.json(body, { status, headers: { 'Cache-Control': 'no-store' } });

export function enforcementView(state, now = Date.now()) {
  return { ...state, frozen: state.permanent || (state.frozenUntil !== null && Date.parse(state.frozenUntil) > now) };
}

export class AccountEnforcement {
  constructor(ctx) { this.storage = ctx.storage; }

  async fetch(request) {
    const body = await request.json();
    if (body.action === 'status') {
      return json({ success: true, data: enforcementView(await this.storage.get('state') || initialState()) });
    }
    if (!['violation', 'unfreeze', 'adjust'].includes(body.action) || !validText(body.eventId) || !validText(body.actor) || !validText(body.reason)) {
      return json({ success: false, code: 'INVALID_ENFORCEMENT_EVENT' }, 400);
    }
    if (body.action === 'violation' && (body.reason !== 'porn' || !validText(body.evidence?.requestId))) {
      return json({ success: false, code: 'CONFIRMED_PORN_EVIDENCE_REQUIRED' }, 400);
    }
    // Manual adjustment supports finite, future instants only. The allowed range
    // and manual permanent freezes remain product questions, so aren't invented.
    if (body.action === 'adjust' && (typeof body.frozenUntil !== 'string' || !Number.isFinite(Date.parse(body.frozenUntil)))) {
      return json({ success: false, code: 'INVALID_EXPIRY' }, 400);
    }
    return this.storage.transaction(async tx => {
      const key = 'event:' + body.eventId;
      const fingerprint = JSON.stringify([body.action, body.actor, body.reason, body.evidence || null, body.frozenUntil || null]);
      const previous = await tx.get(key);
      if (previous) {
        if (previous.fingerprint !== fingerprint) return json({ success: false, code: 'EVENT_CONFLICT' }, 409);
        // Return current truth, not a stale snapshot that could resurrect a freeze.
        return json({ success: true, duplicate: true, data: enforcementView(await tx.get('state') || initialState()) });
      }
      const state = await tx.get('state') || initialState();
      const now = Date.now();
      if (body.action === 'adjust' && Date.parse(body.frozenUntil) <= now) return json({ success: false, code: 'FUTURE_EXPIRY_REQUIRED' }, 400);
      const changesState = body.action !== 'unfreeze' || enforcementView(state, now).frozen;
      if (body.action === 'violation') {
        state.violationCount++;
        state.frozenAt = new Date(now).toISOString();
        state.permanent = state.violationCount >= 3;
        state.frozenUntil = state.permanent ? null : new Date(now + (state.violationCount === 1 ? 7 : 30) * DAY).toISOString();
      } else if (body.action === 'unfreeze') {
        state.frozenUntil = null;
        state.permanent = false;
      } else {
        if (!enforcementView(state, now).frozen) return json({ success: false, code: 'ACCOUNT_NOT_FROZEN' }, 409);
        state.frozenUntil = new Date(body.frozenUntil).toISOString();
        state.permanent = false;
      }
      // Never reset this on expiry or manual release. Old credentials stay dead.
      if (changesState) state.tokenVersion++;
      await tx.put('state', state);
      await tx.put(key, { fingerprint, time: new Date(now).toISOString(), tokenVersion: state.tokenVersion });
      return json({ success: true, data: enforcementView(state, now) });
    });
  }
}

export async function accountEnforcement(env, user, event = { action: 'status' }) {
  if (!env.ACCOUNT_ENFORCEMENT) throw new Error('ACCOUNT_ENFORCEMENT_NOT_CONFIGURED');
  // JWT subject is the existing identity contract; a config ID may be rewritten.
  const identity = user.username.toLowerCase();
  const object = env.ACCOUNT_ENFORCEMENT.get(env.ACCOUNT_ENFORCEMENT.idFromName(identity));
  const response = await object.fetch(new Request('https://account-enforcement/', { method: 'POST', body: JSON.stringify(event) }));
  return { response, result: await response.json() };
}

export async function readEnforcement(env, user) {
  const { response, result } = await accountEnforcement(env, user);
  if (!response.ok || !result.success) throw new Error('ACCOUNT_ENFORCEMENT_UNAVAILABLE');
  return result.data;
}

export async function verifyIdentityJwt(token, env, issuer) {
  try {
    if (typeof token !== 'string' || token.length > 65536 || typeof env.JWT_SECRET !== 'string' || env.JWT_SECRET.length < 32) return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(part => !/^[\w-]+$/.test(part))) return null;
    const decode = part => Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
    const header = JSON.parse(new TextDecoder().decode(decode(parts[0])));
    if (header.alg !== 'HS256') return null;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', encoder.encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    if (!await crypto.subtle.verify('HMAC', key, decode(parts[2]), encoder.encode(parts[0] + '.' + parts[1]))) return null;
    const claims = JSON.parse(new TextDecoder().decode(decode(parts[1])));
    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== issuer || typeof claims.sub !== 'string' || !claims.sub || !Number.isSafeInteger(claims.exp) || claims.exp <= now || !Number.isSafeInteger(claims.iat) || claims.iat > now + 30 || claims.exp <= claims.iat) return null;
    if (claims.token_version !== undefined && (!Number.isSafeInteger(claims.token_version) || claims.token_version < 0)) return null;
    return claims;
  } catch { return null; }
}

export async function verifyServiceRequest(request, env, raw) {
  const secret = env.LUMITAPE_ENFORCEMENT_SECRET;
  if (typeof secret !== 'string' || secret.length < 32) return false;
  const timestamp = request.headers.get('X-Enforcement-Time') || '';
  const nonce = request.headers.get('X-Enforcement-Nonce') || '';
  const signature = request.headers.get('X-Enforcement-Signature') || '';
  if (!/^\d{13}$/.test(timestamp) || Math.abs(Date.now() - Number(timestamp)) > 300_000 || !/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature)) return false;
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(raw));
  const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  const content = ['v1', 'lumitape', request.method, new URL(request.url).pathname, timestamp, nonce, hex(digest)].join('\n');
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const bytes = Uint8Array.from(signature.match(/../g), pair => parseInt(pair, 16));
  return crypto.subtle.verify('HMAC', key, bytes, encoder.encode(content));
}
