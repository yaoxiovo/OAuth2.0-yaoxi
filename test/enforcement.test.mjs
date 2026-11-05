import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHmac, createHash } from 'node:crypto';
import { AccountEnforcement } from '../account-enforcement.mjs';
import worker from '../worker.js';
globalThis.crypto ||= webcrypto;

function objectFixture() {
  const values = new Map();
  let pending = Promise.resolve();
  const storage = {
    async get(key) { return structuredClone(values.get(key)); },
    async put(key, value) { values.set(key, structuredClone(value)); },
    transaction(fn) {
      const result = pending.then(() => fn(storage));
      pending = result.catch(() => {});
      return result;
    },
  };
  const instance = new AccountEnforcement({ storage });
  return async body => {
    const response = await instance.fetch(new Request('https://internal/', { method: 'POST', body: JSON.stringify(body) }));
    return { status: response.status, ...await response.json() };
  };
}

test('first confirmed violation freezes for seven days, duplicate events do not punish again', async () => {
  const call = objectFixture();
  const before = Date.now();
  const event = { action: 'violation', eventId: 'lumitape:upload-1', actor: 'lumitape', reason: 'porn', evidence: { requestId: 'tencent-1' } };
  const first = await call(event);
  assert.equal(first.status, 200);
  assert.equal(first.data.frozen, true);
  assert.equal(first.data.violationCount, 1);
  assert.equal(first.data.tokenVersion, 1);
  assert.ok(Date.parse(first.data.frozenUntil) >= before + 7 * 86400_000);
  const duplicate = await call(event);
  assert.equal(duplicate.data.violationCount, 1);
  assert.equal(duplicate.data.frozenUntil, first.data.frozenUntil);
});

test('second violation is thirty fixed days; third is permanent; release never revives old token versions', async () => {
  const call = objectFixture();
  const violation = n => call({ action: 'violation', eventId: 'upload-' + n, actor: 'lumitape', reason: 'porn', evidence: { requestId: 'request-' + n } });
  await violation(1);
  await call({ action: 'unfreeze', eventId: 'release-1', actor: 'admin', reason: 'early release' });
  const before = Date.now();
  const second = await violation(2);
  assert.equal(second.data.violationCount, 2);
  assert.ok(Date.parse(second.data.frozenUntil) >= before + 30 * 86400_000);
  const third = await violation(3);
  assert.equal(third.data.permanent, true);
  assert.equal(third.data.frozenUntil, null);
  const released = await call({ action: 'unfreeze', eventId: 'release-2', actor: 'admin', reason: 'early release' });
  assert.equal(released.data.frozen, false);
  assert.ok(released.data.tokenVersion > third.data.tokenVersion);
  const conflict = await call({ action: 'unfreeze', eventId: 'release-2', actor: 'other-admin', reason: 'different request' });
  assert.equal(conflict.status, 409);
});

function serviceFixture() {
  const objects = new Map();
  const config = { security: { ssoIssuer: 'https://accounts.yaoxi.cloud', tokenTtl: 3600 }, users: [{ id: 'account-1', username: 'member', status: 'active', roles: ['member'], passwordHash: createHash('sha256').update('password').digest('hex') }] };
  const env = {
    JWT_SECRET: 'test-only-identity-secret-at-least-32-characters',
    LUMITAPE_ENFORCEMENT_SECRET: 'test-only-service-secret-at-least-32-characters',
    SSO_CONFIG_KV: { get: async () => JSON.stringify(config) },
    ACCOUNT_ENFORCEMENT: {
      idFromName: id => id,
      get(id) {
        if (!objects.has(id)) {
          const call = objectFixture();
          objects.set(id, { fetch: async request => { const r = await call(await request.json()); const { status, ...body } = r; return Response.json(body, { status }); } });
        }
        return objects.get(id);
      },
    },
  };
  const fetch = request => worker.fetch(request, env, {});
  const login = () => fetch(new Request('https://accounts.yaoxi.cloud/api/login', { method: 'POST', body: JSON.stringify({ username: 'member', password: 'password', client_id: 'lumitape', target_domain: 'pic.yaoxiovo.cn' }) }));
  const mutate = async (body, secret = env.LUMITAPE_ENFORCEMENT_SECRET) => {
    const raw = JSON.stringify({ subject: 'member', ...body });
    const timestamp = String(Date.now()), nonce = '1'.repeat(32);
    const path = '/api/internal/account-enforcement';
    const content = ['v1', 'lumitape', 'POST', path, timestamp, nonce, createHash('sha256').update(raw).digest('hex')].join('\n');
    return fetch(new Request('https://accounts.yaoxi.cloud' + path, { method: 'POST', headers: { 'X-Enforcement-Time': timestamp, 'X-Enforcement-Nonce': nonce, 'X-Enforcement-Signature': createHmac('sha256', secret).update(content).digest('hex') }, body: raw }));
  };
  return { fetch, login, mutate };
}

test('signed service freeze rejects new authorizations and immediately invalidates previously issued JWTs, including after release', async () => {
  const { fetch, login, mutate } = serviceFixture();
  const loggedIn = await login();
  assert.equal(loggedIn.status, 200);
  const { token } = await loggedIn.json();
  const inspect = token => fetch(new Request('https://accounts.yaoxi.cloud/api/auth/introspect', { method: 'POST', headers: { Authorization: 'Bearer ' + token } }));
  assert.equal((await (await inspect(token)).json()).active, true);
  const event = { action: 'violation', eventId: 'one-upload', actor: 'lumitape', reason: 'porn', evidence: { requestId: 'ims-1' } };
  assert.equal((await mutate(event, 'wrong-secret')).status, 401);
  assert.equal((await mutate(event)).status, 200);
  assert.equal((await (await inspect(token)).json()).active, false);
  const denied = await login();
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).token, undefined);
  assert.equal((await mutate(event)).status, 200);
  await mutate({ action: 'unfreeze', eventId: 'release', actor: 'site-admin', reason: 'early release' });
  assert.equal((await (await inspect(token)).json()).active, false);
  const newToken = (await (await login()).json()).token;
  assert.equal((await (await inspect(newToken)).json()).active, true);
  assert.equal((await (await inspect(token.slice(0, -3) + 'abc')).json()).active, false);
});

test('expiry releases the account but never resets the credential version or strike count', async () => {
  const call = objectFixture();
  const realNow = Date.now;
  let time = realNow();
  Date.now = () => time;
  try {
    await call({ action: 'violation', eventId: 'expire-1', actor: 'lumitape', reason: 'porn', evidence: { requestId: 'ims-1' } });
    time += 7 * 86400_000;
    const expired = await call({ action: 'status' });
    assert.equal(expired.data.frozen, false);
    assert.equal(expired.data.tokenVersion, 1);
    assert.equal(expired.data.violationCount, 1);
  } finally { Date.now = realNow; }
});

test('parallel redeliveries count one violation; review and malformed events cannot freeze', async () => {
  const call = objectFixture();
  const event = { action: 'violation', eventId: 'same-upload', actor: 'lumitape', reason: 'porn', evidence: { requestId: 'ims-1' } };
  const results = await Promise.all(Array.from({ length: 10 }, () => call(event)));
  assert.ok(results.every(result => result.data.violationCount === 1));
  assert.equal((await call({ ...event, eventId: 'review', reason: 'review' })).status, 400);
  assert.equal((await call({ ...event, eventId: 'missing', evidence: {} })).status, 400);
  assert.equal((await call({ action: 'status' })).data.violationCount, 1);
});

test('a successful expiry adjustment remains idempotent when replayed after expiry; repeated release does not revoke new credentials', async () => {
  const call = objectFixture();
  const realNow = Date.now; let now = realNow(); Date.now = () => now;
  try {
    await call({ action: 'violation', eventId: 'one', actor: 'lumitape', reason: 'porn', evidence: { requestId: 'ims-one' } });
    const adjustment = { action: 'adjust', eventId: 'adjust', actor: 'admin', reason: 'release earlier', frozenUntil: new Date(now + 1000).toISOString() };
    assert.equal((await call(adjustment)).status, 200);
    now += 2000;
    const replay = await call(adjustment);
    assert.equal(replay.status, 200); assert.equal(replay.duplicate, true);
    const first = await call({ action: 'unfreeze', eventId: 'release-one', actor: 'admin', reason: 'release' });
    const repeat = await call({ action: 'unfreeze', eventId: 'release-two', actor: 'admin', reason: 'release' });
    assert.equal(first.data.tokenVersion, repeat.data.tokenVersion);
    assert.equal(repeat.data.frozen, false);
  } finally { Date.now = realNow; }
});

test('overturning a false positive releases its freeze, removes exactly one strike and never revives old tokens', async () => {
  const call = objectFixture();
  const violation = id => call({ action: 'violation', eventId: id, actor: 'lumitape', reason: 'porn', evidence: { requestId: 'ims-' + id } });
  await violation('wrong-1');
  const correction = { action: 'overturn', eventId: 'correction-1', actor: 'admin', reason: 'false positive', violationEventId: 'wrong-1' };
  const released = await call(correction);
  assert.equal(released.status, 200); assert.equal(released.data.violationCount, 0);
  assert.equal(released.data.frozen, false); assert.ok(released.data.tokenVersion >= 1);
  assert.equal((await call(correction)).data.violationCount, 0);
  assert.equal((await call({ ...correction, eventId: 'correction-2' })).data.violationCount, 0);
  const next = await violation('valid-1');
  assert.equal(next.data.violationCount, 1);
  assert.equal((await call({ ...correction, eventId: 'correction-2', violationEventId: 'valid-1' })).status, 409);
  assert.equal(Date.parse(next.data.frozenUntil) - Date.parse(next.data.frozenAt), 7 * 86400_000);
  assert.equal((await call({ ...correction, eventId: 'missing', violationEventId: 'not-a-violation' })).status, 404);
});

test('correcting an older false positive does not clear a different current freeze', async () => {
  const call = objectFixture();
  for (const id of ['older', 'current']) await call({ action: 'violation', eventId: id, actor: 'lumitape', reason: 'porn', evidence: { requestId: 'ims-' + id } });
  const result = await call({ action: 'overturn', eventId: 'correct-older', actor: 'admin', reason: 'false positive', violationEventId: 'older' });
  assert.equal(result.data.violationCount, 1); assert.equal(result.data.frozen, true);
  assert.equal(result.data.freezeEventId, 'current');
});
