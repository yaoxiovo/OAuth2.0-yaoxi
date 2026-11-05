import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PersistentStore } from '../server/storage.mjs';
import { createApp } from '../server/main.mjs';
import { staticAssets } from '../server/assets.mjs';

test('concurrent enforcement transactions, receipts and revocations survive restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'accounts-test-'));
  let db = new PersistentStore(join(dir, 'accounts.sqlite'));
  try {
    const event = { action: 'violation', eventId: 'e1', actor: 'test', reason: 'porn', evidence: { requestId: 'proof' } };
    const call = body => db.enforcement.get('member').fetch(new Request('https://internal/', { method: 'POST', body: JSON.stringify(body) })).then(r => r.json());
    const results = await Promise.all(Array.from({ length: 20 }, () => call(event)));
    assert.equal(results.filter(r => !r.duplicate).length, 1);
    assert.equal((await call({ action: 'status' })).data.tokenVersion, 1);
    await db.kv.put('sso_global_config', '{"users":[]}');
    await db.kv.put('expired', 'x', { expiration: 1 });
    db.close(); db = new PersistentStore(join(dir, 'accounts.sqlite'));
    assert.equal(await db.kv.get('sso_global_config'), '{"users":[]}');
    assert.equal(await db.kv.get('expired'), null);
    assert.equal((await call(event)).duplicate, true);
    const state = (await call({ action: 'status' })).data;
    assert.equal(state.violationCount, 1); assert.equal(state.frozen, true);
    const storage = db.storage('rollback');
    await assert.rejects(storage.transaction(async tx => { await tx.put('x', 1); throw new Error('rollback'); }));
    assert.equal(await storage.get('x'), undefined);
  } finally { db.close(); rmSync(dir, { recursive: true }); }
});

test('HTTP runtime preserves canonical issuer routes and gates private assets', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'accounts-http-'));
  const db = new PersistentStore(':memory:');
  writeFileSync(join(dir, 'admin.html'), '<h1>admin</h1>');
  writeFileSync(join(dir, 'index.html'), '<h1>login</h1>');
  writeFileSync(join(dir, 'channel-sync.html'), '<html>relay</html>');
  const config = { security: { ssoIssuer: 'https://accounts.yaoxi.cloud' }, users: [] };
  await db.kv.put('sso_global_config', JSON.stringify(config));
  const secrets = { JWT_SECRET: 'test-key-'.repeat(8), LUMITAPE_ENFORCEMENT_SECRET: 'service-key-'.repeat(8) };
  const app = createApp({ database: db, assets: dir, secrets });
  app.listen(0, '127.0.0.1'); await new Promise(r => app.once('listening', r));
  const base = 'http://127.0.0.1:' + app.address().port;
  try {
    assert.equal((await fetch(base + '/admin.html')).status, 200);
    assert.equal((await fetch(base + '/channel-sync.html')).status, 200);
    assert.equal((await fetch(base + '/accounts-login.html')).status, 400);
    assert.equal((await fetch(base + '/?unknown=bad')).status, 400);
    assert.equal((await fetch(base + '/api/config')).headers.get('X-Yaoxi-Origin'), 'tencent-seoul');
    const privateResponse = await fetch(base + '/functions/api/login.js');
    assert.equal(privateResponse.status, 404);
    const introspect = await fetch(base + '/api/auth/introspect', { method: 'POST', headers: { Authorization: 'Bearer garbage' } });
    assert.deepEqual(await introspect.json(), { active: false });
    const service = await fetch(base + '/api/internal/account-enforcement', { method: 'POST', body: '{}' });
    assert.equal(service.status, 401);
    assert.throws(() => createApp({ database: db, assets: dir, secrets: {} }), /JWT_SECRET_REQUIRED/);
    const assets = staticAssets(dir);
    for (const path of ['/functions/api/login.js', '/server/main.mjs', '/.env', '/%2e%2e%2fsecret.js', '/_headers']) {
      assert.equal((await assets.fetch(new Request('https://accounts.yaoxi.cloud' + path))).status, 404, path);
    }
  } finally { await new Promise(r => app.close(r)); db.close(); rmSync(dir, { recursive: true }); }
});

test('local HTTP password login, signed revocation and release survive process storage restart without external requests', async () => {
  const { createHash, createHmac, randomBytes } = await import('node:crypto');
  const dir = mkdtempSync(join(tmpdir(), 'accounts-local-'));
  const filename = join(dir, 'accounts.sqlite');
  const secrets = { JWT_SECRET: 'identity-test-key-'.repeat(4), LUMITAPE_ENFORCEMENT_SECRET: 'service-test-key-'.repeat(4) };
  let db, app, base;
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = (url, options) => {
    assert.equal(new URL(typeof url === 'string' ? url : url.url).hostname, '127.0.0.1', 'local authentication must not call external compute/storage');
    return nativeFetch(url, options);
  };
  const start = async () => {
    db = new PersistentStore(filename);
    app = createApp({ database: db, assets: dir, secrets });
    app.listen(0, '127.0.0.1');
    await new Promise(r => app.once('listening', r));
    base = 'http://127.0.0.1:' + app.address().port;
  };
  const stop = async () => { await new Promise(r => app.close(r)); db.close(); };
  const login = password => fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'member', password, client_id: 'local-test' }) });
  const inspect = async token => (await fetch(base + '/api/auth/introspect', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })).json();
  const mutate = async body => {
    const path = '/api/internal/account-enforcement';
    const raw = JSON.stringify({ subject: 'member', actor: 'test', reason: 'porn', ...body });
    const time = String(Date.now()), nonce = randomBytes(16).toString('hex');
    const content = ['v1', 'lumitape', 'POST', path, time, nonce, createHash('sha256').update(raw).digest('hex')].join('\n');
    return fetch(base + path, { method: 'POST', headers: { 'X-Enforcement-Time': time, 'X-Enforcement-Nonce': nonce, 'X-Enforcement-Signature': createHmac('sha256', secrets.LUMITAPE_ENFORCEMENT_SECRET).update(content).digest('hex') }, body: raw });
  };
  try {
    await start();
    await db.kv.put('sso_global_config', JSON.stringify({ security: { ssoIssuer: 'https://accounts.yaoxi.cloud' }, turnstile: { enabled: false }, users: [{ id: 'local-member', username: 'member', status: 'active', roles: ['member'], passwordHash: createHash('sha256').update('local-password').digest('hex') }] }));
    assert.equal((await login('wrong-password')).status, 401);
    const response = await login('local-password');
    assert.equal(response.status, 200);
    const { token } = await response.json();
    assert.equal((await inspect(token)).active, true);
    assert.equal(JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).iss, 'https://accounts.yaoxi.cloud');
    await stop(); await start();
    assert.equal((await inspect(token)).active, true);
    const event = { action: 'violation', eventId: 'local-violation', evidence: { requestId: 'isolated-test' } };
    assert.equal((await mutate(event)).status, 200);
    assert.equal((await inspect(token)).active, false);
    assert.equal((await login('local-password')).status, 403);
    await stop(); await start();
    assert.equal((await inspect(token)).active, false);
    assert.equal((await (await mutate(event)).json()).duplicate, true);
    assert.equal((await mutate({ action: 'unfreeze', eventId: 'local-release', reason: 'test release' })).status, 200);
    assert.equal((await inspect(token)).active, false);
    const fresh = await login('local-password');
    assert.equal(fresh.status, 200);
    assert.equal((await inspect((await fresh.json()).token)).active, true);
  } finally {
    globalThis.fetch = nativeFetch;
    if (app?.listening) await stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
