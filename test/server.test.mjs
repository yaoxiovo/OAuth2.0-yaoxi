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
  const config = { security: { ssoIssuer: 'https://accounts.yaoxi.cloud' }, users: [] };
  await db.kv.put('sso_global_config', JSON.stringify(config));
  const secrets = { JWT_SECRET: 'test-key-'.repeat(8), LUMITAPE_ENFORCEMENT_SECRET: 'service-key-'.repeat(8) };
  const app = createApp({ database: db, assets: dir, secrets });
  app.listen(0, '127.0.0.1'); await new Promise(r => app.once('listening', r));
  const base = 'http://127.0.0.1:' + app.address().port;
  try {
    assert.equal((await fetch(base + '/admin.html')).status, 200);
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
