import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function sdkFixture(fetch) {
  const values = new Map();
  const context = {
    module: { exports: {} }, console, fetch,
    localStorage: { getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
    window: { location: { href: 'https://client.example/', hostname: 'client.example' }, addEventListener() {} },
  };
  vm.runInNewContext(readFileSync(new URL('../sdk/yaoxi-auth.js', import.meta.url), 'utf8'), context);
  const auth = new context.module.exports({ clientId: 'test-client', authUrl: 'https://accounts.yaoxi.cloud' });
  auth._saveAuthData('example-opaque-token', { sub: 'member', iss: 'https://untrusted.example' }, 3600);
  return auth;
}

test('SDK introspects actual bearer against configured issuer and clears revoked credentials', async () => {
  let calls = 0;
  const auth = sdkFixture(async (url, options) => {
    calls++;
    assert.equal(url, 'https://accounts.yaoxi.cloud/api/auth/introspect');
    assert.equal(options.headers.Authorization, 'Bearer example-opaque-token');
    return Response.json({ active: false });
  });
  assert.equal(await auth.validateStatus(), false);
  assert.equal(auth.getToken(), null);
  assert.equal(calls, 1);
});

test('SDK fails protected pre-action checks on unavailable introspection without declaring a freeze', async () => {
  const auth = sdkFixture(async () => { throw new Error('unavailable'); });
  assert.equal(await auth.validateStatus(), false);
  assert.equal(auth.getToken(), 'example-opaque-token');
  await assert.rejects(() => auth.assertActive());
});
