import http from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import worker from '../worker.js';
import { PersistentStore } from './storage.mjs';
import { staticAssets } from './assets.mjs';

export function createApp({ database, assets, secrets, publicOrigin = 'https://account.yaoxiovo.cn' }) {
  for (const name of ['JWT_SECRET', 'LUMITAPE_ENFORCEMENT_SECRET']) {
    if (typeof secrets[name] !== 'string' || secrets[name].length < 32) throw new Error(name + '_REQUIRED');
  }
  const env = { ...secrets, SSO_CONFIG_KV: database.kv, ACCOUNT_ENFORCEMENT: database.enforcement, ASSETS: staticAssets(assets) };
  const canonical = new URL(publicOrigin);
  return http.createServer(async (incoming, outgoing) => {
    try {
      if (!incoming.url.startsWith('/') || incoming.url.startsWith('//')) { outgoing.writeHead(400); outgoing.end(); return; }
      const url = new URL(incoming.url, canonical);
      if (url.origin !== canonical.origin) { outgoing.writeHead(400); outgoing.end(); return; }
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value !== undefined && !['host', 'connection', 'transfer-encoding'].includes(name)) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
      }
      headers.set('Host', canonical.host);
      // Only the loopback Nginx proxy may supply the verified client address.
      headers.set('CF-Connecting-IP', incoming.headers['x-real-ip'] || incoming.socket.remoteAddress || 'unknown');
      const parts = []; let size = 0;
      for await (const part of incoming) {
        size += part.length;
        if (size > 1024 * 1024) { outgoing.writeHead(413); outgoing.end(); return; }
        parts.push(part);
      }
      const request = new Request(url, { method: incoming.method, headers, ...(['GET', 'HEAD'].includes(incoming.method) ? {} : { body: Buffer.concat(parts) }) });
      const response = await worker.fetch(request, env, { waitUntil: promise => promise.catch(() => console.error('Background task failed')) });
      outgoing.writeHead(response.status, { ...Object.fromEntries(response.headers), 'X-Yaoxi-Origin': 'tencent-seoul' });
      outgoing.end(incoming.method === 'HEAD' ? undefined : Buffer.from(await response.arrayBuffer()));
    } catch {
      console.error('Request failed');
      if (!outgoing.headersSent) outgoing.writeHead(500, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      outgoing.end('{"success":false,"code":"INTERNAL_ERROR"}');
    }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const database = new PersistentStore(process.env.SSO_DB_PATH || '/var/lib/yaoxi-accounts/accounts.sqlite');
  if (!await database.kv.get('sso_global_config')) throw new Error('IMPORTED_SSO_CONFIG_REQUIRED');
  const app = createApp({ database, assets: new URL('../dist/', import.meta.url).pathname, secrets: process.env, publicOrigin: process.env.PUBLIC_ORIGIN });
  const port = Number(process.env.PORT || 3010);
  app.listen(port, '127.0.0.1', () => console.log('Yaoxi accounts listening on 127.0.0.1:' + port));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => app.close(() => { database.close(); process.exit(0); }));
}
