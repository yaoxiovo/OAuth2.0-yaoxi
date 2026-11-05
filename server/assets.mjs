import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, sep, extname } from 'node:path';

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2' };
export function staticAssets(root) {
  root = resolve(root);
  return { async fetch(request) {
    if (!['GET', 'HEAD'].includes(request.method)) return new Response(null, { status: 405 });
    let pathname;
    try { pathname = decodeURIComponent(new URL(request.url).pathname); }
    catch { return new Response(null, { status: 400 }); }
    // dist includes legacy Pages code. It is never a public asset.
    if (pathname.includes('\\') || pathname.includes('\0') || pathname.split('/').some(p => p.startsWith('.') || ['functions', 'server', 'node_modules', 'test'].includes(p)) || /(?:\.md|^\/_)/i.test(pathname)) return new Response(null, { status: 404 });
    let file = resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (!file.startsWith(root + sep)) return new Response(null, { status: 404 });
    try {
      if (!(await stat(file)).isFile()) return new Response(null, { status: 404 });
      file = await realpath(file);
      if (!file.startsWith(root + sep)) return new Response(null, { status: 404 });
      return new Response(request.method === 'HEAD' ? null : await readFile(file), { headers: {
        'Content-Type': mime[extname(file)] || 'application/octet-stream',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        'X-Robots-Tag': 'noindex, nofollow',
      } });
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    return new Response(null, { status: 404 });
  } };
}
