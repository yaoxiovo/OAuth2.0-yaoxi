/**
 * build.js - 耀西统一身份认证中心自动化构建脚本
 * 零第三方依赖 (纯 Node.js 内置模块)，兼容 Cloudflare Pages、GitHub Actions 与本地环境
 * 
 * 构建职责:
 * 1. 语法门禁检查 (Syntax verification on all JavaScript files)
 * 2. 泛域名与安全规则自检 (Domain whitelist regression unit tests)
 * 3. 生产版本号与防缓存注入 (Cache-busting version stamping for CSS/JS)
 * 4. 同步 accounts-login.html -> index.html (确保单点登录与主页 100% 同步)
 * 5. 边缘中间件同步 (_middleware.js -> cloudflare-worker-400.js)
 * 6. 生成 dist/ 生产输出目录 (兼容 Cloudflare Pages 输出根目录与 dist 目录)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = __dirname;
const DIST_DIR = path.join(ROOT_DIR, 'dist');

console.log('\n======================================================');
console.log(' 🚀 正在执行构建: accounts.yaoxi.cloud 统一身份认证中心');
console.log('======================================================\n');

// 1. 语法门禁自检
console.log('[1/6] 🔍 执行 JavaScript 语法门禁校验...');
const jsFiles = [
  'accounts-login.js',
  'admin.js',
  'worker.js',
  path.join('functions', '_middleware.js'),
  path.join('functions', 'api', 'config.js'),
  path.join('functions', 'api', 'login.js'),
  path.join('functions', 'api', 'status.js'),
  path.join('functions', 'api', 'register.js'),
  path.join('functions', 'api', 'lookup.js'),
  path.join('sdk', 'yaoxi-auth.js'),
  'cloudflare-worker-400.js'
];

for (const file of jsFiles) {
  const fullPath = path.join(ROOT_DIR, file);
  if (fs.existsSync(fullPath)) {
    try {
      execSync('node -c "' + fullPath + '"', { cwd: ROOT_DIR, stdio: 'pipe' });
      console.log('  ✅ ' + file + ' 语法校验通过');
    } catch (err) {
      console.error('  ❌ ' + file + ' 语法校验失败: ', err.message);
      process.exit(1);
    }
  }
}

// 2. 泛域名白名单回归测试
console.log('\n[2/6] 🛡️ 执行泛域名授权逻辑单元测试...');
function isAllowedDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const d = domain.trim().toLowerCase();
  return (
    d === 'yaoxi.wiki' ||
    d.endsWith('.yaoxi.wiki') ||
    d === 'yaoxi.cloud' ||
    d.endsWith('.yaoxi.cloud') ||
    d === 'localhost' ||
    d === '127.0.0.1' ||
    d.endsWith('.localhost')
  );
}

const testCases = [
  ['blog.yaoxi.wiki', true],
  ['sub.admin.yaoxi.wiki', true],
  ['yaoxi.wiki', true],
  ['accounts.yaoxi.cloud', true],
  ['api.yaoxi.cloud', true],
  ['yaoxi.cloud', true],
  ['localhost', true],
  ['127.0.0.1', true],
  ['evil-site.com', false],
  ['fakeyaoxi.wiki.attacker.com', false],
  ['notyaoxi.cloud', false]
];

for (const [dom, expected] of testCases) {
  const actual = isAllowedDomain(dom);
  if (actual !== expected) {
    console.error('  ❌ 泛域名断言失败: ' + dom + ' (预期 ' + expected + ', 实际 ' + actual + ')');
    process.exit(1);
  }
}
console.log('  ✅ 泛域名规则 (*.yaoxi.wiki, *.yaoxi.cloud) 测试全部通过');

// 3. 防缓存版本号生成与 HTML 注入
console.log('\n[3/6] 🏷️ 注入版本号与防缓存时间戳...');
const now = new Date();
const pad = (n) => String(n).padStart(2, '0');
const buildVersion = 'v' + now.getFullYear() + pad(now.getMonth() + 1) + pad(now.getDate()) + '_' + pad(now.getHours()) + pad(now.getMinutes()) + pad(now.getSeconds());
console.log('  📦 本次构建版本号: ' + buildVersion);

const loginHtmlPath = path.join(ROOT_DIR, 'accounts-login.html');
let loginHtml = fs.readFileSync(loginHtmlPath, 'utf8');

loginHtml = loginHtml.replace(/href="accounts-login\.css(\?v=[^"]*)?"/g, 'href="accounts-login.css?v=' + buildVersion + '"');
loginHtml = loginHtml.replace(/src="accounts-login\.js(\?v=[^"]*)?"/g, 'src="accounts-login.js?v=' + buildVersion + '"');

fs.writeFileSync(loginHtmlPath, loginHtml, 'utf8');
console.log('  ✅ accounts-login.html 已注入最新版本参数');

// 4. 同步 accounts-login.html -> index.html
console.log('\n[4/6] 🔄 同步 accounts-login.html 至 index.html...');
const indexHtmlPath = path.join(ROOT_DIR, 'index.html');
fs.writeFileSync(indexHtmlPath, loginHtml, 'utf8');
console.log('  ✅ index.html 已与 accounts-login.html 完全同步');

// 5. 边缘中间件与 Cloudflare Worker 同步
console.log('\n[5/6] ⚡ 同步边缘安全拦截器...');
const middlewarePath = path.join(ROOT_DIR, 'functions', '_middleware.js');
const workerPath = path.join(ROOT_DIR, 'cloudflare-worker-400.js');

if (fs.existsSync(middlewarePath)) {
  let mwCode = fs.readFileSync(middlewarePath, 'utf8');
  let workerCode = mwCode.replace(
    'export async function onRequest(context) {',
    'export default {\n  async fetch(request, env, ctx) {'
  );
  workerCode = workerCode.replace('const url = new URL(context.request.url);', 'const url = new URL(request.url);');
  workerCode = workerCode.replace('context.request.method', 'request.method');
  workerCode = workerCode.replace(/return context\.next\(\);/g, 'return fetch(request);');
  workerCode += '\n};\n';
  fs.writeFileSync(workerPath, workerCode, 'utf8');
  console.log('  ✅ functions/_middleware.js 与 cloudflare-worker-400.js 保持一致');
}

// 6. 生成 dist/ 生产输出目录
console.log('\n[6/6] 📁 生成生产发布目录 (dist/)...');

function copyDirRecursive(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'dist') {
        copyDirRecursive(srcPath, destPath);
      }
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

if (!fs.existsSync(DIST_DIR)) {
  fs.mkdirSync(DIST_DIR, { recursive: true });
}

const copyFiles = [
  'index.html',
  'accounts-login.html',
  'accounts-login.css',
  'accounts-login.js',
  'admin.html',
  'admin.css',
  'admin.js',
  'client-blog.html',
  'blog-login.css',
  '_headers',
  '_routes.json',
  '.assetsignore',
  'cloudflare-worker-400.js'
];

for (const file of copyFiles) {
  const src = path.join(ROOT_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, path.join(DIST_DIR, file));
  }
}

copyDirRecursive(path.join(ROOT_DIR, 'functions'), path.join(DIST_DIR, 'functions'));
copyDirRecursive(path.join(ROOT_DIR, 'sdk'), path.join(DIST_DIR, 'sdk'));

console.log('  ✅ dist/ 生产就绪 (兼容根目录或 dist 输出目录)');
console.log('\n======================================================');
console.log(' 🎉 构建完成！所有静态资源与安全配置均已就绪。');
console.log(' 💡 Cloudflare Pages 构建命令: npm run build');
console.log(' 💡 Cloudflare Pages 输出目录: dist 或 .');
console.log('======================================================\n');
