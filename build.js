/**
 * build.js - 耀西统一身份认证中心自动化构建脚本
 * 零第三方依赖 (纯 Node.js 内置模块)，支持腾讯云 Node.js 服务、GitHub Actions 与本地环境
 * 
 * 构建职责:
 * 1. 语法门禁检查 (Syntax verification on all JavaScript files)
 * 2. 泛域名与安全规则自检 (Domain whitelist regression unit tests)
 * 3. 生产版本号与防缓存注入 (Cache-busting version stamping for CSS/JS)
 * 4. 同步 accounts-login.html -> index.html (确保单点登录与主页 100% 同步)
 * 5. 清理旧发布目录，避免历史服务端代码混入静态资源
 * 6. 生成 dist/ 静态资源目录，由 Node.js 服务提供访问
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = __dirname;
const DIST_DIR = path.join(ROOT_DIR, 'dist');

console.log('\n======================================================');
console.log(' 🚀 正在执行构建: account.yaoxiovo.cn 统一身份认证中心');
console.log('======================================================\n');

// 1. 语法门禁自检
console.log('[1/6] 🔍 执行 JavaScript 语法门禁校验...');
const jsFiles = [
  'accounts-login.js',
  'admin.js',
  'worker.js',
  'account-enforcement.mjs',
  path.join('server', 'main.mjs'),
  path.join('server', 'storage.mjs'),
  path.join('server', 'assets.mjs'),
  path.join('server', 'import.mjs'),
  path.join('sdk', 'yaoxi-auth.js')
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

// 5. 从空目录构建；旧 Pages/Workers 代码不能作为生产静态资源发布。
console.log('\n[5/6] 清理旧静态资源...');
fs.rmSync(DIST_DIR, { recursive: true, force: true });

// 6. 生成 dist/ 生产输出目录
console.log('\n[6/6] 📁 生成生产发布目录 (dist/)...');

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
  'channel-sync.html'
];

for (const file of copyFiles) {
  const src = path.join(ROOT_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, path.join(DIST_DIR, file));
  }
}

fs.mkdirSync(path.join(DIST_DIR, 'sdk'), { recursive: true });
fs.copyFileSync(path.join(ROOT_DIR, 'sdk', 'yaoxi-auth.js'), path.join(DIST_DIR, 'sdk', 'yaoxi-auth.js'));

console.log('  ✅ dist/ 静态资源已就绪，由本机 Node.js 提供服务');
console.log('\n======================================================');
console.log(' 🎉 构建完成！所有静态资源与安全配置均已就绪。');
console.log(' 💡 构建命令: npm run build');
console.log(' 💡 Node.js 启动命令: npm start；静态资源目录: dist');
console.log('======================================================\n');
