# 腾讯云首尔部署

主入口：`https://account.yaoxiovo.cn`。旧域名 `https://accounts.yaoxi.cloud` 回源同一服务，用于兼容现有客户端。域名可以保留 Cloudflare DNS/CDN，认证服务和权威数据均在腾讯云，不经过 Workers。

现有账号配置中的 issuer `https://accounts.yaoxi.cloud` 保持不变。这是现有 JWT 验证契约，与网站入口域名不同。迁移不轮换签名密钥、不使现有会话失效。新 SDK 默认打开新入口；配置旧 authUrl 的客户端仍可继续使用。Turnstile 允许两个入口域名。

## 运行位置

- 主机：`txcloud` / `43.128.137.8`，Node.js 22。
- 源码：`/www/wwwroot/account.yaoxiovo.cn`。
- 服务：`yaoxi-accounts.service`，独立用户 `yaoxi-accounts`。
- 本机监听：`127.0.0.1:3010`；Nginx 提供 HTTPS。
- 环境文件：`/etc/yaoxi-accounts/runtime.env`，仅 root 可读。
- 数据库：`/var/lib/yaoxi-accounts/accounts.sqlite`；包含账号配置、限流计数、处罚状态和幂等事件。事务在单个进程内串行执行，SQLite 使用 WAL 和 FULL 同步。不要在同一数据库上启动多个 Node 实例。
- Nginx：`/www/server/panel/vhost/nginx/account.yaoxiovo.cn.conf`，公共配置 `/etc/yaoxi-accounts/nginx-app.conf`。
- 日志：`journalctl -u yaoxi-accounts`；Nginx 日志在 `/www/wwwlogs/accounts.yaoxi.cloud*.log`。

HTTP 适配层复用 `worker.js` 和 `account-enforcement.mjs` 中的认证及冻结规则。生产没有 Cloudflare KV 或 Durable Objects 绑定。旧 Pages functions 仅作历史兼容源码，不参与构建或部署，不得单独作为生产签发服务。`build.py` 与 `npm run build` 使用同一构建流程。每次构建清理旧 dist，仅复制前端资源，包含跨域退出中继 channel-sync.html。

## 验证与更新

在 Node.js 22 上执行：

```sh
npm run test:enforcement
npm run test:server
npm run build
```

更新前备份当前源码和数据库。将已验证源码部署到上述目录，构建后执行 `systemctl restart yaoxi-accounts`。环境文件、数据库、证书均在源码目录外，不要覆盖。确认 `systemctl is-active yaoxi-accounts`、3010 端口和日志正常，然后验证 HTTPS API。

新服务必须已经导入真实账号配置，且 JWT 和服务 HMAC 密钥均已设置；缺少任一项会拒绝启动。禁止使用默认空配置作为生产初始化。

授权登录链接依然需要有效 `client_request_token`。裸访登录页的 400 是现有握手规则；后台入口为 `/admin.html`。

## 备份和证书

`yaoxi-accounts-backup.timer` 每日执行 SQLite 在线备份，写入 `/var/backups/yaoxi-accounts`，保留最近 14 份并检查完整性。可手动执行 `systemctl start yaoxi-accounts-backup.service`。

证书由 `/opt/yaoxi-acme/acme.sh` 使用 DNS 验证签发，证书在 `/etc/yaoxi-accounts/tls`。每日续期由 `yaoxi-accounts-cert-renew.timer` 调度；签发成功后执行 `nginx -t && systemctl reload nginx`。ACME 的 DNS 凭据仅保存在服务器 root 可读目录，不进入源码和文档。

## 回滚

单纯回滚代码时保留当前 SQLite 数据库，恢复上一版源码，重新构建并重启服务。只有明确需要恢复历史数据时，才停服务并从备份恢复数据库；历史备份会丢失其后产生的账号和吊销记录，不能盲目恢复。

旧 Worker 源码、部署 ID 和迁移快照保存在服务器 `/root/yaoxi-accounts-migration`，只用于离线恢复。首尔开始接收新写入后，不得直接切回旧 KV/DO 快照，否则会丢失新账号和吊销状态。

实现所用接口参考：[Node.js 22 SQLite](https://nodejs.org/download/release/latest-jod/docs/api/sqlite.html)、[ACME 证书安装与续期](https://github.com/acmesh-official/acme.sh)。

## 迁移验收范围

账号配置、密码核验、JWT 签发/验签、处罚/吊销与幂等事件均由本机 Node.js 和 SQLite 完成，不依赖 Workers、KV 或 Durable Objects。`SSO_CONFIG_KV` 和 `ACCOUNT_ENFORCEMENT` 是历史适配器名称，实际分别连接 `PersistentStore.kv` 与 `PersistentStore.enforcement`。

`npm test` 包含隔离 SQLite 的 HTTP 登录、错误密码、数据库重开、服务签名处罚、重复事件、解冻及旧凭据持续吊销测试；该测试禁止访问非回环 HTTP 地址，不读取生产账号或写入生产数据库。生产真实用户浏览器登录仍需用户验收。

Nginx 的 `cloudflare-realip.conf` 模板随源码保留，安装至 `/etc/yaoxi-accounts/`。只信任列明的代理网段传入的客户 IP；应用只监听 `127.0.0.1:3010`。证书和私有环境仍放在源码目录之外。

保留的外部能力为 Cloudflare DNS/CDN、Turnstile，以及 ACME DNS 验证。它们不承担账号存储或身份签发。此迁移不表示完全离线运行。旧 Worker 已删除；遗留 Workers Builds 关联因现有凭据无 CI 查询权限而尚未核验，详见服务器迁移交接记录。不要重新启用 Wrangler 部署。
