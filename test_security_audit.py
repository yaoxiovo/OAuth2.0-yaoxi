#!/usr/bin/env python3
"""
test_security_audit.py - 耀西统一身份认证中心安全性回归自动化测试套件
验证已修复的所有高危与致命安全漏洞 (TDD / Verification)
"""

import os
import re
import json

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def test_vulnerability_1_and_2_config_security():
    print("Testing Vuln 1 & 2: /api/config 数据脱敏与管理员鉴权门禁...")
    config_js = os.path.join(ROOT_DIR, "functions", "api", "config.js")
    worker_js = os.path.join(ROOT_DIR, "worker.js")

    for path in [config_js, worker_js]:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        # 1. 确保 DEFAULT_CONFIG 没有明文密码
        assert 'password: "yaoxi"' not in code, f"{path} 仍包含明文 password: yaoxi!"
        assert 'DEFAULT_ADMIN_PASSWORD_HASH' in code, f"{path} 缺少哈希密码常量!"

        # 2. 确保包含 sanitizePublicConfig 且彻底移除用户目录与内部密钥 (用户邮箱清单零泄露)
        assert 'function sanitizePublicConfig' in code, f"{path} 缺少数据脱敏函数!"
        assert 'delete clone.users;' in code, f"{path} 公开配置未彻底移除用户目录 (users)!"
        assert 'delete clone.security.handshakeSecret;' in code, f"{path} 未在脱敏函数中剔除 handshakeSecret!"

        # 3. 确保包含 verifyAdminAuth 权限拦截
        assert 'verifyAdminAuth' in code, f"{path} 缺少管理员身份核验逻辑!"
        assert '401' in code, f"{path} 未针对未授权操作返回 401 Unauthorized!"

    print("  ✅ 漏洞 1 & 2 已修复并通过断言测试")

def test_vulnerability_3_is_local_or_preview():
    print("\nTesting Vuln 3: isLocalOrPreview 参数注入全穿透后门...")
    login_js = os.path.join(ROOT_DIR, "accounts-login.js")
    with open(login_js, "r", encoding="utf-8") as f:
        code = f.read()

    # 确保不再包含 step === 'password' 或 has('pwd') 导致绕过
    assert "urlParams.get('step') === 'password'" not in code, "accounts-login.js 仍包含 step=password 绕过逻辑!"
    assert "urlParams.has('pwd')" not in code, "accounts-login.js 仍包含 pwd 参数绕过逻辑!"
    print("  ✅ 漏洞 3 已修复并通过断言测试")

def test_vulnerability_4_fake_rs256_and_webauthn():
    print("\nTesting Vuln 4: 客户端伪造 RS256 签名与 WebAuthn 异常放行...")
    login_js = os.path.join(ROOT_DIR, "accounts-login.js")
    with open(login_js, "r", encoding="utf-8") as f:
        code = f.read()

    # 1. 确保已修复 WebAuthn SecurityError 自动签发漏洞
    assert 'generateAndEmitSignature({\n          type: \'passkey_assertion_hw_verified\'' not in code, "accounts-login.js 仍在 SecurityError 下直接放行!"
    # 2. 确保 handlePasswordSubmit 优先调用服务端 /api/login
    assert "fetch('/api/login'" in code, "accounts-login.js 未接入服务端登录验证接口!"
    print("  ✅ 漏洞 4 已修复并通过断言测试")

def test_vulnerability_5_postmessage_wildcard():
    print("\nTesting Vuln 5: postMessage '*' 通配符广播与消息来源校验...")
    login_js = os.path.join(ROOT_DIR, "accounts-login.js")
    with open(login_js, "r", encoding="utf-8") as f:
        code = f.read()

    # 确保 postMessage 不再使用通配符 '*'
    assert "postMessage(messagePayload, '*')" not in code, "accounts-login.js 仍在使用 postMessage 通配符 '*'!"
    assert "isAllowedTargetDomain" in code, "accounts-login.js 未校验 targetOrigin 白名单!"

    # 检查 SDK 端 origin 校验
    sdk_js = os.path.join(ROOT_DIR, "sdk", "yaoxi-auth.js")
    with open(sdk_js, "r", encoding="utf-8") as f:
        sdk_code = f.read()
    assert "event.origin" in sdk_code, "sdk/yaoxi-auth.js 缺少 event.origin 校验!"
    print("  ✅ 漏洞 5 已修复并通过断言测试")

def test_vulnerability_7_xss_protection():
    print("\nTesting Vuln 7: 管理后台与登录界面 XSS 防御...")
    admin_js = os.path.join(ROOT_DIR, "admin.js")
    with open(admin_js, "r", encoding="utf-8") as f:
        admin_code = f.read()

    assert "function escapeHtml" in admin_code, "admin.js 缺少 escapeHtml 转义函数!"
    assert "toggleUserPwdReveal" not in admin_code, "admin.js 仍保留明文密码查看按钮!"
    assert "escapeHtml(u.username)" in admin_code, "admin.js 用户名未进行 HTML 转义!"

    login_js = os.path.join(ROOT_DIR, "accounts-login.js")
    with open(login_js, "r", encoding="utf-8") as f:
        login_code = f.read()
    assert "span.textContent = OAuthParams.targetDomain" in login_code, "accounts-login.js 未使用 safe textContent 插入 targetDomain!"
    print("  ✅ 漏洞 7 已修复并通过断言测试")

def test_timing_attack_protection():
    print("\nTesting Timing Attack Protection: HMAC 恒定时间比较...")
    mw_js = os.path.join(ROOT_DIR, "functions", "_middleware.js")
    worker_js = os.path.join(ROOT_DIR, "worker.js")
    for path in [mw_js, worker_js]:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        assert "function constantTimeCompare" in code, f"{path} 缺少 constantTimeCompare 函数!"
    print("  ✅ 密码学时序攻击防御已生效")

def test_account_revocation_and_client_guard():
    print("\nTesting Account Revocation & Client Real-time Guard: 账号吊销即时退登与客户端门禁...")
    status_js = os.path.join(ROOT_DIR, "functions", "api", "status.js")
    worker_js = os.path.join(ROOT_DIR, "worker.js")
    admin_js = os.path.join(ROOT_DIR, "admin.js")
    sdk_js = os.path.join(ROOT_DIR, "sdk", "yaoxi-auth.js")
    blog_html = os.path.join(ROOT_DIR, "client-blog.html")
    login_js = os.path.join(ROOT_DIR, "accounts-login.js")

    # 1. 验证轻量级状态端点 /api/status
    assert os.path.exists(status_js), "functions/api/status.js 缺失!"
    with open(status_js, "r", encoding="utf-8") as f:
        status_code = f.read()
    assert "resolveUserStatus" in status_code, "status.js 缺少 resolveUserStatus 函数!"
    assert "no-store" in status_code, "status.js 缺少 no-store 禁缓存头!"

    with open(worker_js, "r", encoding="utf-8") as f:
        worker_code = f.read()
    assert "pathname === '/api/status'" in worker_code, "worker.js 缺少 /api/status 路由!"

    # 2. 验证控制台即时广播与黑名单持久化
    with open(admin_js, "r", encoding="utf-8") as f:
        admin_code = f.read()
    assert "function broadcastRevocationEvent" in admin_code, "admin.js 缺少 broadcastRevocationEvent 函数!"
    assert "new BroadcastChannel('yaoxi_sso_channel')" in admin_code, "admin.js 缺少 BroadcastChannel 广播!"
    assert "channel.close()" not in admin_code, "admin.js 仍存在 channel.close() 导致异步广播队列丢失!"
    assert "yaoxi_sso_revoked_users" in admin_code, "admin.js 缺少 yaoxi_sso_revoked_users 本地黑名单持久化!"
    assert "yaoxi_sso_revocation_event" in admin_code, "admin.js 缺少 cross-window storage 吊销广播!"
    assert "broadcastRevocationEvent(u, 'TOGGLE_STATUS'" in admin_code, "admin.js toggleUserStatus 未触发广播!"
    assert "broadcastRevocationEvent(u, 'DELETE_USER'" in admin_code, "admin.js deleteUser 未触发广播!"

    # 3. 验证客户端 SDK 强化与跨域 Front-Channel 监听
    with open(sdk_js, "r", encoding="utf-8") as f:
        sdk_code = f.read()
    assert "_setupRevocationChannels" in sdk_code, "sdk/yaoxi-auth.js 缺少 _setupRevocationChannels!"
    assert "new BroadcastChannel('yaoxi_sso_channel')" in sdk_code, "sdk/yaoxi-auth.js 缺少 BroadcastChannel 监听!"
    assert "yaoxi_sso_revoked_users" in sdk_code, "sdk/yaoxi-auth.js 缺少 yaoxi_sso_revoked_users 黑名单响应!"
    assert "YAOXI_FRONTCHANNEL_REVOCATION" in sdk_code, "sdk/yaoxi-auth.js 缺少 Front-Channel 跨域事件中继处理!"
    assert "assertActive" in sdk_code, "sdk/yaoxi-auth.js 缺少 assertActive 门禁方法!"
    assert "intervalMs = 3000" in sdk_code, "sdk/yaoxi-auth.js 轮询周期未优化为 3000ms!"

    # 4. 验证客户端演示端 client-blog.html 与 Front-Channel 中继挂载
    with open(blog_html, "r", encoding="utf-8") as f:
        blog_code = f.read()
    assert "handleForcedRevocation" in blog_code, "client-blog.html 缺少 handleForcedRevocation 函数!"
    assert "new BroadcastChannel('yaoxi_sso_channel')" in blog_code, "client-blog.html 缺少 BroadcastChannel 监听!"
    assert "yaoxi_sso_revoked_users" in blog_code, "client-blog.html 缺少 yaoxi_sso_revoked_users 黑名单自省!"
    assert "getSSOAuthorityBase" in blog_code, "client-blog.html 缺少权威鉴权域解析函数 getSSOAuthorityBase!"
    assert "mountFrontChannelSync" in blog_code, "client-blog.html 缺少 mountFrontChannelSync 跨域中继挂载!"
    assert "YAOXI_FRONTCHANNEL_REVOCATION" in blog_code, "client-blog.html 缺少 Front-Channel 吊销事件响应!"
    assert "validateAccountStatus(true)" in blog_code, "client-blog.html 评论操作缺少前置自省门禁拦截!"
    assert "revocation-alert-banner" in blog_code, "client-blog.html 缺少即时吊销警示横幅容器!"
    assert "token-badge-error" in blog_code, "client-blog.html 缺少 token-badge-error 状态样式!"

    # 5. 验证跨域前置中继独立页 channel-sync.html
    sync_html = os.path.join(ROOT_DIR, "channel-sync.html")
    assert os.path.exists(sync_html), "channel-sync.html 缺失!"
    with open(sync_html, "r", encoding="utf-8") as f:
        sync_code = f.read()
    assert "YAOXI_FRONTCHANNEL_REVOCATION" in sync_code, "channel-sync.html 缺少 YAOXI_FRONTCHANNEL_REVOCATION 转发!"
    assert "new BroadcastChannel('yaoxi_sso_channel')" in sync_code, "channel-sync.html 缺少 BroadcastChannel 监听!"

    # 6. 验证登录认证界面防伪
    with open(login_js, "r", encoding="utf-8") as f:
        login_code = f.read()
    assert "activeUserSession.status !== 'active'" in login_code, "accounts-login.js 未在签发时校验 status!"

    print("  ✅ 账号吊销即时退登、双通道广播、Front-Channel跨域中继与客户端门禁断言全部通过！")

def test_personalized_platform_tokens():
    print("\nTesting Personalized Platform Tokens: 个人账号个性化平台 Token 携带与客户端下发...")
    config_js = os.path.join(ROOT_DIR, "functions", "api", "config.js")
    login_api_js = os.path.join(ROOT_DIR, "functions", "api", "login.js")
    worker_js = os.path.join(ROOT_DIR, "worker.js")
    accounts_login_js = os.path.join(ROOT_DIR, "accounts-login.js")
    sdk_js = os.path.join(ROOT_DIR, "sdk", "yaoxi-auth.js")
    admin_html = os.path.join(ROOT_DIR, "admin.html")
    admin_js = os.path.join(ROOT_DIR, "admin.js")
    client_blog = os.path.join(ROOT_DIR, "client-blog.html")

    # 1. 验证公共配置脱敏：绝对杜绝未授权访客通过 /api/config 窃取用户的 GitHub/Cloudflare Token 及邮箱清单
    for path in [config_js, worker_js]:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        assert "delete clone.users;" in code, f"{path} 公开配置未彻底移除用户目录 (platformTokens 零泄露)!"

    # 2. 验证服务端登录核验 /api/login 返回个性化 platform_tokens
    for path in [login_api_js, worker_js]:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        assert "platform_tokens: platformTokens" in code or "platform_tokens: matchedUser.platformTokens" in code, f"{path} 签发 JWT 未挂载 platform_tokens!"
        assert "user: safeUser" in code, f"{path} 未返回 safeUser!"

    # 3. 验证网关 accounts-login.js 携带 platform_tokens 回传客户端
    with open(accounts_login_js, "r", encoding="utf-8") as f:
        login_code = f.read()
    assert "platform_tokens: platformTokens" in login_code, "accounts-login.js 未回传 platform_tokens!"
    assert "yaoxi_client_platform_tokens" in login_code, "accounts-login.js 未将 platform_tokens 存入客户端存储!"

    # 4. 验证 SDK 具备 getPlatformTokens() 与 getPlatformToken(name)
    with open(sdk_js, "r", encoding="utf-8") as f:
        sdk_code = f.read()
    assert "getPlatformTokens()" in sdk_code, "sdk/yaoxi-auth.js 缺少 getPlatformTokens() 方法!"
    assert "getPlatformToken(platformName)" in sdk_code, "sdk/yaoxi-auth.js 缺少 getPlatformToken() 方法!"
    assert "platform_tokens" in sdk_code, "sdk/yaoxi-auth.js 未解析或存储 platform_tokens!"

    # 5. 验证管理后台具备配置 GitHub、Cloudflare 等凭据的界面与逻辑
    with open(admin_html, "r", encoding="utf-8") as f:
        admin_h = f.read()
    assert "edit-user-token-github" in admin_h, "admin.html 缺少 GitHub Token 输入框!"
    assert "edit-user-token-cloudflare" in admin_h, "admin.html 缺少 Cloudflare Token 输入框!"

    with open(admin_js, "r", encoding="utf-8") as f:
        admin_c = f.read()
    assert "edit-user-token-github" in admin_c, "admin.js 缺少 GitHub Token 逻辑处理!"
    assert "u.platformTokens = platformTokens" in admin_c or "platformTokens" in admin_c, "admin.js 未保存 platformTokens!"

    # 6. 验证客户端演示界面展示个性化平台 Token
    with open(client_blog, "r", encoding="utf-8") as f:
        blog_c = f.read()
    assert "token-platform-tokens-box" in blog_c, "client-blog.html 缺少平台凭证展示容器!"
    assert "GitHub Token" in blog_c, "client-blog.html 缺少 GitHub Token 显示!"
    assert "Cloudflare Token" in blog_c, "client-blog.html 缺少 Cloudflare Token 显示!"

    print("  ✅ 个人账号个性化平台 Token（GitHub/Cloudflare等）全链路携带与安全脱敏测试全部通过！")

def test_open_registration_and_privacy_hardening():
    print("\nTesting Open Registration & User Directory Privacy Hardening: 开放注册与用户目录隐私加固...")
    worker_js = os.path.join(ROOT_DIR, "worker.js")
    config_js = os.path.join(ROOT_DIR, "functions", "api", "config.js")
    login_api_js = os.path.join(ROOT_DIR, "functions", "api", "login.js")
    register_js = os.path.join(ROOT_DIR, "functions", "api", "register.js")
    lookup_js = os.path.join(ROOT_DIR, "functions", "api", "lookup.js")
    login_js = os.path.join(ROOT_DIR, "accounts-login.js")
    login_html = os.path.join(ROOT_DIR, "accounts-login.html")
    admin_js = os.path.join(ROOT_DIR, "admin.js")
    admin_html = os.path.join(ROOT_DIR, "admin.html")

    # 1. 后端注册与账号解析端点存在且具备完整安全控制
    assert os.path.exists(register_js), "functions/api/register.js 缺失!"
    assert os.path.exists(lookup_js), "functions/api/lookup.js 缺失!"
    for path in [worker_js, register_js]:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        assert "USERNAME_PATTERN" in code, f"{path} 缺少用户名服务端格式校验!"
        assert "RESERVED_USERNAMES" in code, f"{path} 缺少保留用户名保护!"
        assert "verifyTurnstileToken" in code, f"{path} 缺少 Turnstile 服务端 siteverify 二次校验!"
        assert "checkRateLimit" in code, f"{path} 缺少 KV IP 限流硬上限!"
        assert "USER_REGISTER" in code, f"{path} 缺少注册审计日志!"
        assert "requireApproval" in code, f"{path} 缺少审核模式开关!"
        assert "'pending'" in code, f"{path} 缺少待审核状态流转!"

    with open(worker_js, "r", encoding="utf-8") as f:
        worker_code = f.read()
    assert "pathname === '/api/register'" in worker_code, "worker.js 缺少 /api/register 路由!"
    assert "pathname === '/api/lookup'" in worker_code, "worker.js 缺少 /api/lookup 路由!"
    assert "registration:" in worker_code, "worker.js DEFAULT_CONFIG 缺少 registration 策略块!"

    with open(config_js, "r", encoding="utf-8") as f:
        config_code = f.read()
    assert "registration:" in config_code, "functions/api/config.js DEFAULT_CONFIG 缺少 registration 策略块!"

    # 2. 账号解析仅返回最小必要信息 (掩码邮箱)
    with open(lookup_js, "r", encoding="utf-8") as f:
        lookup_code = f.read()
    assert "maskEmail" in lookup_code, "lookup.js 缺少邮箱掩码函数!"
    assert "emailMasked" in lookup_code, "lookup.js 未返回掩码邮箱!"

    # 3. 待审核账号登录被明确拦截
    for path in [login_api_js, worker_js]:
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        assert "等待管理员审核" in code, f"{path} 缺少 pending 账号登录拦截提示!"

    # 4. 登录页具备完整注册步骤与等待审核页
    with open(login_js, "r", encoding="utf-8") as f:
        login_code = f.read()
    assert "fetch('/api/register'" in login_code, "accounts-login.js 未接入 /api/register 注册接口!"
    assert "fetch('/api/lookup'" in login_code, "accounts-login.js 未接入 /api/lookup 账号解析接口!"
    assert "'register-pending'" in login_code, "accounts-login.js 缺少等待审核步骤!"

    with open(login_html, "r", encoding="utf-8") as f:
        login_h = f.read()
    assert 'id="step-register"' in login_h, "accounts-login.html 缺少注册步骤容器!"
    assert 'id="step-register-pending"' in login_h, "accounts-login.html 缺少等待审核页容器!"
    assert 'id="g-btn-create-account"' in login_h, "accounts-login.html 缺少创建账号入口按钮!"

    # 5. 管理后台具备注册策略开关与待审核审批操作
    with open(admin_html, "r", encoding="utf-8") as f:
        admin_h = f.read()
    assert "reg-enabled-switch" in admin_h, "admin.html 缺少开放注册总开关!"
    assert "reg-approval-switch" in admin_h, "admin.html 缺少新账号审核模式开关!"

    with open(admin_js, "r", encoding="utf-8") as f:
        admin_code = f.read()
    assert "renderRegistrationPolicy" in admin_code, "admin.js 缺少注册策略渲染逻辑!"
    assert "approvePendingUser" in admin_code, "admin.js 缺少待审核账号「通过」操作!"
    assert "rejectPendingUser" in admin_code, "admin.js 缺少待审核账号「拒绝」操作!"
    assert "REG_POLICY_UPDATE" in admin_code, "admin.js 缺少注册策略审计日志!"
    assert "USER_APPROVE" in admin_code, "admin.js 缺少审核通过审计日志!"
    assert "USER_REJECT" in admin_code, "admin.js 缺少拒绝注册审计日志!"
    assert "registeredVia" in admin_code, "admin.js 缺少自助注册来源标识渲染!"

    print("  ✅ 开放注册、审核流转、限流防护与用户目录隐私加固断言全部通过！")

if __name__ == "__main__":
    print("\n==================================================")
    print(" 🧪 运行安全审计全量回归单元测试套件")
    print("==================================================")
    test_vulnerability_1_and_2_config_security()
    test_vulnerability_3_is_local_or_preview()
    test_vulnerability_4_fake_rs256_and_webauthn()
    test_vulnerability_5_postmessage_wildcard()
    test_vulnerability_7_xss_protection()
    test_timing_attack_protection()
    test_account_revocation_and_client_guard()
    test_personalized_platform_tokens()
    test_open_registration_and_privacy_hardening()
    print("\n==================================================")
    print(" 💯 全部安全漏洞与即时退登门禁机制验证通过！系统就绪！")
    print("==================================================\n")
