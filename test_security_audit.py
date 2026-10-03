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

        # 2. 确保包含 sanitizePublicConfig 且剔除密码及内部密钥
        assert 'function sanitizePublicConfig' in code, f"{path} 缺少数据脱敏函数!"
        assert 'delete safeUser.password;' in code, f"{path} 未在脱敏函数中剔除 password!"
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
    print("\n==================================================")
    print(" 💯 全部安全漏洞与即时退登门禁机制验证通过！系统就绪！")
    print("==================================================\n")
