/**
 * yaoxi-auth.js - 耀西统一身份认证中心客户端 SDK
 * 适用于 Web 前端、单页应用 (SPA)、博客、控制台等第三方/子业务系统
 *
 * 功能特性:
 * 1. 1:1 调起 accounts.yaoxi.cloud 统一 Google Material 3 登录框
 * 2. 自动生成密码学 HMAC-SHA256 client_request_token 防伪握手凭证
 * 3. 支持弹窗模式 (Popup - 类似 Google One Tap / Sign-in) 与重定向模式 (Redirect)
 * 4. 实时监听 postMessage 跨域广播，自动解析 RS256 时效 Token (Access Token / ID Token)
 * 5. 本地 Token 时效维护与用户身份状态管理
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.YaoxiAuth = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const DEFAULT_SSO_URL = 'https://accounts.yaoxi.cloud';
  const SSO_HANDSHAKE_SECRET = 'yaoxi_sso_handshake_secret_key_v1_auth_guard_2026';

  class YaoxiAuth {
    /**
     * 初始化 SDK 配置
     * @param {Object} options
     * @param {string} options.clientId - 客户端标识 (如 'yaoxi-blog')
     * @param {string} [options.authUrl] - 认证中心地址 (默认 https://accounts.yaoxi.cloud 或相对路径)
     * @param {string} [options.redirectUri] - 登录完成后跳转或回调地址
     * @param {string} [options.targetDomain] - 目标业务域名 (如 'blog.yaoxi.wiki')
     * @param {'popup'|'redirect'} [options.mode='popup'] - 登录交互方式 (popup 为弹窗，redirect 为全页跳转)
     * @param {string} [options.scope='openid profile email admin'] - 申请授权范围
     */
    constructor(options = {}) {
      this.clientId = options.clientId || 'yaoxi-client-app';
      this.authUrl = options.authUrl || DEFAULT_SSO_URL;
      this.redirectUri = options.redirectUri || window.location.href.split('#')[0];
      this.targetDomain = options.targetDomain || window.location.hostname;
      this.mode = options.mode || 'popup';
      this.scope = options.scope || 'openid profile email admin';
      this.storagePrefix = 'yaoxi_auth_';

      this._authListeners = [];
      this._messageListener = null;
      this._popupWindow = null;
    }

    /**
     * 生成符合 accounts 规范的 HMAC-SHA256 握手凭证
     */
    async createSignedHandshakeToken() {
      const timestamp = Date.now().toString();
      const nonce = Math.random().toString(36).substring(2, 10);
      const payload1 = `v1.${timestamp}.${nonce}`;
      const payload2 = `v1.${timestamp}.${nonce}.${this.targetDomain}`;

      if (window.crypto && window.crypto.subtle) {
        try {
          const enc = new TextEncoder();
          const key = await crypto.subtle.importKey(
            'raw',
            enc.encode(SSO_HANDSHAKE_SECRET),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
          );
          const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payload2));
          const sigHex = Array.from(new Uint8Array(sigBuf))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .substring(0, 32);

          return `crt.v1.${timestamp}.${nonce}.${sigHex}`;
        } catch (e) {
          console.warn('[YaoxiAuth SDK] Crypto Subtle HMAC error, using fallback:', e);
        }
      }

      // Fallback signature format
      return `crt.v1.${timestamp}.${nonce}.sigfallback`;
    }

    /**
     * 发起登录流程
     * @param {Object} [overrideOptions]
     * @returns {Promise<{ user: Object, accessToken: string, idToken: string, signature: string }>}
     */
    async login(overrideOptions = {}) {
      const mode = overrideOptions.mode || this.mode;
      const clientRequestToken = await this.createSignedHandshakeToken();

      const params = new URLSearchParams({
        client_id: this.clientId,
        target_domain: this.targetDomain,
        redirect_uri: this.redirectUri,
        client_request_token: clientRequestToken,
        response_type: 'token',
        scope: this.scope,
        state: 'st_' + Math.random().toString(36).substring(2, 10)
      });

      const ssoTargetUrl = `${this.authUrl.replace(/\/$/, '')}/accounts-login.html?${params.toString()}`;

      if (mode === 'redirect') {
        // 重定向模式
        sessionStorage.setItem(this.storagePrefix + 'pending_token', clientRequestToken);
        window.location.href = ssoTargetUrl;
        return new Promise(() => {}); // 页面即将跳转
      }

      // 弹窗模式 (Popup - 类似 Google Sign-In)
      return new Promise((resolve, reject) => {
        const width = 1060;
        const height = 620;
        const left = Math.max(0, (window.screen.width - width) / 2);
        const top = Math.max(0, (window.screen.height - height) / 2);

        this._popupWindow = window.open(
          ssoTargetUrl,
          'yaoxi_sso_popup',
          `width=${width},height=${height},top=${top},left=${left},toolbar=no,menubar=no,location=yes,status=no,resizable=yes,scrollbars=yes`
        );

        if (!this._popupWindow || this._popupWindow.closed) {
          return reject(new Error('浏览器拦截了弹窗，请允许弹出窗口后重试'));
        }

        // 监听跨域 postMessage 消息
        const handleMessage = (event) => {
          const data = event.data;
          if (!data || data.type !== 'YAOXI_SSO_SIGNATURE_CALLBACK') return;

          // 严格校验发送方 Origin 来源 (Strict Origin Verification)
          let expectedOrigin = '';
          try {
            expectedOrigin = new URL(this.authUrl).origin;
          } catch (e) {
            expectedOrigin = 'https://accounts.yaoxi.cloud';
          }

          if (event.origin !== expectedOrigin && event.origin !== 'https://accounts.yaoxi.cloud') {
            console.warn('[YaoxiAuth SDK] Rejected cross-origin message from unauthorized origin:', event.origin);
            return;
          }

          // 校验回传与凭据绑定
          if (data.client_request_token !== clientRequestToken) {
            console.warn('[YaoxiAuth SDK] Received token does not match request token.');
            return;
          }

          window.removeEventListener('message', handleMessage);
          clearInterval(pollTimer);

          if (this._popupWindow && !this._popupWindow.closed) {
            this._popupWindow.close();
          }

          const bundle = data.tokenBundle || {};
          const accessToken = bundle.access_token || data.signed_token;
          const user = bundle.user || this.parseJwtPayload(accessToken);

          this._saveAuthData(accessToken, user, bundle.expires_in || 7200);

          resolve({
            user,
            accessToken,
            idToken: bundle.id_token || accessToken,
            signature: data.signature || bundle.signature,
            expiresIn: bundle.expires_in || 7200
          });
        };

        window.addEventListener('message', handleMessage);

        // 轮询检查用户是否中途手动关闭了弹窗
        const pollTimer = setInterval(() => {
          if (this._popupWindow && this._popupWindow.closed) {
            clearInterval(pollTimer);
            window.removeEventListener('message', handleMessage);
            reject(new Error('用户取消了登录或关闭了认证窗口'));
          }
        }, 800);
      });
    }

    /**
     * 重定向模式下的回调解析
     */
    handleCallback() {
      const hash = window.location.hash.substring(1);
      if (!hash) return null;

      const params = new URLSearchParams(hash);
      const accessToken = params.get('access_token');
      if (!accessToken) return null;

      const user = this.parseJwtPayload(accessToken);
      const expiresIn = parseInt(params.get('expires_in'), 10) || 7200;

      this._saveAuthData(accessToken, user, expiresIn);

      // 清除 URL 中的 hash 保持地址栏整洁
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, document.title, window.location.pathname + window.location.search);
      }

      return {
        user,
        accessToken,
        signature: params.get('signature'),
        expiresIn
      };
    }

    /**
     * 判断当前是否已登录且有效
     * @returns {boolean}
     */
    isAuthenticated() {
      return !!this.getToken();
    }

    /**
     * 校验当前登录账号是否已被服务端管理员冻结
     * @returns {Promise<boolean>} 若已被冻结返回 false 并自动登出，正常返回 true
     */
    async validateStatus() {
      const user = this.getUser();
      if (!user) return false;
      try {
        const res = await fetch(`${this.authUrl}/api/config?t=${Date.now()}`, { cache: 'no-store' });
        if (res.ok) {
          const cfg = await res.json();
          if (cfg && Array.isArray(cfg.users)) {
            const sub = (user.sub || '').toLowerCase();
            const email = (user.email || '').toLowerCase();
            const matched = cfg.users.find(u => (u.username || '').toLowerCase() === sub || (u.email || '').toLowerCase() === email);
            if (matched && matched.status !== 'active') {
              this.logout();
              return false;
            }
          }
        }
      } catch (e) {}
      return true;
    }

    /**
     * 获取当前已登录的用户信息 (自动检查 Token 是否过期)
     */
    getUser() {
      const token = this.getToken();
      if (!token) return null;

      try {
        const userJson = localStorage.getItem(this.storagePrefix + 'user');
        return userJson ? JSON.parse(userJson) : null;
      } catch (e) {
        return null;
      }
    }

    /**
     * 获取当前有效 Token (若已过期返回 null)
     */
    getToken() {
      const token = localStorage.getItem(this.storagePrefix + 'token');
      const expStr = localStorage.getItem(this.storagePrefix + 'exp');

      if (!token) return null;
      if (expStr) {
        const expTime = parseInt(expStr, 10);
        if (Date.now() >= expTime) {
          this.logout();
          return null;
        }
      }
      return token;
    }

    /**
     * 监听用户认证状态变更 (登录 / 登出)
     * @param {function(user: Object|null): void} callback
     */
    onAuthStateChanged(callback) {
      if (typeof callback === 'function') {
        this._authListeners.push(callback);
        // 立即触发一次当前状态
        callback(this.getUser());
      }
    }

    /**
     * 自动监控账号实时状态 (窗口激活或定时轮询)
     * @param {function(user: Object): void} [onFrozenCallback] - 账号被冻结时的回调
     * @param {number} [intervalMs=60000] - 轮询间隔毫秒数
     * @returns {function(): void} 取消监控的注销函数
     */
    watchAccountStatus(onFrozenCallback, intervalMs = 60000) {
      const check = async () => {
        if (this.isAuthenticated()) {
          const valid = await this.validateStatus();
          if (!valid && typeof onFrozenCallback === 'function') {
            onFrozenCallback();
          }
        }
      };

      const focusHandler = () => check();
      window.addEventListener('focus', focusHandler);
      const timer = setInterval(check, intervalMs);

      return () => {
        window.removeEventListener('focus', focusHandler);
        clearInterval(timer);
      };
    }

    /**
     * 退出登录并清除本地凭证
     */
    logout() {
      localStorage.removeItem(this.storagePrefix + 'token');
      localStorage.removeItem(this.storagePrefix + 'user');
      localStorage.removeItem(this.storagePrefix + 'exp');
      this._notifyAuthChanged(null);
    }

    /**
     * 本地存储 Token 与用户
     */
    _saveAuthData(token, user, expiresInSec = 7200) {
      const expTime = Date.now() + expiresInSec * 1000;
      localStorage.setItem(this.storagePrefix + 'token', token);
      localStorage.setItem(this.storagePrefix + 'user', JSON.stringify(user));
      localStorage.setItem(this.storagePrefix + 'exp', expTime.toString());
      this._notifyAuthChanged(user);
    }

    /**
     * 广播用户状态变更
     */
    _notifyAuthChanged(user) {
      for (const listener of this._authListeners) {
        try {
          listener(user);
        } catch (e) {
          console.warn('[YaoxiAuth SDK] Auth listener error:', e);
        }
      }
    }

    /**
     * 解析 JWT Token 荷载
     */
    parseJwtPayload(jwtToken) {
      if (!jwtToken || typeof jwtToken !== 'string') return {};
      try {
        const parts = jwtToken.split('.');
        if (parts.length >= 2) {
          const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
          const jsonStr = decodeURIComponent(escape(atob(base64)));
          return JSON.parse(jsonStr);
        }
      } catch (e) {
        console.warn('[YaoxiAuth SDK] Failed to decode JWT payload:', e);
      }
      return {};
    }
  }

  return YaoxiAuth;
});
