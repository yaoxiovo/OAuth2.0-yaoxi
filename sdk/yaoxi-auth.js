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
      this._revocationListeners = [];
      this._messageListener = null;
      this._popupWindow = null;
      this._ssoChannel = null;

      this._setupRevocationChannels();
    }

    /**
     * 挂载多通道账号吊销即时监听器 (BroadcastChannel + Storage Event)
     */
    _setupRevocationChannels() {
      // 1. BroadcastChannel (0延迟同源跨标签页/窗口双向即时同步)
      if (typeof BroadcastChannel !== 'undefined') {
        try {
          this._ssoChannel = new BroadcastChannel('yaoxi_sso_channel');
          this._ssoChannel.onmessage = (event) => {
            this._handleRevocationEvent(event.data);
          };
        } catch (e) {
          console.warn('[YaoxiAuth SDK] BroadcastChannel init warning:', e);
        }
      }

      // 2. Storage Event (跨窗口原生存储事件兜底)
      if (typeof window !== 'undefined' && window.addEventListener) {
        window.addEventListener('storage', (event) => {
          if (event.key === 'yaoxi_sso_revocation_event' && event.newValue) {
            try {
              const data = JSON.parse(event.newValue);
              this._handleRevocationEvent(data);
            } catch (e) {}
          } else if (event.key === 'yaoxi_sso_revoked_users' && event.newValue) {
            this.validateStatus();
          } else if (event.key === 'yaoxi_sso_config') {
            this.validateStatus();
          }
        });

        // 3. OIDC Front-Channel 跨域 iframe 中继消息监听
        window.addEventListener('message', (event) => {
          if (!event.data || typeof event.data !== 'object') return;
          if (event.data.type === 'YAOXI_FRONTCHANNEL_REVOCATION') {
            this._handleRevocationEvent(event.data.payload || event.data);
          } else if (event.data.type === 'YAOXI_FRONTCHANNEL_READY' || event.data.type === 'YAOXI_FRONTCHANNEL_BLACKLIST_UPDATE') {
            const list = (event.data.payload && event.data.payload.revokedUsers) || event.data.revokedUsers || event.data.payload;
            if (Array.isArray(list)) {
              try {
                localStorage.setItem('yaoxi_sso_revoked_users', JSON.stringify(list));
              } catch (e) {}
              this.validateStatus();
            }
          }
        });
      }
    }

    /**
     * 处理广播的账号状态变更/吊销事件
     */
    _handleRevocationEvent(data) {
      if (!data || data.type !== 'YAOXI_ACCOUNT_REVOCATION_EVENT') return;
      const user = this.getUser();
      if (!user) return;

      const curSub = (user.sub || user.username || '').toLowerCase();
      const curEmail = (user.email || '').toLowerCase();
      const curId = user.id || '';

      const targetSub = (data.username || '').toLowerCase();
      const targetEmail = (data.email || '').toLowerCase();
      const targetId = data.userId || '';

      const isMatch = (data.userId === '*' || targetId === curId || (targetSub && targetSub === curSub) || (targetEmail && targetEmail === curEmail));

      if (isMatch && (data.status === 'suspended' || data.action === 'DELETE_USER' || data.action === 'FACTORY_RESET')) {
        console.warn('[YaoxiAuth SDK] Active user session revoked by admin:', data);
        this.logout();
        for (const cb of this._revocationListeners) {
          try {
            cb(data);
          } catch (e) {
            console.error('[YaoxiAuth SDK] Revocation listener error:', e);
          }
        }
      }
    }

    /**
     * 注册账号被吊销/冻结时的监听回调
     * @param {function(event: Object): void} callback
     */
    onRevoked(callback) {
      if (typeof callback === 'function') {
        this._revocationListeners.push(callback);
      }
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

      const curSub = (user.sub || user.username || '').toLowerCase();
      const curEmail = (user.email || '').toLowerCase();
      const curId = user.id || '';

      // 0. 本地 LocalStorage 独立黑名单极速自省 (0 延迟毫秒级拦截)
      try {
        const blStr = localStorage.getItem('yaoxi_sso_revoked_users');
        if (blStr) {
          const bl = JSON.parse(blStr);
          if (Array.isArray(bl)) {
            const hit = bl.some(item => {
              if (item.id === '*' || item.username === '*' || item.email === '*') return true;
              if (curId && item.id === curId) return true;
              if (curSub && (item.username === curSub || item.email === curSub)) return true;
              if (curEmail && (item.email === curEmail || item.username === curEmail)) return true;
              return false;
            });
            if (hit) {
              this.logout();
              this._triggerRevocation({ reason: 'ACCOUNT_SUSPENDED_BLACKLIST', username: curSub });
              return false;
            }
          }
        }
      } catch (e) {}

      // 1. 本地 LocalStorage 配置优先自省 (同源或本地调试极速判定)
      try {
        const localCfgStr = localStorage.getItem('yaoxi_sso_config');
        if (localCfgStr) {
          const localCfg = JSON.parse(localCfgStr);
          if (Array.isArray(localCfg.users)) {
            const matched = localCfg.users.find(u => {
              const uName = (u.username || '').toLowerCase();
              const uEmail = (u.email || '').toLowerCase();
              return (curSub && (uName === curSub || uEmail === curSub)) || (curEmail && (uEmail === curEmail || uName === curEmail));
            });
            if (!matched || matched.status !== 'active') {
              this.logout();
              this._triggerRevocation({ reason: 'ACCOUNT_SUSPENDED_LOCAL', username: curSub });
              return false;
            }
          }
        }
      } catch (e) {}

      // 解析权威认证中心基地址 (优先信任 Token Payload 中的 iss 机构)
      let targetAuthUrl = this.authUrl;
      if (user.iss && typeof user.iss === 'string' && user.iss.startsWith('http')) {
        targetAuthUrl = user.iss;
      }
      const base = targetAuthUrl.replace(/\/+$/, '');

      // 2. 服务端轻量级 /api/status 高频自省端点 (0延迟、无缓存)
      try {
        const statusUrl = `${base}/api/status?username=${encodeURIComponent(curSub)}&email=${encodeURIComponent(curEmail)}&id=${encodeURIComponent(curId)}&t=${Date.now()}`;
        const res = await fetch(statusUrl, { cache: 'no-store' });
        if (res.ok) {
          const data = await res.json();
          if (data && (data.revoked || !data.active || data.status === 'suspended')) {
            this.logout();
            this._triggerRevocation({ reason: 'ACCOUNT_SUSPENDED_REMOTE', username: curSub });
            return false;
          }
          return true;
        }
      } catch (e) {}

      // 3. 服务端配置 /api/config 兜底自省端点
      try {
        const cfgRes = await fetch(`${base}/api/config?t=${Date.now()}`, { cache: 'no-store' });
        if (cfgRes.ok) {
          const cfg = await cfgRes.json();
          if (cfg && Array.isArray(cfg.users)) {
            const matched = cfg.users.find(u => (u.username || '').toLowerCase() === curSub || (u.email || '').toLowerCase() === curEmail);
            if (!matched || matched.status !== 'active') {
              this.logout();
              this._triggerRevocation({ reason: 'ACCOUNT_SUSPENDED_CONFIG', username: curSub });
              return false;
            }
          }
        }
      } catch (e) {}

      return true;
    }

    _triggerRevocation(data) {
      for (const cb of this._revocationListeners) {
        try {
          cb(data);
        } catch (e) {
          console.error('[YaoxiAuth SDK] Revocation listener error:', e);
        }
      }
    }

    /**
     * 前置操作拦截门禁 (Pre-Action Guard)
     * 在敏感操作 (发表评论、调取受保护接口) 前强制执行
     * @returns {Promise<boolean>} 若通过返回 true，若未登录或已冻结则抛出异常并阻断执行
     */
    async assertActive() {
      if (!this.isAuthenticated()) {
        throw new Error('UNAUTHENTICATED: 用户未登录或凭据已失效');
      }
      const valid = await this.validateStatus();
      if (!valid) {
        throw new Error('ACCOUNT_REVOKED: 账号已被统一身份认证中心冻结或注销');
      }
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
     * 自动监控账号实时状态 (窗口激活、可见性切换或定时轮询)
     * @param {function(user: Object): void} [onFrozenCallback] - 账号被冻结时的回调
     * @param {number} [intervalMs=3000] - 轮询间隔毫秒数 (默认 3 秒高频检测)
     * @returns {function(): void} 取消监控的注销函数
     */
    watchAccountStatus(onFrozenCallback, intervalMs = 3000) {
      if (typeof onFrozenCallback === 'function') {
        this.onRevoked(onFrozenCallback);
      }

      const check = async () => {
        if (this.isAuthenticated()) {
          const valid = await this.validateStatus();
          if (!valid && typeof onFrozenCallback === 'function') {
            onFrozenCallback();
          }
        }
      };

      const focusHandler = () => check();
      const visHandler = () => { if (document.visibilityState === 'visible') check(); };

      window.addEventListener('focus', focusHandler);
      document.addEventListener('visibilitychange', visHandler);
      const timer = setInterval(check, intervalMs);

      return () => {
        window.removeEventListener('focus', focusHandler);
        document.removeEventListener('visibilitychange', visHandler);
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
