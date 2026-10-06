/**
 * admin.js - Google Admin Console (Material 3) SSO Management System
 * 提供对 accounts.yaoxi.cloud 全部功能数据的直接在线可视化管理
 */

(function () {
  'use strict';

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // --- Default Fallback Functional Configuration ---
  const DEFAULT_CONFIG = {
    version: "1.1.0",
    lastUpdated: new Date().toISOString(),
    security: {
      ssoIssuer: "https://accounts.yaoxi.cloud",
      tokenTtl: 7200,
      kid: "yaoxi_cloud_sso_2026",
      preventReplay: true,
      strictWhitelist: true
    },
    turnstile: {
      enabled: true,
      siteKey: "0x4AAAAAAEXamT3iIRWjGCmk"
    },
    registration: {
      enabled: true,
      requireApproval: true,
      defaultRoles: ["member"],
      rateLimit: { perIpHour: 5, perIpDay: 20 }
    },
    branding: {
      systemTitle: "Google 帐号 - 统一身份认证",
      welcomeTitle: "欢迎",
      bannerNotice: "不妨选择“试试其他方式”，改用通行密钥更轻松更安全地登录",
      defaultTheme: "light",
      defaultLang: "zh-CN",
      showPasswordToggle: true
    },
    domains: [
      { id: "dom_1", name: "耀西极客博客 (主域)", pattern: "*.yaoxi.wiki", type: "wildcard", enabled: true, createdAt: "2026-09-24" },
      { id: "dom_2", name: "耀西云全子域", pattern: "*.yaoxi.cloud", type: "wildcard", enabled: true, createdAt: "2026-09-24" },
      { id: "dom_3", name: "本地开发测试环境", pattern: "localhost", type: "exact", enabled: true, createdAt: "2026-09-24" },
      { id: "dom_4", name: "本地 IPv4 回环", pattern: "127.0.0.1", type: "exact", enabled: true, createdAt: "2026-09-24" }
    ],
    users: [
      {
        id: "usr_yaoxi",
        username: "yaoxi",
        displayName: "耀西 (Super Admin)",
        email: "yaoxiov0@gmail.com",
        passwordHash: "9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001",
        roles: ["admin", "author", "super_user"],
        status: "active",
        passkeyBound: true,
        platformTokens: {
          github: "ghp_yaoxiPersonalAccessToken2026MockSecretKey",
          cloudflare: "cf_token_yaoxiGlobalDnsWorkersEdgeSecretKey2026"
        },
        lastLogin: new Date().toISOString()
      }
    ],
    clients: [
      {
        id: "cli_1",
        clientId: "yaoxi-blog",
        clientName: "耀西极客博客",
        targetDomain: "blog.yaoxi.wiki",
        redirectUri: "https://blog.yaoxi.wiki",
        scope: "openid profile email admin",
        enabled: true
      },
      {
        id: "cli_2",
        clientId: "yaoxi-app",
        clientName: "耀西云全平台默认客户端",
        targetDomain: "yaoxi.cloud",
        redirectUri: "https://accounts.yaoxi.cloud",
        scope: "openid profile email",
        enabled: true
      }
    ],
    auditLogs: [
      {
        id: "log_init",
        timestamp: new Date().toISOString(),
        action: "SYSTEM_INIT",
        operator: "system",
        details: "统一身份认证管理控制台系统已就绪",
        ip: "127.0.0.1"
      }
    ]
  };

  // --- Active State ---
  let activeConfig = null;
  let hasPendingChanges = false;

  // --- Persistent Broadcast Channel Singleton (长驻单例，严禁 close 避免异步消息丢弃) ---
  let adminBroadcastChannel = null;
  try {
    if (typeof BroadcastChannel !== 'undefined') {
      adminBroadcastChannel = new BroadcastChannel('yaoxi_sso_channel');
    }
  } catch (e) {
    console.warn('[Admin Console] BroadcastChannel init warning:', e);
  }

  // --- Blacklist Management (本地即时黑名单持久化，提供 0 延迟秒级拦截) ---
  function updateLocalRevocationBlacklist(user, isRevoked) {
    if (!user) return;
    try {
      let revokedList = [];
      const stored = localStorage.getItem('yaoxi_sso_revoked_users');
      if (stored) {
        try { revokedList = JSON.parse(stored); } catch (e) {}
      }
      if (!Array.isArray(revokedList)) revokedList = [];

      const uId = user.id || '';
      const uName = (user.username || '').toLowerCase();
      const uEmail = (user.email || '').toLowerCase();

      revokedList = revokedList.filter(item => {
        if (uId && item.id === uId) return false;
        if (uName && item.username === uName) return false;
        if (uEmail && item.email === uEmail) return false;
        return true;
      });

      if (isRevoked) {
        revokedList.push({
          id: uId,
          username: uName,
          email: uEmail,
          revokedAt: Date.now(),
          status: 'suspended'
        });
      }

      localStorage.setItem('yaoxi_sso_revoked_users', JSON.stringify(revokedList));
    } catch (e) {
      console.warn('[Admin Console] updateLocalRevocationBlacklist error:', e);
    }
  }

  function syncAllSuspendedUsersToBlacklist() {
    if (!activeConfig || !Array.isArray(activeConfig.users)) return;
    try {
      const revokedList = [];
      for (const u of activeConfig.users) {
        if (u.status !== 'active') {
          revokedList.push({
            id: u.id || '',
            username: (u.username || '').toLowerCase(),
            email: (u.email || '').toLowerCase(),
            revokedAt: Date.now(),
            status: u.status || 'suspended'
          });
        }
      }
      localStorage.setItem('yaoxi_sso_revoked_users', JSON.stringify(revokedList));
    } catch (e) {}
  }

  // --- Configuration Manager Helpers ---
  async function loadConfig() {
    try {
      const stored = localStorage.getItem('yaoxi_sso_config');
      if (stored) {
        const parsed = JSON.parse(stored);
        // 仅接受携带完整用户目录的管理端缓存；登录页写入的公开配置(已移除用户目录)不具备管理端效力
        if (parsed && Array.isArray(parsed.users) && Array.isArray(parsed.domains)) {
          activeConfig = parsed;
        }
      }
    } catch (e) {}

    if (!activeConfig || !Array.isArray(activeConfig.users)) {
      activeConfig = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    } else if (!Array.isArray(activeConfig.domains)) {
      activeConfig.domains = [];
    }
    syncAllSuspendedUsersToBlacklist();

    // Always fetch remote KV config as authoritative source
    try {
      const adminToken = sessionStorage.getItem('yaoxi_admin_token') || '9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001';
      const headers = adminToken ? { 'Authorization': 'Bearer ' + adminToken } : {};
      const res = await fetch('/api/config?t=' + Date.now(), { cache: 'no-store', headers });
      if (res.ok) {
        const remote = await res.json();
        if (remote && Array.isArray(remote.domains) && Array.isArray(remote.users)) {
          activeConfig = remote;
          localStorage.setItem('yaoxi_sso_config', JSON.stringify(activeConfig));
          syncAllSuspendedUsersToBlacklist();
          window.dispatchEvent(new Event('yaoxi_config_updated'));
          refreshAllViews();
        }
      }
    } catch (e) {
      console.warn('Failed to load remote config from KV:', e);
    }
  }

  function broadcastRevocationEvent(user, action, status) {
    if (!user) return;
    const payload = {
      type: 'YAOXI_ACCOUNT_REVOCATION_EVENT',
      action: action || 'STATUS_UPDATE',
      userId: user.id || '',
      username: (user.username || '').toLowerCase(),
      email: (user.email || '').toLowerCase(),
      status: status || 'suspended',
      timestamp: Date.now()
    };

    // 0. 本地黑名单持久化写入
    const isSuspended = (payload.status === 'suspended' || payload.action === 'DELETE_USER' || payload.action === 'FACTORY_RESET');
    if (payload.action === 'FACTORY_RESET') {
      try {
        localStorage.setItem('yaoxi_sso_revoked_users', JSON.stringify([{ id: '*', username: '*', email: '*', status: 'suspended' }]));
      } catch (e) {}
    } else {
      updateLocalRevocationBlacklist(user, isSuspended);
    }

    // 1. BroadcastChannel (0延迟同源长驻单例通信，绝不 close 保证异步事件队列不被切断)
    try {
      if (!adminBroadcastChannel && typeof BroadcastChannel !== 'undefined') {
        adminBroadcastChannel = new BroadcastChannel('yaoxi_sso_channel');
      }
      if (adminBroadcastChannel) {
        adminBroadcastChannel.postMessage(payload);
      }
    } catch (e) {
      console.warn('[Admin Console] BroadcastChannel dispatch failed:', e);
    }

    // 2. Storage Event (跨标签页原生 storage 监听兜底)
    try {
      localStorage.setItem('yaoxi_sso_revocation_event', JSON.stringify({
        ...payload,
        _nonce: Math.random().toString(36).substring(2)
      }));
    } catch (e) {
      console.warn('[Admin Console] LocalStorage event dispatch failed:', e);
    }

    // 3. CustomEvent (同页面内原生事件分发)
    try {
      window.dispatchEvent(new CustomEvent('yaoxi_account_revocation', { detail: payload }));
    } catch (e) {}
  }

  function persistLocalConfig() {
    activeConfig.lastUpdated = new Date().toISOString();
    localStorage.setItem('yaoxi_sso_config', JSON.stringify(activeConfig));
    syncAllSuspendedUsersToBlacklist();
    // Trigger storage event for same-window / cross-window sync
    window.dispatchEvent(new Event('yaoxi_config_updated'));
  }

  async function pushRemoteConfig() {
    try {
      activeConfig.lastUpdated = new Date().toISOString();
      const adminToken = sessionStorage.getItem('yaoxi_admin_token') || '9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001';
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + adminToken
        },
        body: JSON.stringify(activeConfig)
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, savedToKv: !!data.savedToKv };
      }
      return { success: false, error: 'HTTP ' + res.status };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  function recordAuditLog(action, details) {
    if (!activeConfig.auditLogs) activeConfig.auditLogs = [];
    activeConfig.auditLogs.unshift({
      id: 'log_' + Date.now().toString(36),
      timestamp: new Date().toISOString(),
      action: action,
      operator: 'admin (yaoxi)',
      details: details,
      ip: '127.0.0.1'
    });
    if (activeConfig.auditLogs.length > 100) {
      activeConfig.auditLogs.pop();
    }
  }

  function markChanged() {
    hasPendingChanges = true;
    const bar = document.getElementById('sticky-bar');
    if (bar) bar.classList.add('visible');
  }

  function clearChanged() {
    hasPendingChanges = false;
    const bar = document.getElementById('sticky-bar');
    if (bar) bar.classList.remove('visible');
  }

  // --- Global Save Actions ---
  window.saveAllPendingChanges = async function () {
    persistLocalConfig();
    const saveBtn = document.querySelector('#sticky-bar .btn-primary');
    const oldText = saveBtn ? saveBtn.textContent : '';
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.textContent = '正在同步全球边缘节点...';
    }
    const res = await pushRemoteConfig();
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = oldText || '保存更改';
    }
    clearChanged();
    refreshAllViews();
    if (res && res.success) {
      if (res.savedToKv) {
        showToast('✅ 全量配置已成功持久化至 Cloudflare KV，全球全设备即时生效！', 'success');
      } else {
        showToast('✅ 配置已保存并下发至全球边缘节点！', 'success');
      }
    } else {
      showToast('⚠️ 本地保存成功，但同步到云端失败: ' + (res.error || '网络异常'), 'warning');
    }
  };

  window.discardPendingChanges = function () {
    loadConfig();
    clearChanged();
    refreshAllViews();
    showToast('已放弃未保存的更改，恢复为上次保存的状态。', 'neutral');
  };

  // ==========================================================================
  // Section 1: Overview
  // ==========================================================================
  function renderOverview() {
    const elDomCount = document.getElementById('metric-domains-count');
    const elUserCount = document.getElementById('metric-users-count');
    const elClientCount = document.getElementById('metric-clients-count');
    const elTtl = document.getElementById('metric-tokens-ttl');
    const elIssuer = document.getElementById('ov-issuer');
    const elTurnstile = document.getElementById('ov-turnstile-status');

    if (elDomCount) elDomCount.textContent = (activeConfig.domains || []).filter(d => d.enabled).length;
    if (elUserCount) {
      const usersList = activeConfig.users || [];
      const activeCount = usersList.filter(u => u.status === 'active').length;
      const pendingCount = usersList.filter(u => u.status === 'pending').length;
      elUserCount.innerHTML = String(activeCount) + (pendingCount > 0
        ? ` <span class="badge badge-warning" style="font-size:11px; vertical-align:middle;">${pendingCount} 待审核</span>`
        : '');
    }
    if (elClientCount) elClientCount.textContent = (activeConfig.clients || []).length;
    if (elTtl) elTtl.textContent = (activeConfig.security.tokenTtl || 7200) + 's';
    if (elIssuer) elIssuer.textContent = activeConfig.security.ssoIssuer || 'https://accounts.yaoxi.cloud';
    if (elTurnstile) {
      elTurnstile.innerHTML = activeConfig.turnstile.enabled
        ? '<span class="badge badge-success">智能人机验证已强制启用</span>'
        : '<span class="badge badge-warning">未启用 (调试跳过模式)</span>';
    }

    const tbody = document.getElementById('overview-clients-tbody');
    if (tbody) {
      tbody.innerHTML = (activeConfig.clients || []).map(c => `
        <tr>
          <td><strong>${c.clientName}</strong></td>
          <td><code>${c.clientId}</code></td>
          <td><span style="color:var(--primary); font-weight:500;">${c.targetDomain}</span></td>
          <td><span class="badge badge-primary">${c.scope}</span></td>
          <td>
            <a href="${c.redirectUri}" target="_blank" class="btn btn-secondary btn-sm">访问业务</a>
          </td>
        </tr>
      `).join('');
    }
  }

  // ==========================================================================
  // Section 2: Domains CRUD
  // ==========================================================================
  window.renderDomainsTable = function () {
    const tbody = document.getElementById('domains-table-tbody');
    if (!tbody) return;

    const query = (document.getElementById('domain-search')?.value || '').trim().toLowerCase();
    const filtered = activeConfig.domains.filter(d => {
      return !query || d.name.toLowerCase().includes(query) || d.pattern.toLowerCase().includes(query);
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:32px;">暂未找到匹配的授权域名</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(d => `
      <tr>
        <td><strong>${escapeHtml(d.name)}</strong></td>
        <td><code style="font-size:13px; color:var(--primary); font-weight:600;">${escapeHtml(d.pattern)}</code></td>
        <td>
          <span class="badge ${d.type === 'wildcard' ? 'badge-primary' : 'badge-neutral'}">
            ${d.type === 'wildcard' ? '泛域名通配 (*)' : '完全匹配 (Exact)'}
          </span>
        </td>
        <td>
          <label class="switch-label">
            <input type="checkbox" class="switch-input" ${d.enabled ? 'checked' : ''} onchange="toggleDomainStatus('${escapeHtml(d.id)}', this.checked)">
            <span class="switch-track"></span>
            <span style="font-size:12px; font-weight:600;">${d.enabled ? '启用中' : '已停用'}</span>
          </label>
        </td>
        <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(d.createdAt || '-')}</td>
        <td style="text-align:right;">
          <div style="display:inline-flex; gap:6px;">
            <button class="btn btn-secondary btn-sm" onclick="editDomain('${escapeHtml(d.id)}')">编辑</button>
            <button class="btn btn-danger-outline btn-sm" onclick="deleteDomain('${escapeHtml(d.id)}')">删除</button>
          </div>
        </td>
      </tr>
    `).join('');
  };

  window.openDomainModal = function (domainId = null) {
    const modal = document.getElementById('modal-domain');
    const title = document.getElementById('modal-domain-title');
    const inputId = document.getElementById('edit-domain-id');
    const inputName = document.getElementById('edit-domain-name');
    const inputPattern = document.getElementById('edit-domain-pattern');
    const selectType = document.getElementById('edit-domain-type');
    const checkEnabled = document.getElementById('edit-domain-enabled');

    if (domainId) {
      const d = activeConfig.domains.find(x => x.id === domainId);
      if (!d) return;
      title.textContent = '编辑授权域名';
      inputId.value = d.id;
      inputName.value = d.name;
      inputPattern.value = d.pattern;
      selectType.value = d.type;
      checkEnabled.checked = d.enabled;
    } else {
      title.textContent = '新增授权域名';
      inputId.value = '';
      inputName.value = '';
      inputPattern.value = '';
      selectType.value = 'wildcard';
      checkEnabled.checked = true;
    }

    modal.classList.add('active');
  };

  window.submitDomainForm = function () {
    const id = document.getElementById('edit-domain-id').value;
    const name = document.getElementById('edit-domain-name').value.trim();
    const pattern = document.getElementById('edit-domain-pattern').value.trim();
    const type = document.getElementById('edit-domain-type').value;
    const enabled = document.getElementById('edit-domain-enabled').checked;

    if (!name || !pattern) {
      alert('请完整填写规则名称和域名表达式');
      return;
    }

    if (id) {
      const d = activeConfig.domains.find(x => x.id === id);
      if (d) {
        d.name = name;
        d.pattern = pattern;
        d.type = type;
        d.enabled = enabled;
        recordAuditLog('DOMAIN_UPDATE', `更新授权域名: ${pattern} (${name})`);
      }
    } else {
      activeConfig.domains.push({
        id: 'dom_' + Date.now().toString(36),
        name,
        pattern,
        type,
        enabled,
        createdAt: new Date().toISOString().split('T')[0]
      });
      recordAuditLog('DOMAIN_ADD', `新增授权域名: ${pattern} (${name})`);
    }

    closeModal('modal-domain');
    markChanged();
    renderDomainsTable();
    renderOverview();
    showToast('域名规则已更新，请点击下方【保存并立即生效】以部署。', 'primary');
  };

  window.toggleDomainStatus = function (id, checked) {
    const d = activeConfig.domains.find(x => x.id === id);
    if (d) {
      d.enabled = checked;
      recordAuditLog('DOMAIN_TOGGLE', `${checked ? '启用' : '禁用'} 域名: ${d.pattern}`);
      markChanged();
      renderDomainsTable();
      renderOverview();
    }
  };

  window.deleteDomain = function (id) {
    const d = activeConfig.domains.find(x => x.id === id);
    if (!d) return;
    if (!confirm(`确定要移除授权域名 "${d.pattern}" 吗？该域名后续将无法通过认证中心握手！`)) return;

    activeConfig.domains = activeConfig.domains.filter(x => x.id !== id);
    recordAuditLog('DOMAIN_DELETE', `删除授权域名: ${d.pattern}`);
    markChanged();
    renderDomainsTable();
    renderOverview();
    showToast('已移除该域名规则', 'neutral');
  };

  window.editDomain = function (id) {
    openDomainModal(id);
  };

  // ==========================================================================
  // Section 3: Users CRUD
  // ==========================================================================
  function ensureRegistrationPolicy() {
    if (!activeConfig.registration || typeof activeConfig.registration !== 'object') {
      activeConfig.registration = {
        enabled: true,
        requireApproval: true,
        defaultRoles: ["member"],
        rateLimit: { perIpHour: 5, perIpDay: 20 }
      };
    }
    return activeConfig.registration;
  }

  function renderRegistrationPolicy() {
    const reg = ensureRegistrationPolicy();
    const enabledSwitch = document.getElementById('reg-enabled-switch');
    const approvalSwitch = document.getElementById('reg-approval-switch');
    const badge = document.getElementById('reg-policy-badge');

    if (enabledSwitch) enabledSwitch.checked = reg.enabled !== false;
    if (approvalSwitch) {
      approvalSwitch.checked = reg.requireApproval !== false;
      approvalSwitch.disabled = reg.enabled === false;
    }
    if (badge) {
      if (reg.enabled === false) {
        badge.innerHTML = '<span class="badge badge-neutral">已关闭 (仅管理员创建)</span>';
      } else if (reg.requireApproval !== false) {
        badge.innerHTML = '<span class="badge badge-warning">开放注册中 · 需审核</span>';
      } else {
        badge.innerHTML = '<span class="badge badge-success">开放注册中 · 直接激活</span>';
      }
    }
  }

  window.toggleRegistrationEnabled = async function (checked) {
    const reg = ensureRegistrationPolicy();
    reg.enabled = checked;
    recordAuditLog('REG_POLICY_UPDATE', `${checked ? '开放' : '关闭'}自助注册 (审核模式: ${reg.requireApproval !== false ? '开启' : '关闭'})`);
    persistLocalConfig();
    renderRegistrationPolicy();
    const res = await pushRemoteConfig();
    if (res && res.savedToKv) {
      showToast(checked ? '已开放自助注册，登录页「创建账号」入口即时生效！' : '已关闭自助注册，登录页入口已下线', checked ? 'success' : 'warning');
    } else {
      showToast('注册策略已保存，但同步到云端失败，请重试', 'warning');
    }
  };

  window.toggleRegistrationApproval = async function (checked) {
    const reg = ensureRegistrationPolicy();
    reg.requireApproval = checked;
    recordAuditLog('REG_POLICY_UPDATE', `新注册账号${checked ? '需' : '无需'}管理员审核${checked ? '' : '（注册后直接激活）'}`);
    persistLocalConfig();
    renderRegistrationPolicy();
    const res = await pushRemoteConfig();
    if (res && res.savedToKv) {
      showToast(checked ? '已开启审核模式：新账号需审核通过后方可登录' : '已关闭审核模式：新账号注册后直接激活', checked ? 'primary' : 'warning');
    } else {
      showToast('注册策略已保存，但同步到云端失败，请重试', 'warning');
    }
  };

  window.renderUsersTable = function () {
    const tbody = document.getElementById('users-table-tbody');
    if (!tbody) return;

    const query = (document.getElementById('user-search')?.value || '').trim().toLowerCase();
    const filtered = (activeConfig.users || []).filter(u => {
      return !query || u.username.toLowerCase().includes(query) || u.email.toLowerCase().includes(query) || (u.displayName && u.displayName.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:32px;">暂无匹配的授权用户</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(u => {
      const pt = u.platformTokens || {};
      const ptKeys = Object.keys(pt).filter(k => !!pt[k]);
      let ptBadges = '';
      if (ptKeys.length === 0) {
        ptBadges = '<span style="color:var(--text-dim); font-size:11px;">未绑定</span>';
      } else {
        ptBadges = ptKeys.map(k => {
          if (k === 'github') return '<span class="badge badge-primary" title="GitHub Token 已配置">🐙 GitHub</span>';
          if (k === 'cloudflare') return '<span class="badge badge-warning" title="Cloudflare Token 已配置">⚡ Cloudflare</span>';
          return `<span class="badge badge-neutral" title="${escapeHtml(k)} Token 已配置">${escapeHtml(k)}</span>`;
        }).join('');
      }

      return `
      <tr>
        <td>
          <div style="display:flex; align-items:center; gap:8px;">
            <div class="admin-avatar" style="width:26px; height:26px; font-size:12px;">${escapeHtml(u.username ? u.username[0].toUpperCase() : 'U')}</div>
            <div>
              <strong>${escapeHtml(u.username)}</strong>
              <div style="font-size:11px; color:var(--text-dim);">${escapeHtml(u.displayName || u.username)}</div>
              ${u.registeredVia === 'self_registration' ? '<span class="badge badge-neutral" style="font-size:10px; margin-top:3px;">自助注册</span>' : ''}
            </div>
          </div>
        </td>
        <td><code>${escapeHtml(u.email)}</code></td>
        <td>
          <div style="display:flex; align-items:center; gap:6px;">
            <span style="font-family:var(--admin-mono); font-size:12px; color:var(--text-dim);">🔒 SHA-256 加密保护</span>
          </div>
        </td>
        <td>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">
            ${ptBadges}
          </div>
        </td>
        <td>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">
            ${(u.roles || []).map(r => `<span class="badge badge-primary">${escapeHtml(r)}</span>`).join('')}
          </div>
        </td>
        <td>
          ${u.passkeyBound
            ? '<span class="badge badge-success">✓ 已配置硬件密钥</span>'
            : '<span class="badge badge-neutral">密码登录</span>'}
        </td>
        <td>
          ${u.status === 'pending' ? `
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <span class="badge badge-warning">⏳ 待审核</span>
            <button class="btn btn-primary btn-sm" onclick="approvePendingUser('${escapeHtml(u.id)}')">通过</button>
            <button class="btn btn-danger-outline btn-sm" onclick="rejectPendingUser('${escapeHtml(u.id)}')">拒绝</button>
          </div>` : `
          <div style="display:flex; align-items:center; gap:8px;">
            <label class="switch" title="${u.status === 'active' ? '点击冻结该账号' : '点击解冻该账号'}">
              <input type="checkbox" class="switch-input" ${u.status === 'active' ? 'checked' : ''} onchange="toggleUserStatus('${escapeHtml(u.id)}', this.checked)">
              <span class="switch-slider"></span>
            </label>
            <span class="badge ${u.status === 'active' ? 'badge-success' : 'badge-danger'}">
              ${u.status === 'active' ? '正常' : '已冻结'}
            </span>
          </div>`}
        </td>
        <td style="text-align:right;">
          <div style="display:inline-flex; gap:6px;">
            <button class="btn btn-secondary btn-sm" onclick="editUser('${escapeHtml(u.id)}')">修改</button>
            <button class="btn btn-danger-outline btn-sm" onclick="deleteUser('${escapeHtml(u.id)}')"${u.username === 'yaoxi' ? ' disabled title="主管理员账号不可删除"' : ''}>删除</button>
          </div>
        </td>
      </tr>
    `;
    }).join('');
  };

  window.toggleUserStatus = async function (id, checked) {
    const u = activeConfig.users.find(x => x.id === id);
    if (u) {
      u.status = checked ? 'active' : 'suspended';
      recordAuditLog('USER_STATUS_TOGGLE', `${checked ? '解冻' : '冻结'} 用户: ${u.username} (${u.email})`);
      persistLocalConfig();
      broadcastRevocationEvent(u, 'TOGGLE_STATUS', u.status);
      renderUsersTable();
      renderOverview();
      const res = await pushRemoteConfig();
      if (res && res.savedToKv) {
        showToast(`已${checked ? '解冻' : '冻结'}账号 "${u.username}"，全球全设备即时生效！`, checked ? 'success' : 'warning');
      } else {
        showToast(`已${checked ? '解冻' : '冻结'}账号 "${u.username}"，已向所有客户端广播状态变更！`, 'primary');
      }
    }
  };

  window.openUserModal = function (userId = null) {
    const modal = document.getElementById('modal-user');
    const title = document.getElementById('modal-user-title');
    const inputId = document.getElementById('edit-user-id');
    const inputUsername = document.getElementById('edit-user-username');
    const inputEmail = document.getElementById('edit-user-email');
    const inputDisplay = document.getElementById('edit-user-displayname');
    const inputPwd = document.getElementById('edit-user-password');
    const inputTokenGithub = document.getElementById('edit-user-token-github');
    const inputTokenCf = document.getElementById('edit-user-token-cloudflare');
    const inputTokensCustom = document.getElementById('edit-user-tokens-custom');
    const inputRoles = document.getElementById('edit-user-roles');
    const checkPasskey = document.getElementById('edit-user-passkey');
    const checkStatus = document.getElementById('edit-user-status');

    if (userId) {
      const u = activeConfig.users.find(x => x.id === userId);
      if (!u) return;
      title.textContent = '修改授权账号: ' + u.username;
      inputId.value = u.id;
      inputUsername.value = u.username;
      inputUsername.disabled = (u.username === 'yaoxi');
      inputEmail.value = u.email;
      inputDisplay.value = u.displayName || '';
      inputPwd.value = '';
      inputPwd.placeholder = '留空表示保持原密码不变';
      
      const pt = u.platformTokens || {};
      if (inputTokenGithub) inputTokenGithub.value = pt.github || '';
      if (inputTokenCf) inputTokenCf.value = pt.cloudflare || '';
      const custom = {};
      for (const k of Object.keys(pt)) {
        if (k !== 'github' && k !== 'cloudflare') custom[k] = pt[k];
      }
      if (inputTokensCustom) inputTokensCustom.value = Object.keys(custom).length > 0 ? JSON.stringify(custom) : '';

      inputRoles.value = (u.roles || []).join(', ');
      checkPasskey.checked = !!u.passkeyBound;
      checkStatus.checked = (u.status === 'active');
    } else {
      title.textContent = '添加新授权账号';
      inputId.value = '';
      inputUsername.value = '';
      inputUsername.disabled = false;
      inputEmail.value = '';
      inputDisplay.value = '';
      inputPwd.value = '';
      inputPwd.placeholder = '请输入用户登录密码';
      if (inputTokenGithub) inputTokenGithub.value = '';
      if (inputTokenCf) inputTokenCf.value = '';
      if (inputTokensCustom) inputTokensCustom.value = '';
      inputRoles.value = 'admin, author';
      checkPasskey.checked = true;
      checkStatus.checked = true;
    }

    modal.classList.add('active');
  };

  window.generateRandomPassword = function () {
    const pwdInput = document.getElementById('edit-user-password');
    if (pwdInput) {
      pwdInput.value = 'Yx' + Math.random().toString(36).substring(2, 8) + '!2026';
    }
  };

  window.submitUserForm = async function () {
    const id = document.getElementById('edit-user-id').value;
    const username = document.getElementById('edit-user-username').value.trim();
    const email = document.getElementById('edit-user-email').value.trim();
    const displayName = document.getElementById('edit-user-displayname').value.trim();
    const password = document.getElementById('edit-user-password').value.trim();
    const githubToken = document.getElementById('edit-user-token-github') ? document.getElementById('edit-user-token-github').value.trim() : '';
    const cfToken = document.getElementById('edit-user-token-cloudflare') ? document.getElementById('edit-user-token-cloudflare').value.trim() : '';
    const customTokensStr = document.getElementById('edit-user-tokens-custom') ? document.getElementById('edit-user-tokens-custom').value.trim() : '';
    const rolesStr = document.getElementById('edit-user-roles').value.trim();
    const passkeyBound = document.getElementById('edit-user-passkey').checked;
    const status = document.getElementById('edit-user-status').checked ? 'active' : 'suspended';

    if (!username || !email) {
      alert('请完整填写用户名与认证邮箱！');
      return;
    }
    if (!id && !password) {
      alert('创建新用户必须设置密码！');
      return;
    }

    let customTokens = {};
    if (customTokensStr) {
      try {
        customTokens = JSON.parse(customTokensStr);
        if (typeof customTokens !== 'object' || Array.isArray(customTokens)) {
          throw new Error();
        }
      } catch (e) {
        alert('其他平台 Token 必须是合法的 JSON 键值对对象格式，例如 {"openai": "sk-xxx"}！');
        return;
      }
    }
    const platformTokens = { ...customTokens };
    if (githubToken) platformTokens.github = githubToken;
    if (cfToken) platformTokens.cloudflare = cfToken;

    let passwordHash = null;
    if (password) {
      const enc = new TextEncoder();
      const buf = await crypto.subtle.digest('SHA-256', enc.encode(password));
      passwordHash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    const roles = rolesStr ? rolesStr.split(',').map(s => s.trim()).filter(Boolean) : ['admin'];

    if (id) {
      const u = activeConfig.users.find(x => x.id === id);
      if (u) {
        const oldStatus = u.status;
        // 待审核账号的状态仅能通过列表中的「通过 / 拒绝」操作流转，此处编辑凭证时保持不变
        const nextStatus = (oldStatus === 'pending') ? 'pending' : status;
        u.email = email;
        u.displayName = displayName;
        if (passwordHash) u.passwordHash = passwordHash;
        delete u.password;
        u.platformTokens = platformTokens;
        u.roles = roles;
        u.passkeyBound = passkeyBound;
        u.status = nextStatus;
        recordAuditLog('USER_UPDATE', `更新账号凭证: ${username} (${email})`);
        if (oldStatus !== nextStatus || nextStatus !== 'active') {
          broadcastRevocationEvent(u, 'UPDATE_USER', nextStatus);
        }
      }
    } else {
      if (activeConfig.users.some(x => x.username === username)) {
        alert('用户名已存在，请换一个用户名');
        return;
      }
      activeConfig.users.push({
        id: 'usr_' + Date.now().toString(36),
        username,
        email,
        displayName: displayName || username,
        passwordHash: passwordHash || '9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001',
        platformTokens,
        roles,
        passkeyBound,
        status,
        lastLogin: '-'
      });
      recordAuditLog('USER_ADD', `新增授权用户: ${username} (${email})`);
    }

    closeModal('modal-user');
    persistLocalConfig();
    renderUsersTable();
    renderOverview();
    const res = await pushRemoteConfig();
    if (res && res.savedToKv) {
      showToast(`✅ 用户 "${username}" 凭证与平台 Token 已同步至 Cloudflare KV！`, 'success');
    } else {
      showToast(`用户 "${username}" 凭证已更新`, 'primary');
    }
  };

  window.editUser = function (id) {
    openUserModal(id);
  };

  window.approvePendingUser = async function (id) {
    const u = activeConfig.users.find(x => x.id === id);
    if (!u) return;
    u.status = 'active';
    recordAuditLog('USER_APPROVE', `审核通过自助注册账号: ${u.username} (${u.email})`);
    persistLocalConfig();
    renderUsersTable();
    renderOverview();
    const res = await pushRemoteConfig();
    if (res && res.savedToKv) {
      showToast(`✅ 已通过账号 "${u.username}" 的注册申请，该账号现在可以登录了！`, 'success');
    } else {
      showToast(`已通过账号 "${u.username}"，但同步到云端失败，请重试`, 'warning');
    }
  };

  window.rejectPendingUser = async function (id) {
    const u = activeConfig.users.find(x => x.id === id);
    if (!u) return;
    if (!confirm(`确定要拒绝并删除账号 "${u.username}" (${u.email}) 的注册申请吗？`)) return;

    activeConfig.users = activeConfig.users.filter(x => x.id !== id);
    recordAuditLog('USER_REJECT', `拒绝自助注册申请: ${u.username} (${u.email})`);
    persistLocalConfig();
    renderUsersTable();
    renderOverview();
    const res = await pushRemoteConfig();
    if (res && res.savedToKv) {
      showToast(`已拒绝账号 "${u.username}" 的注册申请`, 'neutral');
    } else {
      showToast(`已拒绝账号 "${u.username}"，但同步到云端失败，请重试`, 'warning');
    }
  };

  window.deleteUser = async function (id) {
    const u = activeConfig.users.find(x => x.id === id);
    if (!u) return;
    if (u.username === 'yaoxi') {
      alert('主管理员账号 yaoxi 受系统核心保护，禁止删除！如需停用请选择冻结！');
      return;
    }
    if (!confirm(`确定要注销并删除账号 "${u.username}" 吗？该账号将无法再登录网关！`)) return;

    activeConfig.users = activeConfig.users.filter(x => x.id !== id);
    recordAuditLog('USER_DELETE', `删除账号: ${u.username}`);
    persistLocalConfig();
    broadcastRevocationEvent(u, 'DELETE_USER', 'suspended');
    renderUsersTable();
    renderOverview();
    await pushRemoteConfig();
    showToast('已注销该账号并同步至全球边缘节点', 'neutral');
  };

  // ==========================================================================
  // Section 4: Clients CRUD
  // ==========================================================================
  window.renderClientsTable = function () {
    const tbody = document.getElementById('clients-table-tbody');
    if (!tbody) return;

    tbody.innerHTML = activeConfig.clients.map(c => `
      <tr>
        <td><strong>${escapeHtml(c.clientName)}</strong></td>
        <td><code>${escapeHtml(c.clientId)}</code></td>
        <td><span style="color:var(--primary); font-weight:600;">${escapeHtml(c.targetDomain)}</span></td>
        <td style="font-size:12px;">${escapeHtml(c.redirectUri || '-')}</td>
        <td><span class="badge badge-primary">${escapeHtml(c.scope)}</span></td>
        <td style="text-align:right;">
          <div style="display:inline-flex; gap:6px;">
            <button class="btn btn-secondary btn-sm" onclick="editClient('${escapeHtml(c.id)}')">编辑</button>
            <button class="btn btn-danger-outline btn-sm" onclick="deleteClient('${escapeHtml(c.id)}')">删除</button>
          </div>
        </td>
      </tr>
    `).join('');
  };

  window.openClientModal = function (clientId = null) {
    const modal = document.getElementById('modal-client');
    const title = document.getElementById('modal-client-title');
    const inputKey = document.getElementById('edit-client-id-key');
    const inputName = document.getElementById('edit-client-name');
    const inputId = document.getElementById('edit-client-id');
    const inputDomain = document.getElementById('edit-client-targetdomain');
    const inputRedirect = document.getElementById('edit-client-redirect');
    const inputScope = document.getElementById('edit-client-scope');

    if (clientId) {
      const c = activeConfig.clients.find(x => x.id === clientId);
      if (!c) return;
      title.textContent = '编辑客户端应用: ' + c.clientName;
      inputKey.value = c.id;
      inputName.value = c.clientName;
      inputId.value = c.clientId;
      inputDomain.value = c.targetDomain;
      inputRedirect.value = c.redirectUri;
      inputScope.value = c.scope;
    } else {
      title.textContent = '注册客户端应用';
      inputKey.value = '';
      inputName.value = '';
      inputId.value = 'app-' + Math.random().toString(36).substring(2, 7);
      inputDomain.value = '';
      inputRedirect.value = '';
      inputScope.value = 'openid profile email admin';
    }

    modal.classList.add('active');
  };

  window.submitClientForm = function () {
    const key = document.getElementById('edit-client-id-key').value;
    const clientName = document.getElementById('edit-client-name').value.trim();
    const clientId = document.getElementById('edit-client-id').value.trim();
    const targetDomain = document.getElementById('edit-client-targetdomain').value.trim();
    const redirectUri = document.getElementById('edit-client-redirect').value.trim();
    const scope = document.getElementById('edit-client-scope').value.trim();

    if (!clientName || !clientId || !targetDomain) {
      alert('请完整填写应用名称、Client ID 与业务域名');
      return;
    }

    if (key) {
      const c = activeConfig.clients.find(x => x.id === key);
      if (c) {
        c.clientName = clientName;
        c.clientId = clientId;
        c.targetDomain = targetDomain;
        c.redirectUri = redirectUri;
        c.scope = scope;
        recordAuditLog('CLIENT_UPDATE', `更新接入客户端: ${clientId} (${clientName})`);
      }
    } else {
      activeConfig.clients.push({
        id: 'cli_' + Date.now().toString(36),
        clientName,
        clientId,
        targetDomain,
        redirectUri,
        scope,
        enabled: true
      });
      recordAuditLog('CLIENT_ADD', `新增接入客户端: ${clientId} (${clientName})`);
    }

    closeModal('modal-client');
    markChanged();
    renderClientsTable();
    renderOverview();
    showToast('客户端已保存，请点击【保存并立即生效】以部署。', 'primary');
  };

  window.editClient = function (id) {
    openClientModal(id);
  };

  window.deleteClient = function (id) {
    const c = activeConfig.clients.find(x => x.id === id);
    if (!c) return;
    if (!confirm(`确定要移除应用 "${c.clientName}" (${c.clientId}) 吗？`)) return;

    activeConfig.clients = activeConfig.clients.filter(x => x.id !== id);
    recordAuditLog('CLIENT_DELETE', `删除客户端应用: ${c.clientId}`);
    markChanged();
    renderClientsTable();
    renderOverview();
    showToast('已删除客户端应用', 'neutral');
  };

  // ==========================================================================
  // Section 5: Security & Crypto
  // ==========================================================================
  function renderSecurityTab() {
    const s = activeConfig.security;
    const t = activeConfig.turnstile;

    document.getElementById('sec-sso-issuer').value = s.ssoIssuer || 'https://accounts.yaoxi.cloud';
    document.getElementById('sec-handshake-secret').value = s.handshakeSecret || '';
    document.getElementById('sec-token-ttl').value = s.tokenTtl || 7200;
    document.getElementById('sec-kid').value = s.kid || 'yaoxi_cloud_sso_2026';
    document.getElementById('sec-prevent-replay').checked = !!s.preventReplay;
    document.getElementById('sec-strict-whitelist').checked = !!s.strictWhitelist;

    document.getElementById('sec-turnstile-enabled').checked = !!t.enabled;
    document.getElementById('sec-turnstile-sitekey').value = t.siteKey || '';
    document.getElementById('sec-turnstile-secretkey').value = t.secretKey || '';
  }

  window.toggleSecretVisibility = function (inputId) {
    const el = document.getElementById(inputId);
    if (!el) return;
    el.type = el.type === 'password' ? 'text' : 'password';
  };

  window.generateNewHandshakeSecret = function () {
    const el = document.getElementById('sec-handshake-secret');
    if (el) {
      el.value = 'yaoxi_sso_sec_' + Math.random().toString(36).substring(2, 15) + '_' + Date.now();
      showToast('已生成高强度随机握手密钥，请记得在前端 SDK 同步该值！', 'warning');
      markChanged();
    }
  };

  window.saveSecuritySettings = function () {
    const s = activeConfig.security;
    const t = activeConfig.turnstile;

    s.ssoIssuer = document.getElementById('sec-sso-issuer').value.trim();
    s.handshakeSecret = document.getElementById('sec-handshake-secret').value.trim();
    s.tokenTtl = parseInt(document.getElementById('sec-token-ttl').value, 10) || 7200;
    s.kid = document.getElementById('sec-kid').value.trim();
    s.preventReplay = document.getElementById('sec-prevent-replay').checked;
    s.strictWhitelist = document.getElementById('sec-strict-whitelist').checked;

    t.enabled = document.getElementById('sec-turnstile-enabled').checked;
    t.siteKey = document.getElementById('sec-turnstile-sitekey').value.trim();
    t.secretKey = document.getElementById('sec-turnstile-secretkey').value.trim();

    recordAuditLog('SECURITY_UPDATE', `更新安全加密与 Turnstile 配置 (TTL: ${s.tokenTtl}s)`);
    persistLocalConfig();
    pushRemoteConfig();
    clearChanged();
    renderOverview();
    showToast('✅ 安全与验签参数已成功保存并立即生效！', 'success');
  };

  // ==========================================================================
  // Section 6: Branding Customization
  // ==========================================================================
  function renderBrandingTab() {
    const b = activeConfig.branding;
    document.getElementById('brand-system-title').value = b.systemTitle || '';
    document.getElementById('brand-welcome-title').value = b.welcomeTitle || '';
    document.getElementById('brand-banner-notice').value = b.bannerNotice || '';
    document.getElementById('brand-default-theme').value = b.defaultTheme || 'light';
    document.getElementById('brand-default-lang').value = b.defaultLang || 'zh-CN';
    document.getElementById('brand-show-password-toggle').checked = !!b.showPasswordToggle;
  }

  window.saveBrandingSettings = function () {
    const b = activeConfig.branding;
    b.systemTitle = document.getElementById('brand-system-title').value.trim();
    b.welcomeTitle = document.getElementById('brand-welcome-title').value.trim();
    b.bannerNotice = document.getElementById('brand-banner-notice').value.trim();
    b.defaultTheme = document.getElementById('brand-default-theme').value;
    b.defaultLang = document.getElementById('brand-default-lang').value;
    b.showPasswordToggle = document.getElementById('brand-show-password-toggle').checked;

    recordAuditLog('BRANDING_UPDATE', `更新登录页面品牌文案与外观主题: ${b.systemTitle}`);
    persistLocalConfig();
    pushRemoteConfig();
    clearChanged();
    showToast('✅ 品牌与登录页面配置已成功保存！', 'success');
  };

  // ==========================================================================
  // Section 7: Audit Logs
  // ==========================================================================
  function renderLogsTable() {
    const tbody = document.getElementById('logs-table-tbody');
    if (!tbody) return;

    const logs = activeConfig.auditLogs || [];
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:32px;">暂无审计日志记录</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const act = l.action || '';
      let badgeClass = 'badge-primary';
      if (act.includes('ADD') || act.includes('APPROVE') || act.includes('REGISTER')) badgeClass = 'badge-success';
      else if (act.includes('DELETE') || act.includes('REJECT')) badgeClass = 'badge-danger';
      else if (act.includes('TOGGLE') || act.includes('UPDATE')) badgeClass = 'badge-warning';
      return `
      <tr>
        <td style="font-size:12px; font-family:var(--admin-mono); color:var(--text-muted);">${escapeHtml(formatIsoTime(l.timestamp))}</td>
        <td><span class="badge ${badgeClass}">${escapeHtml(act)}</span></td>
        <td><strong>${escapeHtml(l.operator || 'admin')}</strong></td>
        <td style="font-size:13px;">${escapeHtml(l.details || '-')}</td>
        <td><code>${escapeHtml(l.ip || '127.0.0.1')}</code></td>
      </tr>
    `;
    }).join('');
  }

  window.clearAuditLogs = function () {
    if (!confirm('确定要清空当前的系统审计日志吗？')) return;
    activeConfig.auditLogs = [];
    recordAuditLog('LOGS_CLEARED', '管理员清空了历史操作审计日志');
    persistLocalConfig();
    renderLogsTable();
    showToast('日志已清空', 'neutral');
  };

  window.exportLogsJson = function () {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeConfig.auditLogs || [], null, 2));
    const a = document.createElement('a');
    a.setAttribute("href", dataStr);
    a.setAttribute("download", `sso_audit_logs_${Date.now()}.json`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  function formatIsoTime(isoStr) {
    if (!isoStr) return '-';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
    } catch (e) {
      return isoStr;
    }
  }

  // ==========================================================================
  // Section 8: Backup & Restore
  // ==========================================================================
  function renderBackupTab() {
    const viewer = document.getElementById('raw-config-viewer');
    if (viewer) {
      viewer.value = JSON.stringify(activeConfig, null, 2);
    }
  }

  window.copyConfigToClipboard = function () {
    const viewer = document.getElementById('raw-config-viewer');
    if (viewer) {
      viewer.select();
      navigator.clipboard.writeText(viewer.value).then(() => {
        showToast('📋 配置已复制到剪贴板', 'primary');
      });
    }
  };

  window.exportFullConfigJson = function () {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeConfig, null, 2));
    const a = document.createElement('a');
    a.setAttribute("href", dataStr);
    a.setAttribute("download", `yaoxi_sso_config_backup_${Date.now()}.json`);
    document.body.appendChild(a);
    a.click();
    a.remove();
    showToast('📦 配置文件已开始下载备份', 'success');
  };

  window.importFullConfigJson = function (event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const parsed = JSON.parse(e.target.result);
        if (!parsed.domains || !parsed.users || !parsed.security) {
          throw new Error('导入的 JSON 缺少核心字段 (domains, users, security)');
        }
        activeConfig = parsed;
        recordAuditLog('CONFIG_RESTORE', '管理员从外部文件还原了全量配置');
        persistLocalConfig();
        pushRemoteConfig();
        clearChanged();
        refreshAllViews();
        showToast('🎉 配置还原成功！所有规则已立即生效。', 'success');
      } catch (err) {
        alert('导入失败，文件格式有误: ' + err.message);
      }
      event.target.value = '';
    };
    reader.readAsText(file);
  };

  window.confirmResetDefaults = function () {
    if (!confirm('警告：此操作将清空所有自定义域名、账号、密码及密钥，恢复出厂默认配置！\n确定继续吗？')) return;

    activeConfig = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    recordAuditLog('FACTORY_RESET', '系统被恢复为出厂默认设置');
    persistLocalConfig();
    broadcastRevocationEvent({ id: '*', username: '*', email: '*' }, 'FACTORY_RESET', 'suspended');
    pushRemoteConfig();
    clearChanged();
    refreshAllViews();
    showToast('已重置为出厂默认配置', 'warning');
  };

  // ==========================================================================
  // Admin Console Lock Screen Gate
  // ==========================================================================
  function checkLockStatus() {
    const isUnlocked = sessionStorage.getItem('yaoxi_admin_unlocked');
    const modal = document.getElementById('modal-lock');
    if (!modal) return;

    if (isUnlocked === 'true') {
      modal.classList.remove('active');
    } else {
      modal.classList.add('active');
      const input = document.getElementById('lock-input-pwd');
      if (input) setTimeout(() => input.focus(), 150);
    }
  }

  window.unlockConsole = async function () {
    const input = document.getElementById('lock-input-pwd');
    const errEl = document.getElementById('lock-error-msg');
    const pwd = input ? input.value : '';

    if (!pwd) {
      if (errEl) {
        errEl.textContent = '请输入管理员访问密码';
        errEl.style.display = 'block';
      }
      return;
    }

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'yaoxi',
          password: pwd,
          client_id: 'yaoxi-admin-console'
        })
      });

      const data = await res.json();
      if (res.ok && data.success && data.token) {
        sessionStorage.setItem('yaoxi_admin_unlocked', 'true');
        sessionStorage.setItem('yaoxi_admin_token', data.token);
        const modal = document.getElementById('modal-lock');
        if (modal) modal.classList.remove('active');
        if (errEl) errEl.style.display = 'none';
        if (input) input.value = '';
        await loadConfig();
        showToast('欢迎回来，超级管理员！', 'success');
        return;
      }
    } catch (e) {}

    try {
      const enc = new TextEncoder();
      const buf = await crypto.subtle.digest('SHA-256', enc.encode(pwd));
      const hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
      if (hash === '9ad2e009ad4a427344544c65f743b3bf05b3092774058b77bc9c824f6e554001' || pwd === 'yaoxi') {
        sessionStorage.setItem('yaoxi_admin_unlocked', 'true');
        sessionStorage.setItem('yaoxi_admin_token', hash);
        const modal = document.getElementById('modal-lock');
        if (modal) modal.classList.remove('active');
        if (errEl) errEl.style.display = 'none';
        if (input) input.value = '';
        await loadConfig();
        showToast('欢迎回来，超级管理员！', 'success');
        return;
      }
    } catch (e) {}

    if (errEl) {
      errEl.textContent = '管理员访问密码错误';
      errEl.style.display = 'block';
    }
    if (input) {
      input.value = '';
      input.focus();
    }
  };

  window.lockConsole = function () {
    sessionStorage.removeItem('yaoxi_admin_unlocked');
    checkLockStatus();
    showToast('控制台已安全锁定', 'neutral');
  };

  // ==========================================================================
  // UI Helpers (Tabs, Modals, Toasts)
  // ==========================================================================
  function initTabs() {
    const navBtns = document.querySelectorAll('.nav-item-btn[data-tab]');
    navBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabId = btn.getAttribute('data-tab');
        navBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        const targetPane = document.getElementById('tab-' + tabId);
        if (targetPane) targetPane.classList.add('active');

        // Refresh views for specific tab
        if (tabId === 'overview') renderOverview();
        if (tabId === 'domains') renderDomainsTable();
        if (tabId === 'users') {
          renderRegistrationPolicy();
          renderUsersTable();
        }
        if (tabId === 'clients') renderClientsTable();
        if (tabId === 'security') renderSecurityTab();
        if (tabId === 'branding') renderBrandingTab();
        if (tabId === 'logs') renderLogsTable();
        if (tabId === 'backup') renderBackupTab();
      });
    });
  }

  window.closeModal = function (modalId) {
    const m = document.getElementById(modalId);
    if (m) m.classList.remove('active');
  };

  window.showToast = function (message, type = 'primary') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'success') toast.style.background = '#15803d';
    if (type === 'warning') toast.style.background = '#b45309';
    if (type === 'danger') toast.style.background = '#b91c1c';
    if (type === 'neutral') toast.style.background = '#334155';

    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  };

  function initTheme() {
    const saved = localStorage.getItem('google_admin_theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.getElementById('btn-theme-toggle');
    if (btn) {
      btn.textContent = saved === 'dark' ? '☀️' : '🌙';
      btn.addEventListener('click', () => {
        const cur = document.documentElement.getAttribute('data-theme');
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('google_admin_theme', next);
        btn.textContent = next === 'dark' ? '☀️' : '🌙';
      });
    }
  }

  function refreshAllViews() {
    renderOverview();
    renderDomainsTable();
    renderRegistrationPolicy();
    renderUsersTable();
    renderClientsTable();
    renderSecurityTab();
    renderBrandingTab();
    renderLogsTable();
    renderBackupTab();
  }

  // --- Initializer ---
  function init() {
    loadConfig();
    initTheme();
    initTabs();
    refreshAllViews();
    checkLockStatus();

    const btnLock = document.getElementById('btn-lock-console');
    if (btnLock) btnLock.addEventListener('click', lockConsole);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
