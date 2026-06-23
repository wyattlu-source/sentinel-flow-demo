/* ── Config ──────────────────────────────────────────────────────────────── */
const API = 'http://localhost:8000';

/* ── State ───────────────────────────────────────────────────────────────── */
let token       = localStorage.getItem('sf_token') || null;
let currentUser = JSON.parse(localStorage.getItem('sf_user') || 'null');
let tempToken   = null;
let tempUsername = null;

/* ── API helper ──────────────────────────────────────────────────────────── */
async function apiFetch(path, method = 'GET', body = null, expectBlob = false) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  let res;
  try {
    res = await fetch(`${API}${path}`, opts);
  } catch (e) {
    throw new Error('Cannot reach API Gateway. Is the server running?');
  }

  if (res.status === 401) { logout(); return null; }

  if (expectBlob) {
    if (!res.ok) { const t = await res.text(); throw new Error(t); }
    return res.blob();
  }

  const data = await res.json().catch(() => ({ detail: res.statusText }));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

/* ── Auth ────────────────────────────────────────────────────────────────── */
function setLoginMsg(msg, type = 'error') {
  const el = document.getElementById('login-msg');
  el.textContent = msg;
  el.className = `login-status ${type}`;
}

function saveSession(data) {
  token = data.access_token;
  currentUser = data.user;
  localStorage.setItem('sf_token', token);
  localStorage.setItem('sf_user', JSON.stringify(currentUser));
}

document.getElementById('btn-login').addEventListener('click', doLogin);
document.getElementById('inp-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

async function doLogin() {
  const username = document.getElementById('inp-user').value.trim();
  const password = document.getElementById('inp-pass').value;
  if (!username || !password) { setLoginMsg('Enter username and password.'); return; }

  const btn = document.getElementById('btn-login');
  btn.disabled = true; btn.textContent = 'AUTHENTICATING...';

  try {
    const data = await apiFetch('/auth/login', 'POST', { username, password });
    if (!data) return;

    if (data.otp_required) {
      tempToken    = data.temp_token;
      tempUsername = username;
      document.getElementById('login-section').style.display = 'none';
      document.getElementById('otp-section').style.display   = 'block';
      setLoginMsg('OTP required. Enter your 6-digit code.', 'info');
    } else {
      saveSession(data);
      showApp();
    }
  } catch (e) {
    setLoginMsg(e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'LOGIN';
  }
}

document.getElementById('btn-otp').addEventListener('click', doOTP);
document.getElementById('inp-otp').addEventListener('keydown', e => { if (e.key === 'Enter') doOTP(); });

async function doOTP() {
  const otp_code = document.getElementById('inp-otp').value.trim();
  if (otp_code.length !== 6) { setLoginMsg('OTP must be 6 digits.'); return; }

  const btn = document.getElementById('btn-otp');
  btn.disabled = true; btn.textContent = 'VERIFYING...';

  try {
    const data = await apiFetch('/auth/otp/verify', 'POST', {
      username: tempUsername, otp_code, temp_token: tempToken
    });
    if (!data) return;
    saveSession(data);
    showApp();
  } catch (e) {
    setLoginMsg(e.message);
  } finally {
    btn.disabled = false; btn.textContent = 'VERIFY OTP';
  }
}

document.getElementById('btn-otp-back').addEventListener('click', () => {
  document.getElementById('login-section').style.display = '';
  document.getElementById('otp-section').style.display   = 'none';
  setLoginMsg('');
});

function logout() {
  localStorage.removeItem('sf_token');
  localStorage.removeItem('sf_user');
  token = null; currentUser = null;
  document.getElementById('app-shell').classList.remove('visible');
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('inp-pass').value = '';
  document.getElementById('otp-section').style.display = 'none';
  document.getElementById('login-section').style.display = '';
}

function showApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app-shell').classList.add('visible');

  const name = currentUser?.name || currentUser?.username || 'User';
  const role = currentUser?.role || 'user';
  const tier = currentUser?.tier || 'standard';

  document.getElementById('disp-name').textContent = name;
  const badge = document.getElementById('disp-badge');
  if (role === 'admin')      { badge.textContent = 'ADMIN';  badge.className = 'user-badge badge-admin'; }
  else if (tier === 'vip')   { badge.textContent = 'VIP';    badge.className = 'user-badge badge-vip'; }
  else                       { badge.textContent = 'USER';   badge.className = 'user-badge badge-user'; }

  navigate('dashboard');
  pollUnreadCount();
}

/* ── Router ──────────────────────────────────────────────────────────────── */
function navigate(page) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });
  const area = document.getElementById('content-area');
  area.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

  const pages = { dashboard, transfer, risk, notifications, reports };
  if (pages[page]) pages[page](area);
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function fmt(n) { return n === undefined || n === null ? '—' : Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
function fmtDate(s) { return s ? s.replace('T', ' ').substring(0, 16) : '—'; }
function loading(area) { area.innerHTML = '<div class="loading"><div class="spinner"></div>載入中...</div>'; }

function statusPill(status) {
  const map = {
    active: 'pill-green', completed: 'pill-green', resolved: 'pill-green', ok: 'pill-green',
    frozen: 'pill-red', failed: 'pill-red', locked: 'pill-red', critical: 'pill-red',
    pending_review: 'pill-yellow', pending: 'pill-yellow', investigating: 'pill-yellow', open: 'pill-yellow',
    high: 'pill-orange', medium: 'pill-yellow',
    low: 'pill-blue', false_positive: 'pill-gray',
  };
  const cls = map[status] || 'pill-gray';
  return `<span class="pill ${cls}">${status?.replace('_', ' ') || '—'}</span>`;
}

function severityPill(sev) {
  const map = { critical: 'pill-red', high: 'pill-orange', medium: 'pill-yellow', low: 'pill-blue' };
  return `<span class="pill ${map[sev] || 'pill-gray'}">${sev || '—'}</span>`;
}

function feedback(id, msg, type = 'success') {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = `feedback show ${type}`;
  setTimeout(() => el.classList.remove('show'), 5000);
}

/* ── Unread badge polling ────────────────────────────────────────────────── */
async function pollUnreadCount() {
  try {
    const data = await apiFetch('/notifications/unread-count');
    if (!data) return;
    const badge = document.getElementById('notif-badge');
    badge.textContent = data.count;
    badge.classList.toggle('show', data.count > 0);
  } catch (_) {}
  setTimeout(pollUnreadCount, 30000);
}

/* ════════════════════════════════════════════════════════════════════════════
   PAGE: Dashboard
═══════════════════════════════════════════════════════════════════════════ */
async function dashboard(area) {
  try {
    const data = await apiFetch('/accounts/summary');
    if (!data) return;

    const twd = data.balance_by_currency['TWD'] || 0;
    const usd = data.balance_by_currency['USD'] || 0;
    const hkd = data.balance_by_currency['HKD'] || 0;
    const bySt = data.count_by_status || {};

    area.innerHTML = `
    <div class="page-header">
      <h2>◈ 帳戶總覽</h2>
      <span class="page-sub">Account Overview · ${fmtDate(new Date().toISOString())}</span>
    </div>

    <div class="card-grid card-grid-3">
      <div class="stat-card accent-blue">
        <div class="card-label">TWD 台幣總餘額</div>
        <div class="card-value text-blue">$ ${fmt(twd)}</div>
        <div class="card-sub">New Taiwan Dollar</div>
      </div>
      <div class="stat-card accent-green">
        <div class="card-label">USD 美金總餘額</div>
        <div class="card-value text-green">$ ${fmt(usd)}</div>
        <div class="card-sub">US Dollar</div>
      </div>
      <div class="stat-card accent-gold">
        <div class="card-label">HKD 港幣總餘額</div>
        <div class="card-value text-yellow">$ ${fmt(hkd)}</div>
        <div class="card-sub">Hong Kong Dollar</div>
      </div>
    </div>

    <div class="card-grid card-grid-4">
      <div class="stat-card"><div class="card-label">Total Accounts</div><div class="card-value">${data.total_accounts}</div></div>
      <div class="stat-card accent-green"><div class="card-label">Active</div><div class="card-value text-green">${bySt.active || 0}</div></div>
      <div class="stat-card accent-red"><div class="card-label">Frozen</div><div class="card-value text-red">${bySt.frozen || 0}</div></div>
      <div class="stat-card accent-gold"><div class="card-label">Pending Review</div><div class="card-value text-yellow">${bySt.pending_review || 0}</div></div>
    </div>

    <div class="table-container">
      <div class="table-header">
        <span class="table-title">帳戶列表</span>
        <button class="btn-action btn-blue" onclick="openAccountModal()">+ 開戶申請</button>
      </div>
      <table>
        <thead><tr>
          <th>Account ID</th><th>Currency</th><th>Type</th><th>Nickname</th>
          <th class="td-num">Balance</th><th>Status</th><th>Created</th>
        </tr></thead>
        <tbody>
        ${(data.accounts || []).map(a => `
          <tr>
            <td class="mono text-blue">${a.account_id}</td>
            <td class="mono">${a.currency}</td>
            <td>${a.account_type}</td>
            <td>${a.nickname || '<span class="text-dim">—</span>'}</td>
            <td class="td-num">${fmt(a.balance)}</td>
            <td>${statusPill(a.status)}</td>
            <td class="text-dim">${fmtDate(a.created_at)}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;

  } catch (e) {
    area.innerHTML = `<div class="feedback show error">${e.message}</div>`;
  }
}

function openAccountModal() {
  const cur = currentUser?.username;
  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:999';
  modal.innerHTML = `
    <div class="content-card" style="width:380px;margin:0">
      <h3>開戶申請</h3>
      <div id="open-msg"></div>
      <div class="field-row">
        <div class="field-group"><label>Currency</label>
          <select id="oa-cur"><option value="TWD">TWD — 台幣</option><option value="USD">USD — 美金</option><option value="HKD">HKD — 港幣</option></select>
        </div>
        <div class="field-group"><label>Type</label>
          <select id="oa-type"><option value="savings">Savings</option><option value="checking">Checking</option><option value="investment">Investment</option></select>
        </div>
      </div>
      <div class="field-group"><label>Initial Deposit</label><input type="number" id="oa-amt" value="0" min="0"></div>
      <div class="btn-row">
        <button class="btn-action btn-blue" onclick="submitOpenAccount()">SUBMIT</button>
        <button class="btn-action btn-ghost" onclick="this.closest('div[style]').remove()">CANCEL</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
}

async function submitOpenAccount() {
  try {
    const res = await apiFetch('/accounts/open', 'POST', {
      currency: document.getElementById('oa-cur').value,
      account_type: document.getElementById('oa-type').value,
      initial_deposit: parseFloat(document.getElementById('oa-amt').value) || 0,
    });
    document.querySelector('div[style*="position:fixed"]').remove();
    navigate('dashboard');
  } catch (e) {
    document.getElementById('open-msg').innerHTML = `<div class="feedback show error">${e.message}</div>`;
  }
}

/* ════════════════════════════════════════════════════════════════════════════
   PAGE: Transfer
═══════════════════════════════════════════════════════════════════════════ */
async function transfer(area) {
  let accounts = [];
  try {
    const sum = await apiFetch('/accounts/summary');
    accounts = (sum?.accounts || []).filter(a => a.status === 'active');
  } catch (_) {}

  const optionsHtml = accounts.map(a =>
    `<option value="${a.account_id}">${a.account_id} (${a.currency} ${fmt(a.balance)})</option>`
  ).join('');

  area.innerHTML = `
  <div class="page-header">
    <h2>⇄ 轉帳作業</h2>
    <span class="page-sub">Fund Transfer</span>
  </div>

  <div class="content-card">
    <h3>發起轉帳</h3>
    <div id="tx-msg" class="feedback"></div>
    <div class="field-row">
      <div class="field-group"><label>From Account</label>
        <select id="tx-from">${optionsHtml || '<option value="">— No active accounts —</option>'}</select>
      </div>
      <div class="field-group"><label>To Account ID</label>
        <input type="text" id="tx-to" placeholder="e.g. T1A2B3C4D5">
      </div>
    </div>
    <div class="field-row">
      <div class="field-group"><label>Amount</label>
        <input type="number" id="tx-amt" placeholder="0.00" min="0.01" step="0.01">
      </div>
      <div class="field-group"><label>Currency</label>
        <select id="tx-cur">
          <option value="TWD">TWD</option>
          <option value="USD">USD</option>
          <option value="HKD">HKD</option>
        </select>
      </div>
    </div>
    <div class="field-row full">
      <div class="field-group"><label>Memo (Optional)</label>
        <input type="text" id="tx-memo" placeholder="Transfer description">
      </div>
    </div>
    <div class="btn-row">
      <button class="btn-action btn-blue" id="btn-tx-submit" onclick="submitTransfer()">SUBMIT TRANSFER</button>
    </div>
  </div>

  <div class="table-container" id="tx-history-container">
    <div class="table-header"><span class="table-title">Recent Transactions</span>
      <button class="btn-action btn-ghost" onclick="loadTxHistory()">↻ Refresh</button>
    </div>
    <div id="tx-history-body"><div class="loading"><div class="spinner"></div>Loading...</div></div>
  </div>`;

  loadTxHistory();
}

async function submitTransfer() {
  const from = document.getElementById('tx-from').value;
  const to   = document.getElementById('tx-to').value.trim();
  const amt  = parseFloat(document.getElementById('tx-amt').value);
  const cur  = document.getElementById('tx-cur').value;
  const memo = document.getElementById('tx-memo').value.trim();

  if (!from) { feedback('tx-msg', 'Select a source account.', 'error'); return; }
  if (!to)   { feedback('tx-msg', 'Enter destination account ID.', 'error'); return; }
  if (!amt || amt <= 0) { feedback('tx-msg', 'Enter a valid amount.', 'error'); return; }

  const btn = document.getElementById('btn-tx-submit');
  btn.disabled = true; btn.textContent = 'PROCESSING...';

  try {
    const tx = await apiFetch('/transactions/transfer', 'POST', {
      from_account_id: from, to_account_id: to,
      amount: amt, currency: cur, memo,
    });
    feedback('tx-msg', `Transfer completed. TX ID: ${tx.transaction_id}`, 'success');
    document.getElementById('tx-amt').value = '';
    document.getElementById('tx-to').value  = '';
    loadTxHistory();
  } catch (e) {
    feedback('tx-msg', e.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'SUBMIT TRANSFER';
  }
}

async function loadTxHistory() {
  const body = document.getElementById('tx-history-body');
  if (!body) return;
  body.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  try {
    const txs = await apiFetch('/transactions?limit=30');
    if (!txs) return;
    if (!txs.length) { body.innerHTML = '<div style="padding:20px;text-align:center;color:#3d5570;font-family:var(--mono);font-size:12px">No transactions found.</div>'; return; }
    body.innerHTML = `<table>
      <thead><tr>
        <th>TX ID</th><th>Type</th><th>From</th><th>To</th>
        <th class="td-num">Amount</th><th>Cur</th><th>Status</th><th>Date</th>
      </tr></thead>
      <tbody>${txs.map(t => `
        <tr>
          <td class="mono text-blue" style="font-size:10px">${t.transaction_id}</td>
          <td>${t.type || '—'}</td>
          <td class="mono" style="font-size:10px">${t.from_account_id || '—'}</td>
          <td class="mono" style="font-size:10px">${t.to_account_id || '—'}</td>
          <td class="td-num ${t.type === 'withdrawal' ? 'text-red' : 'text-green'}">${fmt(t.amount)}</td>
          <td>${t.currency || '—'}</td>
          <td>${statusPill(t.status)}</td>
          <td class="text-dim">${fmtDate(t.created_at)}</td>
        </tr>`).join('')}
      </tbody></table>`;
  } catch (e) {
    body.innerHTML = `<div class="feedback show error">${e.message}</div>`;
  }
}

/* ════════════════════════════════════════════════════════════════════════════
   PAGE: Risk Monitor
═══════════════════════════════════════════════════════════════════════════ */
async function risk(area) {
  area.innerHTML = `
  <div class="page-header">
    <h2>⚠ 風險監控</h2>
    <span class="page-sub">Risk &amp; AML Monitoring</span>
  </div>
  <div class="card-grid card-grid-2">
    <div class="content-card mb-0" id="score-card">
      <h3>信用評分 Credit Score</h3>
      <div class="loading"><div class="spinner"></div>Computing...</div>
    </div>
    <div class="content-card mb-0" id="dashboard-card">
      <h3>風險儀表板 Risk Dashboard</h3>
      <div class="loading"><div class="spinner"></div>Loading...</div>
    </div>
  </div>
  <div style="height:16px"></div>
  <div class="table-container">
    <div class="table-header">
      <span class="table-title">Risk Events</span>
      <select id="risk-filter" style="background:var(--bg-input);border:1px solid var(--border);color:var(--text-sec);font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:3px" onchange="loadRiskEvents()">
        <option value="">All Status</option>
        <option value="open">Open</option>
        <option value="investigating">Investigating</option>
        <option value="resolved">Resolved</option>
      </select>
    </div>
    <div id="risk-events-body"><div class="loading"><div class="spinner"></div></div></div>
  </div>`;

  loadCreditScore();
  loadRiskDashboard();
  loadRiskEvents();
}

async function loadCreditScore() {
  const card = document.getElementById('score-card');
  if (!card) return;
  try {
    const username = currentUser?.username;
    const data = await apiFetch(`/risk/score/${username}`);
    if (!data) return;
    const pct = ((data.score - 300) / 550) * 100;
    const gradeColor = { A: '#00d68f', B: '#00aaff', C: '#f5c542', D: '#ff8c00', F: '#ff4757' };
    const color = gradeColor[data.grade] || '#7a96b8';
    const circum = 2 * Math.PI * 38;
    const dash = (pct / 100) * circum;

    card.innerHTML = `<h3>信用評分 Credit Score</h3>
    <div class="score-gauge">
      <div class="gauge-circle">
        <svg width="100" height="100" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="38" fill="none" stroke="var(--border)" stroke-width="8"/>
          <circle cx="50" cy="50" r="38" fill="none" stroke="${color}" stroke-width="8"
                  stroke-dasharray="${dash.toFixed(1)} ${circum.toFixed(1)}"
                  stroke-linecap="round"/>
        </svg>
        <div class="gauge-text">
          <span class="gauge-score">${data.score}</span>
          <span class="gauge-label">/ 850</span>
        </div>
      </div>
      <div class="gauge-info">
        <div class="gauge-grade" style="color:${color}">${data.grade}</div>
        <div class="gauge-rating">${data.rating}</div>
        <ul class="factors-list">
          ${(data.factors || []).map(f => `<li>${f}</li>`).join('')}
        </ul>
      </div>
    </div>`;
  } catch (e) {
    if (document.getElementById('score-card'))
      document.getElementById('score-card').innerHTML = `<h3>信用評分</h3><div class="feedback show error">${e.message}</div>`;
  }
}

async function loadRiskDashboard() {
  const card = document.getElementById('dashboard-card');
  if (!card) return;
  try {
    const data = await apiFetch('/risk/dashboard');
    if (!data) return;
    const sevs = data.open_by_severity || {};
    card.innerHTML = `<h3>風險儀表板 Risk Dashboard</h3>
    <div class="card-grid card-grid-2" style="margin:0 0 10px">
      <div class="stat-card accent-red mb-0"><div class="card-label">Open Events</div><div class="card-value text-red">${data.total_open}</div></div>
      <div class="stat-card accent-green mb-0"><div class="card-label">Resolved</div><div class="card-value text-green">${data.total_resolved}</div></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
      <span class="pill pill-red">CRITICAL: ${sevs.critical || 0}</span>
      <span class="pill pill-orange">HIGH: ${sevs.high || 0}</span>
      <span class="pill pill-yellow">MED: ${sevs.medium || 0}</span>
      <span class="pill pill-blue">LOW: ${sevs.low || 0}</span>
    </div>
    <div class="mt-8" style="font-size:11px;font-family:var(--mono);color:var(--text-sec)">New (24h): <span class="text-yellow">${data.new_last_24h}</span></div>`;
  } catch (e) {
    if (document.getElementById('dashboard-card'))
      document.getElementById('dashboard-card').innerHTML = `<h3>風險儀表板</h3><div class="feedback show info">Admin access required for full dashboard.</div>`;
  }
}

async function loadRiskEvents() {
  const body = document.getElementById('risk-events-body');
  if (!body) return;
  body.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
  const statusFilter = document.getElementById('risk-filter')?.value || '';
  try {
    const path = `/risk/events?limit=50${statusFilter ? '&status=' + statusFilter : ''}`;
    const events = await apiFetch(path);
    if (!events) return;
    if (!events.length) {
      body.innerHTML = '<div style="padding:20px;text-align:center;color:#3d5570;font-family:var(--mono);font-size:12px">No risk events found.</div>';
      return;
    }
    body.innerHTML = `<table>
      <thead><tr>
        <th>Event ID</th><th>Type</th><th>Severity</th><th>Description</th>
        <th>Status</th><th>Date</th><th>Action</th>
      </tr></thead>
      <tbody>${events.map(e => `
        <tr>
          <td class="mono text-blue" style="font-size:10px">${e.event_id || '—'}</td>
          <td class="mono" style="font-size:10px">${e.event_type || '—'}</td>
          <td>${severityPill(e.severity)}</td>
          <td style="max-width:280px;white-space:normal;font-size:11px">${e.description || '—'}</td>
          <td>${statusPill(e.status)}</td>
          <td class="text-dim">${fmtDate(e.created_at)}</td>
          <td>${e.status === 'open' ? `<button class="btn-action btn-ghost" style="padding:4px 10px;font-size:10px" onclick="reviewEvent('${e.event_id}')">Review</button>` : ''}</td>
        </tr>`).join('')}
      </tbody></table>`;
  } catch (e) {
    body.innerHTML = `<div class="feedback show error">${e.message}</div>`;
  }
}

async function reviewEvent(eventId) {
  const action = prompt('Action (resolved / investigating / false_positive / escalated):');
  if (!action) return;
  const notes = prompt('Review notes (optional):') || '';
  try {
    await apiFetch(`/risk/events/${eventId}/review`, 'PUT', { action, notes });
    loadRiskEvents();
  } catch (e) { alert(e.message); }
}

/* ════════════════════════════════════════════════════════════════════════════
   PAGE: Notifications
═══════════════════════════════════════════════════════════════════════════ */
async function notifications(area) {
  area.innerHTML = `
  <div class="page-header flex-between">
    <div style="display:flex;align-items:baseline;gap:12px">
      <h2>◉ 通知中心</h2>
      <span class="page-sub">Notification Center</span>
    </div>
    <div style="display:flex;gap:8px">
      <label style="display:flex;align-items:center;gap:6px;font-size:11px;font-family:var(--mono);color:var(--text-sec);cursor:pointer">
        <input type="checkbox" id="unread-only" onchange="loadNotifList()"> Unread only
      </label>
      <button class="btn-action btn-ghost" style="padding:6px 12px;font-size:10px" onclick="markAllRead()">Mark All Read</button>
    </div>
  </div>
  <div id="notif-list"><div class="loading"><div class="spinner"></div></div></div>`;

  loadNotifList();
}

async function loadNotifList() {
  const body = document.getElementById('notif-list');
  if (!body) return;
  body.innerHTML = '<div class="loading"><div class="spinner"></div></div>';

  const unreadOnly = document.getElementById('unread-only')?.checked;
  try {
    const notifs = await apiFetch(`/notifications?limit=50${unreadOnly ? '&unread_only=true' : ''}`);
    if (!notifs) return;
    if (!notifs.length) {
      body.innerHTML = '<div style="padding:32px;text-align:center;color:#3d5570;font-family:var(--mono);font-size:12px">No notifications.</div>';
      return;
    }

    const typeIcon = { transaction_alert: '💸', risk_alert: '⚠️', system_notice: '📢', account_alert: '🏦', login_alert: '🔐' };
    body.innerHTML = `<div class="notif-list">${notifs.map(n => `
      <div class="notif-item ${n.is_read ? '' : 'unread'}" onclick="markRead('${n.id}', this)">
        <div class="notif-type-icon">${typeIcon[n.type] || '📌'}</div>
        <div class="notif-body">
          <div class="notif-title">${n.title}</div>
          <div class="notif-msg">${n.message}</div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">
          <div class="notif-time">${fmtDate(n.created_at)}</div>
          <div class="notif-dot ${n.is_read ? 'read' : ''}"></div>
        </div>
      </div>`).join('')}</div>`;
  } catch (e) {
    body.innerHTML = `<div class="feedback show error">${e.message}</div>`;
  }
}

async function markRead(id, el) {
  try {
    await apiFetch(`/notifications/${id}/read`, 'PUT');
    el.classList.remove('unread');
    el.querySelector('.notif-dot')?.classList.add('read');
    pollUnreadCount();
  } catch (_) {}
}

async function markAllRead() {
  try {
    await apiFetch('/notifications/read-all', 'PUT');
    loadNotifList();
    pollUnreadCount();
  } catch (e) { alert(e.message); }
}

/* ════════════════════════════════════════════════════════════════════════════
   PAGE: Reports
═══════════════════════════════════════════════════════════════════════════ */
async function reports(area) {
  let accounts = [];
  try {
    const sum = await apiFetch('/accounts/summary');
    accounts = sum?.accounts || [];
  } catch (_) {}

  const optHtml = accounts.map(a =>
    `<option value="${a.account_id}">${a.account_id} (${a.currency})</option>`
  ).join('');

  area.innerHTML = `
  <div class="page-header">
    <h2>↓ 報表下載</h2>
    <span class="page-sub">Statement &amp; Reports</span>
  </div>

  <div class="content-card" style="max-width:500px">
    <h3>對帳單 PDF 下載</h3>
    <div id="rpt-msg" class="feedback"></div>
    <div class="field-row">
      <div class="field-group"><label>Account</label>
        <select id="rpt-acc">${optHtml || '<option value="">— No accounts —</option>'}</select>
      </div>
      <div class="field-group"><label>Period (days)</label>
        <select id="rpt-days">
          <option value="30">30 Days</option>
          <option value="60">60 Days</option>
          <option value="90">90 Days</option>
          <option value="180">180 Days</option>
        </select>
      </div>
    </div>
    <div class="btn-row">
      <button class="btn-action btn-blue" id="btn-dl" onclick="downloadStatement()">↓ DOWNLOAD PDF</button>
    </div>
  </div>

  <div class="content-card" style="max-width:500px">
    <h3>Risk Analysis Report</h3>
    <p style="font-size:12px;font-family:var(--mono);color:var(--text-sec);margin-bottom:12px">
      Enter a transaction ID to run the AML rules engine.
    </p>
    <div id="aml-msg" class="feedback"></div>
    <div class="field-group"><label>Transaction ID</label>
      <input type="text" id="aml-tx-id" placeholder="TX...">
    </div>
    <div class="btn-row">
      <button class="btn-action btn-blue" onclick="runAmlCheck()">⚠ RUN AML CHECK</button>
    </div>
    <div id="aml-result" style="margin-top:14px"></div>
  </div>`;
}

async function downloadStatement() {
  const accountId = document.getElementById('rpt-acc').value;
  const days = document.getElementById('rpt-days').value;
  if (!accountId) { feedback('rpt-msg', 'Select an account.', 'error'); return; }

  const btn = document.getElementById('btn-dl');
  btn.disabled = true; btn.textContent = 'GENERATING...';

  try {
    const blob = await apiFetch(`/transactions/statement/${accountId}?days=${days}`, 'GET', null, true);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `statement_${accountId}_${days}d.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    feedback('rpt-msg', 'PDF downloaded successfully.', 'success');
  } catch (e) {
    feedback('rpt-msg', e.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = '↓ DOWNLOAD PDF';
  }
}

async function runAmlCheck() {
  const txId = document.getElementById('aml-tx-id').value.trim();
  if (!txId) { feedback('aml-msg', 'Enter a transaction ID.', 'error'); return; }
  try {
    const result = await apiFetch('/risk/analyze', 'POST', { transaction_id: txId });
    if (!result) return;
    const resultEl = document.getElementById('aml-result');
    const passed = result.aml_passed;
    resultEl.innerHTML = `
      <div class="stat-card ${passed ? 'accent-green' : 'accent-red'}">
        <div class="card-label">AML Check Result</div>
        <div class="card-value ${passed ? 'text-green' : 'text-red'}">${passed ? 'PASSED ✓' : 'FLAGGED ✗'}</div>
        <div class="card-sub">${result.alerts_count} alert(s) generated</div>
      </div>
      ${(result.events_created || []).map(ev => `
        <div style="margin-top:8px;padding:10px;background:var(--red-dim);border:1px solid var(--red);border-radius:3px;font-family:var(--mono);font-size:11px">
          ${severityPill(ev.severity)} ${ev.event_type}: ${ev.description}
        </div>`).join('')}`;
    feedback('aml-msg', 'AML analysis complete.', 'success');
  } catch (e) {
    feedback('aml-msg', e.message, 'error');
  }
}

/* ── Init ────────────────────────────────────────────────────────────────── */
(function init() {
  if (token && currentUser) {
    showApp();
  }
})();
