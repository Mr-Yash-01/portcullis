'use strict';
// All DOM updates use textContent / DOM nodes, never innerHTML. The CSP enforces
// Trusted Types, so any accidental HTML-string sink would throw instead of running.

const $ = (sel) => document.querySelector(sel);
const el = (tag, props = {}, ...kids) => {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...kids);
  return node;
};
const csrfToken = () =>
  document.cookie.split('; ').find((c) => c.startsWith('__Host-csrf='))?.slice('__Host-csrf='.length) ?? '';
const fmtTime = (v) => (v ? new Date(v).toLocaleString() : '—');
const LABELS = {
  login_success: 'Sign-in succeeded', login_failed: 'Sign-in failed', login_blocked: 'Sign-in blocked',
  account_locked: 'Account locked', user_registered: 'Account created', user_updated: 'User changed',
  user_unlocked: 'User unlocked', mfa_enabled: 'MFA enabled', logout: 'Signed out',
};

let me = null;
let poll = null;

function flash(text, kind = 'info') {
  const msg = $('#msg');
  msg.textContent = text;
  msg.className = kind;
  msg.hidden = !text;
}

async function api(path, method = 'GET', body) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (data.served_by) {
    const s = data.served_by;
    $('#served').textContent = `Served by ${s.service} ${s.version} · pod ${s.pod}`;
  }
  if (res.status === 401 && me && path !== '/api/auth/login') {
    showAuth();
    flash('Your session ended. Please sign in again.', 'error');
  }
  if (!res.ok) {
    throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${res.status})`);
  }
  return data;
}

function selectTab(container, attr, value) {
  for (const b of container.querySelectorAll(`[${attr}]`)) {
    b.setAttribute('aria-selected', String(b.getAttribute(attr) === value));
  }
}

// ---------- sign-in / registration ----------

function showAuth() {
  me = null;
  clearInterval(poll);
  $('#app-view').hidden = true;
  $('#whoami').hidden = true;
  $('#auth-view').hidden = false;
  $('#served').textContent = '';
}

for (const tab of document.querySelectorAll('[data-tab]')) {
  tab.addEventListener('click', () => {
    selectTab($('#auth-view'), 'data-tab', tab.dataset.tab);
    $('#login-form').hidden = tab.dataset.tab !== 'login';
    $('#register-form').hidden = tab.dataset.tab !== 'register';
    flash('');
  });
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = { username: f.username.value.trim().toLowerCase(), password: f.password.value };
  if (!$('#totp-row').hidden) body.totp = f.totp.value.trim();
  try {
    const r = await api('/api/auth/login', 'POST', body);
    if (r.mfa_required) {
      $('#totp-row').hidden = false;
      f.totp.required = true;
      f.totp.focus();
      flash('Enter the 6-digit code from your authenticator app.');
      return;
    }
    f.reset();
    $('#totp-row').hidden = true;
    f.totp.required = false;
    flash('');
    await loadApp();
  } catch (err) {
    f.password.value = '';
    f.totp.value = '';
    flash(err.message, 'error');
  }
});

$('#register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  if (f.password.value !== f.confirm.value) return flash('The passwords do not match.', 'error');
  const username = f.username.value.trim().toLowerCase();
  try {
    await api('/api/auth/register', 'POST', { username, password: f.password.value });
    f.reset();
    document.querySelector('[data-tab="login"]').click();
    $('#login-form').username.value = username;
    flash('Account created. You can sign in now.', 'ok');
  } catch (err) {
    flash(err.message, 'error');
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', 'POST'); } catch { /* session may already be gone */ }
  showAuth();
  flash('Signed out.', 'ok');
});

// ---------- signed-in app ----------

async function loadApp() {
  me = await api('/api/auth/me');
  const staff = me.role === 'admin' || me.role === 'auditor';
  $('#who').textContent = me.username;
  $('#role-badge').textContent = me.role;
  $('#whoami').hidden = false;
  $('#auth-view').hidden = true;
  $('#app-view').hidden = false;
  for (const v of ['users', 'audit']) document.querySelector(`[data-view="${v}"]`).hidden = !staff;
  showView('account');
  clearInterval(poll);
  // Keep-alive check: shows session expiry/revocation, and which pod/version answered (load balancing, rollouts).
  poll = setInterval(() => api('/api/auth/me').then((m) => { me = m; }).catch(() => {}), 5000);
}

function showView(name) {
  selectTab($('#app-view'), 'data-view', name);
  for (const v of ['account', 'users', 'audit']) $(`#view-${v}`).hidden = v !== name;
  ({ account: renderAccount, users: () => loadUsers(1), audit: loadAudit })[name]();
}

for (const tab of document.querySelectorAll('[data-view]')) {
  tab.addEventListener('click', () => showView(tab.dataset.view));
}

function renderAccount() {
  const rows = [
    ['Username', me.username], ['Role', me.role],
    ['MFA', me.mfa_enabled ? 'Enabled' : 'Not enabled'],
    ['Session expires', fmtTime(me.session_expires * 1000)],
    ['Member since', fmtTime(me.created_at)], ['Last sign-in', fmtTime(me.last_login_at)],
  ];
  $('#account-details').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { textContent: k }), el('dd', { textContent: v })]));

  const box = $('#mfa-box');
  if (me.mfa_enabled) {
    box.replaceChildren(el('p', { className: 'ok', textContent: 'Multi-factor authentication is protecting this account.' }));
    return;
  }
  const kids = [
    el('h3', { textContent: 'Multi-factor authentication' }),
    el('p', { textContent: 'Add a second factor with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password...).' }),
  ];
  if (me.role !== 'user') {
    kids.push(el('p', { className: 'warn', textContent: `As ${me.role}, you must enable MFA before the admin tools unlock.` }));
  }
  kids.push(el('button', { type: 'button', textContent: 'Set up MFA', onclick: startMfa }));
  box.replaceChildren(...kids);
}

async function startMfa() {
  try {
    const { secret, uri } = await api('/api/auth/mfa/setup', 'POST');
    const form = el('form', { className: 'row' },
      el('label', { className: 'grow' }, 'Code from your app',
        el('input', { name: 'code', inputMode: 'numeric', pattern: '[0-9]{6}', maxLength: 6, required: true, autocomplete: 'one-time-code' })),
      el('button', { type: 'submit', textContent: 'Verify and enable' }));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await api('/api/auth/mfa/enable', 'POST', { code: form.code.value.trim() });
        flash('MFA is now on. Other sessions were signed out.', 'ok');
        await loadApp();
      } catch (err) {
        flash(err.message, 'error');
      }
    });
    $('#mfa-box').replaceChildren(
      el('h3', { textContent: 'Add this key to your authenticator app' }),
      el('p', { textContent: 'Choose "Enter a setup key", account Portcullis, time-based:' }),
      el('p', { className: 'secret', textContent: secret.match(/.{1,4}/g).join(' ') }),
      el('details', {}, el('summary', { textContent: 'otpauth URI' }), el('code', { className: 'uri', textContent: uri })),
      form);
    form.code.focus();
  } catch (err) {
    flash(err.message, 'error');
  }
}

// ---------- users (admin / auditor) ----------

function badge(text) {
  return el('span', { className: `badge ${text}`, textContent: text });
}

function pager(sel, page, hasMore, load) {
  $(sel).replaceChildren(
    el('button', { type: 'button', className: 'ghost', textContent: '← Previous', disabled: page <= 1, onclick: () => load(page - 1) }),
    el('span', { textContent: `Page ${page}` }),
    el('button', { type: 'button', className: 'ghost', textContent: 'Next →', disabled: !hasMore, onclick: () => load(page + 1) }));
}

async function changeUser(u, change, okText) {
  try {
    await api(`/api/directory/users/${u.id}`, 'PATCH', change);
    flash(okText, 'ok');
  } catch (err) {
    flash(err.message, 'error');
  }
  loadUsers(1);
}

function userRow(u) {
  const editable = me.role === 'admin' && u.username !== me.username;
  const role = editable
    ? el('select', {
      ariaLabel: `Role for ${u.username}`,
      onchange: (e) => changeUser(u, { role: e.target.value }, `${u.username} is now ${e.target.value}.`),
    }, ...['user', 'auditor', 'admin'].map((r) => el('option', { value: r, textContent: r, selected: r === u.role })))
    : badge(u.role);
  const actions = [];
  if (editable) {
    const disable = u.status === 'active';
    actions.push(el('button', {
      type: 'button', className: disable ? 'danger' : 'ghost', textContent: disable ? 'Disable' : 'Enable',
      onclick: () => changeUser(u, { status: disable ? 'disabled' : 'active' }, `${u.username} ${disable ? 'disabled' : 'enabled'}.`),
    }));
    if (u.locked) {
      actions.push(el('button', {
        type: 'button', className: 'ghost', textContent: 'Unlock',
        onclick: async () => {
          try { await api(`/api/directory/users/${u.id}/unlock`, 'POST'); flash(`${u.username} unlocked.`, 'ok'); } catch (err) { flash(err.message, 'error'); }
          loadUsers(1);
        },
      }));
    }
  }
  return el('tr', {},
    el('td', { textContent: u.username }), el('td', {}, role), el('td', {}, badge(u.status)),
    el('td', { textContent: u.mfa_enabled ? 'On' : 'Off' }), el('td', {}, u.locked ? badge('locked') : '—'),
    el('td', { textContent: fmtTime(u.last_login_at) }), el('td', { className: 'actions' }, ...actions));
}

async function loadUsers(page) {
  try {
    const q = $('#user-q').value.trim().toLowerCase();
    const data = await api(`/api/directory/users?q=${encodeURIComponent(q)}&page=${page}`);
    $('#users-body').replaceChildren(...data.users.map(userRow));
    pager('#users-pager', page, data.has_more, loadUsers);
  } catch (err) {
    flash(err.message, 'error');
  }
}

$('#user-search').addEventListener('submit', (e) => { e.preventDefault(); loadUsers(1); });

// ---------- security log (admin / auditor) ----------

async function loadAudit() {
  try {
    const stats = await api('/api/audit/stats');
    const tiles = ['login_success', 'login_failed', 'login_blocked', 'account_locked', 'user_updated'].map((k) =>
      el('div', { className: `tile ${k}` }, el('strong', { textContent: stats.last_24h[k] ?? 0 }), el('span', { textContent: LABELS[k] })));
    const ips = stats.top_failing_ips.length
      ? el('ul', {}, ...stats.top_failing_ips.map((r) => el('li', { textContent: `${r.ip || 'unknown'} · ${r.n} failures` })))
      : el('p', { className: 'muted', textContent: 'No failed sign-ins.' });
    $('#stats').replaceChildren(...tiles, el('div', { className: 'tile wide' }, el('span', { textContent: 'Top failing IPs (24 h)' }), ips));
    loadEvents(1);
  } catch (err) {
    flash(err.message, 'error');
  }
}

async function loadEvents(page) {
  try {
    const action = $('#audit-filter').value;
    const data = await api(`/api/audit/events?action=${encodeURIComponent(action)}&page=${page}`);
    $('#audit-body').replaceChildren(...data.events.map((ev) => el('tr', {},
      el('td', { textContent: ev.id }), el('td', { textContent: fmtTime(ev.ts_ms) }),
      el('td', { textContent: LABELS[ev.action] ?? ev.action }), el('td', {}, badge(ev.outcome)),
      el('td', { textContent: ev.actor || '—' }), el('td', { textContent: ev.target || '—' }),
      el('td', { textContent: ev.ip || '—' }), el('td', { className: 'detail', textContent: ev.detail === '{}' ? '' : ev.detail }))));
    pager('#audit-pager', page, data.has_more, loadEvents);
  } catch (err) {
    flash(err.message, 'error');
  }
}

$('#audit-filter').addEventListener('change', () => loadEvents(1));

$('#verify').addEventListener('click', async () => {
  const out = $('#verify-result');
  out.textContent = 'Checking…';
  out.className = '';
  try {
    const r = await api('/api/audit/verify');
    out.textContent = r.valid
      ? `Intact: all ${r.checked} events verified against the hash chain.`
      : `TAMPERING DETECTED at event #${r.broken_at_id} (${r.checked} events before it are intact).`;
    out.className = r.valid ? 'ok' : 'error';
  } catch (err) {
    out.textContent = err.message;
    out.className = 'error';
  }
});

// Resume an existing session if the cookie is still valid.
loadApp().catch(showAuth);
