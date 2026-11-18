'use strict';

/* ------------------------------------------------------------------
   Safe rendering: every piece of server data is inserted with textContent
   (via h()). innerHTML is never used with data, so a malicious username or
   audit entry cannot run script in an admin's browser.
------------------------------------------------------------------- */
const $ = id => document.getElementById(id);

function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'style') Object.assign(el.style, v);
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
        if (kid == null || kid === false) continue;
        el.append(kid instanceof Node ? kid : String(kid));
    }
    return el;
}

let token = '';          // kept in memory only (not localStorage)
let me = null;
let auditOffset = 0;
const PAGE = 15;
let timer = null;
const EXPIRED = 'Your session has expired. Please log in again.';

/* ---------- API helper: the response body is read exactly once ---------- */
async function api(path, { method = 'GET', json, form } = {}) {
    const headers = {};
    if (token) headers.Authorization = 'Bearer ' + token;
    let body;
    if (form) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        body = form;
    } else if (json !== undefined) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(json);
    }
    const res = await fetch(path, { method, headers, body });
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    return { res, data };
}

function errText(data, fallback = 'Request failed') {
    const d = data && data.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d) && d.length) return d.map(x => x.msg).join('; ');
    return fallback;
}

/* ---------- toasts, confirm dialog, count-up ---------- */
function toast(msg, kind = 'ok') {
    const t = h('div', { class: 'toast ' + kind }, msg);
    $('toasts').append(t);
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 350); }, 3400);
}

function confirmBox(message, okLabel = 'Confirm', danger = false) {
    return new Promise(resolve => {
        const done = v => {
            overlay.classList.add('closing');
            setTimeout(() => overlay.remove(), 200);
            document.removeEventListener('keydown', onKey);
            resolve(v);
        };
        const onKey = e => { if (e.key === 'Escape') done(false); };
        const ok = h('button', { class: danger ? 'btn-danger-solid' : 'btn-primary', onclick: () => done(true) }, okLabel);
        const overlay = h('div', { class: 'overlay', onclick: e => { if (e.target === overlay) done(false); } },
            h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' },
                h('h3', {}, 'Are you sure?'),
                h('p', {}, message),
                h('div', { class: 'row-actions end' },
                    h('button', { class: 'btn-secondary', onclick: () => done(false) }, 'Cancel'), ok)));
        document.addEventListener('keydown', onKey);
        document.body.append(overlay);
        ok.focus();
    });
}

/* ---------- view switching ---------- */
function show(view) {
    $('auth-view').style.display = view === 'auth' ? 'flex' : 'none';
    $('mfa-onboarding-view').style.display = view === 'mfa' ? 'flex' : 'none';
    $('dashboard-view').style.display = view === 'dashboard' ? 'grid' : 'none';
}

function setMsg(id, msg, isError) {
    const el = $(id);
    el.textContent = msg;
    el.className = isError ? 'msg error' : 'msg success';
}
const setAuthMessage = (m, e) => {
    setMsg('auth-msg', m, e);
    if (e) {
        const card = $('auth-card');
        card.classList.remove('shake');
        void card.offsetWidth;                 // restart the animation
        card.classList.add('shake');
    }
};

const AUTH_COPY = {
    login: {
        title: ['Sign ', 'in.'], sub: 'Use your username and password.',
        asideTitle: 'Welcome back.',
        asideText: 'Sign in to manage accounts and roles, and to see what everyone has been up to.',
    },
    register: {
        title: ['Create ', 'account.'], sub: 'It only takes a minute.',
        asideTitle: "Let's get started.",
        asideText: "Pick a username and a strong password. Right after, you'll add two-step sign-in so the account stays safe.",
    },
};

function toggleAuthMode(mode) {
    const c = AUTH_COPY[mode === 'register' ? 'register' : 'login'];
    $('auth-title').replaceChildren(c.title[0], h('span', { class: 'accent' }, c.title[1]));
    $('auth-sub').textContent = c.sub;
    $('aside-title').textContent = c.asideTitle;
    $('aside-text').textContent = c.asideText;
    $('auth-msg').textContent = '';
    $('login-form').style.display = mode === 'register' ? 'none' : 'block';
    $('register-form').style.display = mode === 'register' ? 'block' : 'none';
}

function logout(message) {
    token = '';
    me = null;
    clearInterval(timer);
    $('log-password').value = '';
    $('log-totp').value = '';
    $('mfa-code').value = '';
    show('auth');
    toggleAuthMode('login');
    if (message) setAuthMessage(message, true);
}

function switchTab(tab) {
    for (const t of ['overview', 'directory']) {
        $('tab-' + t).classList.toggle('active', t === tab);
        $('nav-' + t).classList.toggle('active', t === tab);
    }
    if (tab === 'directory') loadDirectory();
}

/* ---------- registration ---------- */
function checkPasswordStrength() {
    const val = $('reg-password').value;
    $('password-rules').classList.toggle('show', val.length > 0);
    const rules = [
        ['rule-length', /.{8,}/], ['rule-upper', /[A-Z]/], ['rule-lower', /[a-z]/],
        ['rule-number', /[0-9]/], ['rule-special', /[!@#$%^&*(),.?":{}|<>]/],
    ];
    for (const [id, rx] of rules) {
        const ok = rx.test(val);
        const li = $(id);
        li.classList.toggle('valid', ok);
        li.classList.toggle('invalid', !ok);
        li.querySelector('i').className = ok ? 'fa-solid fa-check' : 'fa-solid fa-xmark';
    }
}

async function register() {
    const u = $('reg-username').value.trim();
    const p = $('reg-password').value;
    if (p !== $('reg-confirm-password').value) return setAuthMessage('Passwords do not match.', true);

    // No role is sent: the server always creates standard users.
    const { res, data } = await api('/register', { method: 'POST', json: { username: u, password: p } });
    if (!res.ok) return setAuthMessage(errText(data), true);

    setAuthMessage('Account created. Authenticating...', false);
    $('log-username').value = u;
    $('log-password').value = p;
    $('reg-password').value = '';
    $('reg-confirm-password').value = '';
    $('password-rules').classList.remove('show');
    setTimeout(login, 800);
}

/* ---------- login / MFA enrolment ---------- */
async function login() {
    const form = new URLSearchParams();
    form.append('username', $('log-username').value);
    form.append('password', $('log-password').value);
    const code = $('log-totp').value.trim();
    if (code) form.append('totp_code', code);

    const { res, data } = await api('/login', { method: 'POST', form });
    if (!res.ok) return setAuthMessage(errText(data), true);

    token = data.access_token;
    $('log-totp').value = '';
    await enter();
}

async function enter() {
    const { res, data } = await api('/api/me');
    if (!res.ok) return logout('Session could not be verified. Please log in again.');
    me = data;
    if (me.scope !== 'full' || !me.mfa_enabled) {        // limited token: MFA enrolment is mandatory
        $('mfa-step-1').style.display = 'block';
        $('mfa-step-2').style.display = 'none';
        $('mfa-msg').textContent = '';
        show('mfa');
        return;
    }
    showDashboard();
}

async function startMfaOnboarding() {
    const { res, data } = await api('/api/mfa/setup', { method: 'POST' });
    if (res.status === 401) return logout(EXPIRED);
    if (!res.ok) return setMsg('mfa-msg', errText(data), true);
    $('mfa-qr').src = data.qr;                            // data: URI generated by the server
    $('mfa-onboarding-secret').textContent = data.secret.match(/.{1,4}/g).join(' ');
    $('mfa-step-1').style.display = 'none';
    $('mfa-step-2').style.display = 'block';
    $('mfa-msg').textContent = '';
    $('mfa-code').focus();
}

async function finishMfaOnboarding() {
    const code = $('mfa-code').value.trim();
    const { res, data } = await api('/api/mfa/enable', { method: 'POST', json: { code } });
    if (res.status === 401) return logout(EXPIRED);
    if (!res.ok) return setMsg('mfa-msg', errText(data), true);
    token = data.access_token;                            // upgraded to a full-scope token
    $('mfa-code').value = '';
    await enter();
}

/* ---------- dashboard ---------- */
function showDashboard() {
    show('dashboard');
    $('display-name').textContent = me.username;
    $('det-username').textContent = me.username;
    $('welcome-msg').replaceChildren('Hello, ', h('span', { class: 'accent' }, me.username), '.');
    $('avatar-letter').textContent = me.username.charAt(0).toUpperCase();
    for (const id of ['display-role', 'det-role', 'kpi-role']) $(id).textContent = me.role;

    $('kpi-mfa').textContent = me.mfa_enabled ? 'Enabled' : 'Not enrolled';
    const badge = $('det-mfa');
    badge.textContent = me.mfa_enabled ? 'Verified' : 'Not enrolled';
    badge.className = 'badge ' + (me.mfa_enabled ? 'mfa-on' : 'mfa-off');
    $('det-session').textContent = me.session_minutes + ' minutes';
    $('det-lastlogin').textContent = me.last_login_at ? new Date(me.last_login_at).toLocaleString() : 'This is your first sign-in';
    $('verify-btn').style.display = me.role === 'Admin' ? '' : 'none';
    $('verify-result').textContent = '';

    clearInterval(timer);
    tick();
    timer = setInterval(tick, 15000);

    switchTab('overview');
    auditOffset = 0;
    fetchAuditLogs();
}

function tick() {
    if (!me) return;
    const mins = Math.ceil((new Date(me.session_expires_at) - Date.now()) / 60000);
    if (mins <= 0) return logout(EXPIRED);
    $('kpi-session').textContent = mins + ' min';
}

function addResponseCard(endpoint, ok, status, pairs, time) {
    const label = ok ? ' 200 OK' : ` ${status} ${status === 403 ? 'Forbidden' : 'Error'}`;
    const card = h('div', { class: 'response-card ' + (ok ? 'success' : 'denied') },
        h('div', { class: 'response-header' },
            h('span', {},
                h('i', { class: ok ? 'fa-solid fa-check-circle' : 'fa-solid fa-circle-xmark', style: { color: ok ? 'var(--green-d)' : 'var(--red-d)' } }),
                label,
                h('span', { style: { color: 'var(--muted)', fontWeight: '600', fontSize: '0.8rem', marginLeft: '0.5rem' } }, endpoint)),
            h('span', { style: { fontSize: '0.75rem', color: 'var(--muted)', fontWeight: 'normal' } }, time)),
        h('div', { class: 'response-body' },
            pairs.map(([k, v], i) => [i ? ' | ' : '', h('strong', {}, k + ': '), String(v)])));
    const box = $('api-responses');
    const ph = box.querySelector('.placeholder');
    if (ph) ph.remove();
    box.prepend(card);
}

async function testAccess(endpoint) {
    const { res, data } = await api(endpoint);           // body read once, inside api()
    if (res.status === 401) return logout(EXPIRED);
    const time = new Date().toLocaleTimeString();
    if (res.ok) {
        addResponseCard(endpoint, true, res.status, [
            ['Message', data.message], ['User', data.username], ['Role', data.role],
            ['MFA', data.mfa_enabled ? 'ON' : 'OFF']], time);
    } else {
        addResponseCard(endpoint, false, res.status, [['Blocked', errText(data)]], time);
    }
    fetchAuditLogs();
}

/* ---------- audit trail ---------- */
function prettyDetail(json) {
    try {
        const o = JSON.parse(json);
        return Object.entries(o).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join('/') : v}`).join(', ');
    } catch (_) { return ''; }
}

function auditRow(l, i = 0) {
    const bad = !l.success;
    const detail = l.detail ? prettyDetail(l.detail) : '';
    return h('tr', { class: 'row-in', style: { animationDelay: Math.min(i, 12) * 35 + 'ms' } },
        h('td', { style: { fontFamily: 'var(--mono)', fontSize: '0.8rem', color: 'var(--muted)', whiteSpace: 'nowrap' } },
            new Date(l.timestamp).toLocaleString()),
        h('td', { style: { fontWeight: '600' } }, l.actor || '-'),
        h('td', {}, h('span', { style: { fontWeight: '600', color: bad ? 'var(--red-d)' : 'var(--green-d)' } }, l.action),
            detail ? h('div', { class: 'muted-small' }, detail) : null),
        h('td', {}, l.target || '-'),
        h('td', { title: l.user_agent || '', style: { fontFamily: 'var(--mono)', fontSize: '0.8rem' } }, l.ip || '-'),
        h('td', {}, h('span', { class: 'badge ' + (bad ? 'mfa-off' : 'mfa-on') }, bad ? 'Failed' : 'OK')));
}

async function fetchAuditLogs() {
    if (!token) return;
    const { res, data } = await api(`/api/audit-logs?limit=${PAGE}&offset=${auditOffset}`);
    if (res.status === 401) return logout(EXPIRED);
    if (!res.ok) return;

    if (data.items.length === 0 && data.total > 0 && auditOffset > 0) {
        auditOffset = Math.max(0, auditOffset - PAGE);
        return fetchAuditLogs();
    }
    const tbody = $('audit-table-body');
    if (data.items.length === 0) {
        tbody.replaceChildren(h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'No events yet.')));
    } else {
        tbody.replaceChildren(...data.items.map((l, i) => auditRow(l, i)));
    }
    const from = data.total === 0 ? 0 : data.offset + 1;
    $('audit-range').textContent = `${from}-${data.offset + data.items.length} of ${data.total}`;
    $('audit-prev').disabled = data.offset === 0;
    $('audit-next').disabled = data.offset + data.items.length >= data.total;
}

async function verifyAudit() {
    const el = $('verify-result');
    const { res, data } = await api('/api/audit-logs/verify');
    if (res.status === 401) return logout(EXPIRED);
    if (!res.ok) return setMsg('verify-result', errText(data), true);
    if (data.valid) {
        setMsg('verify-result', `Log is intact: ${data.checked} entries verified (head ${data.head.slice(0, 12)}...)`, false);
    } else {
        setMsg('verify-result', `Tampering detected at entry #${data.broken_at}: ${data.reason}`, true);
    }
    el.setAttribute('role', 'status');
}

/* ---------- admin: user directory ---------- */
async function adminAction(path, method, json, okMsg) {
    const { res, data } = await api(path, { method, json });
    if (res.status === 401) return logout(EXPIRED);
    toast(res.ok ? okMsg : errText(data), res.ok ? 'ok' : 'bad');
    loadDirectory();
    fetchAuditLogs();
}

function directoryRow(u, i = 0) {
    const select = h('select', { style: { padding: '0.35rem 0.5rem', width: 'auto', fontWeight: '600' }, disabled: u.is_self },
        h('option', { value: 'User', selected: u.role === 'User' }, 'User'),
        h('option', { value: 'Admin', selected: u.role === 'Admin' }, 'Admin'));

    let status;
    if (!u.is_active) status = h('span', { class: 'badge mfa-off' }, 'Disabled');
    else if (u.is_locked) status = h('span', { class: 'badge', style: { background: 'var(--red-soft)', color: 'var(--red-d)' } }, `LOCKED (${u.lockout_remaining}m left)`);
    else status = h('span', { style: { color: 'var(--muted)', fontSize: '0.85rem' } }, 'Active');

    const actions = h('div', { class: 'row-actions' },
        h('button', { class: 'btn-secondary', disabled: u.is_self, onclick: () =>
            adminAction(`/api/admin/users/${u.id}/role`, 'PUT', { new_role: select.value }, 'Role updated.') }, 'Save role'),
        u.mfa_enabled && !u.is_self ? h('button', { class: 'btn-warn', onclick: async () => {
            if (await confirmBox(`Reset two-factor for '${u.username}'? They will have to set it up again on their next sign-in.`, 'Reset', true))
                adminAction(`/api/admin/users/${u.id}/reset-mfa`, 'PUT', undefined, 'Two-factor has been reset.');
        } }, 'Reset MFA') : null,
        u.is_locked ? h('button', { class: 'btn-info', onclick: () =>
            adminAction(`/api/admin/users/${u.id}/unlock`, 'PUT', undefined, 'Account unlocked.') },
            h('i', { class: 'fa-solid fa-unlock' }), ' Unlock') : null,
        !u.is_self ? h('button', { class: 'btn-secondary', onclick: async () => {
            if (u.is_active && !(await confirmBox(`Disable '${u.username}'? They will be signed out and unable to sign in until you enable them again.`, 'Disable', true))) return;
            adminAction(`/api/admin/users/${u.id}/status`, 'PUT', { is_active: !u.is_active },
                u.is_active ? 'Account disabled.' : 'Account enabled.');
        } }, u.is_active ? 'Disable' : 'Enable') : null,
        !u.is_self ? h('button', { class: 'btn-danger', title: 'Permanently delete user', onclick: async () => {
            if (await confirmBox(`Permanently delete '${u.username}'? This cannot be undone.`, 'Delete', true))
                adminAction(`/api/admin/users/${u.id}`, 'DELETE', undefined, `'${u.username}' removed.`);
        } }, h('i', { class: 'fa-solid fa-trash-can' })) : null);

    return h('tr', { class: 'row-in', style: { animationDelay: Math.min(i, 12) * 45 + 'ms' } },
        h('td', {}, h('span', { class: 'badge' }, '#' + u.id)),
        h('td', { style: { fontWeight: '700' } }, u.username, u.is_self ? ' (you)' : ''),
        h('td', {}, h('span', { class: 'badge ' + (u.mfa_enabled ? 'mfa-on' : 'mfa-off') }, u.mfa_enabled ? 'Enabled' : 'Not enrolled')),
        h('td', {}, status),
        h('td', {}, select),
        h('td', {}, actions));
}

async function loadDirectory() {
    const tbody = $('directory-table-body');
    const { res, data } = await api('/api/admin/users');
    if (res.status === 401) return logout(EXPIRED);
    if (!res.ok) {
        tbody.replaceChildren(h('tr', {}, h('td', { colspan: 6, class: 'empty', style: { color: 'var(--red-d)', fontWeight: '600' } },
            `${res.status} Forbidden: ${errText(data, 'Insufficient Admin Privileges')}`)));
        return;
    }
    tbody.replaceChildren(...data.map((u, i) => directoryRow(u, i)));
    if (data.length === 1 && data[0].is_self) {
        tbody.append(h('tr', {}, h('td', { colspan: 6, class: 'empty' },
            'Only your account exists so far. People who sign up will show up here.')));
    }
}

/* ---------- wiring (no inline handlers anywhere in the HTML) ---------- */
function onEnter(id, fn) { $(id).addEventListener('keydown', e => { if (e.key === 'Enter') fn(); }); }

$('btn-login').addEventListener('click', login);
['log-username', 'log-password', 'log-totp'].forEach(id => onEnter(id, login));
$('link-register').addEventListener('click', () => toggleAuthMode('register'));
$('link-login').addEventListener('click', () => toggleAuthMode('login'));
$('btn-register').addEventListener('click', register);
$('reg-password').addEventListener('input', checkPasswordStrength);

$('btn-mfa-start').addEventListener('click', startMfaOnboarding);
$('btn-mfa-finish').addEventListener('click', finishMfaOnboarding);
onEnter('mfa-code', finishMfaOnboarding);
$('mfa-cancel').addEventListener('click', () => logout());

$('nav-overview').addEventListener('click', () => switchTab('overview'));
$('nav-directory').addEventListener('click', () => switchTab('directory'));
$('btn-logout').addEventListener('click', () => logout());
$('btn-test-user').addEventListener('click', () => testAccess('/api/user-data'));
$('btn-test-admin').addEventListener('click', () => testAccess('/api/admin-data'));
$('audit-refresh').addEventListener('click', fetchAuditLogs);
$('verify-btn').addEventListener('click', verifyAudit);
$('audit-prev').addEventListener('click', () => { auditOffset = Math.max(0, auditOffset - PAGE); fetchAuditLogs(); });
$('audit-next').addEventListener('click', () => { auditOffset += PAGE; fetchAuditLogs(); });
$('dir-refresh').addEventListener('click', loadDirectory);

