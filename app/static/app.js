'use strict';
// All user-controlled text is inserted with textContent (never innerHTML) -> no stored XSS.
const $app = document.getElementById('app');
let csrf = null, me = null, view = 'docs', toast = '';

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v; else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
async function api(method, path, data, isForm) {
  const opt = { method, headers: {}, credentials: 'same-origin' };
  if (csrf) opt.headers['X-CSRF-Token'] = csrf;
  if (data && isForm) opt.body = data;
  else if (data) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(data); }
  const r = await fetch('/api' + path, opt);
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) { const e = new Error(j.error || r.statusText); e.status = r.status; throw e; }
  return j;
}
const say = (m, bad) => { toast = bad ? '!' + m : m; const t = document.getElementById('toast'); if (t) { t.textContent = m; t.className = bad ? 'err' : 'ok'; } };
const fmt = s => s ? s.replace('T', ' ').replace(/\.\d+Z$|Z$/, ' UTC') : '';
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { say(e.message, true); if (e.status === 401) { me = null; csrf = null; render(); } } };

async function boot() { const j = await api('GET', '/me'); me = j.user; csrf = j.csrf; render(); }

function render() {
  $app.replaceChildren(me ? shell() : loginView());
  if (me) ({ docs: docsView, trash: docsView, users: usersView, adocs: adminDocsView, audit: auditView, alerts: alertsView }[view] || docsView)();
}
function loginView() {
  const u = el('input', { placeholder: 'username', autocomplete: 'username' });
  const p = el('input', { type: 'password', placeholder: 'password', autocomplete: 'current-password' });
  const msg = el('div', { class: 'err', id: 'toast' });
  const go = guard(async () => { const j = await api('POST', '/login', { username: u.value, password: p.value }); me = j.user; csrf = j.csrf; view = me.role === 'admin' ? 'users' : 'docs'; render(); });
  p.addEventListener('keydown', e => e.key === 'Enter' && go().catch(() => {}));
  return el('main', {}, el('div', { class: 'card' }, el('h1', {}, 'TrustVault'), el('p', { class: 'mut' }, 'Secure document sharing with a verifiable audit trail.'),
    el('div', { class: 'row' }, u, p, el('button', { class: 'p', onclick: go }, 'Sign in')), msg));
}
function shell() {
  const tabs = me.role === 'admin' ? [['users', 'Users'], ['adocs', 'Documents (metadata)'], ['audit', 'Audit'], ['alerts', 'Alerts']]
    : [['docs', 'Documents'], ['trash', 'Trash']];
  return el('div', {}, el('header', {}, el('h1', {}, 'TrustVault'),
    el('nav', {}, tabs.map(([k, l]) => el('button', { class: view === k ? 'on' : '', onclick: () => { view = k; render(); } }, l))),
    el('span', { class: 'mut' }, `${me.display_name} (${me.role})`),
    el('button', { onclick: guard(async () => { await api('POST', '/logout'); me = csrf = null; render(); }) }, 'Sign out')),
    el('main', {}, el('div', { id: 'toast' }), el('div', { id: 'view' })));
}
const V = () => document.getElementById('view');

// ---------- documents
function docsView() {
  const f = {};
  const mk = (k, ph, type) => (f[k] = el('input', { placeholder: ph, type: type || 'text' }));
  const list = el('div');
  const search = guard(async () => {
    const q = new URLSearchParams(); if (view === 'trash') q.set('scope', 'trash');
    for (const [k, i] of Object.entries(f)) if (i.value) q.set(k, i.value);
    const j = await api('GET', '/documents?' + q);
    list.replaceChildren(j.documents.length ? el('table', {}, el('thead', {}, el('tr', {}, ['Name', 'Owner', 'Category', 'Updated', 'Access', ''].map(h => el('th', {}, h)))),
      el('tbody', {}, j.documents.map(d => el('tr', {}, el('td', {}, d.name), el('td', {}, d.owner.name), el('td', {}, d.category), el('td', {}, fmt(d.updated_at)),
        el('td', {}, el('span', { class: 'tag' }, d.my_access)),
        el('td', {}, view === 'trash' ? el('button', { onclick: guard(async () => { await api('POST', `/documents/${d.id}/restore`); say('Restored'); search(); }) }, 'Restore')
          : el('button', { onclick: () => openDoc(d.id) }, 'Open'))))))
      : el('p', { class: 'mut' }, 'No documents.'));
  });
  V().replaceChildren(
    el('div', { class: 'card' }, el('div', { class: 'row' }, mk('q', 'name'), mk('owner', 'owner'), mk('category', 'category'),
      el('label', { class: 'mut' }, 'from ', mk('from', '', 'date')), el('label', { class: 'mut' }, 'to ', mk('to', '', 'date')),
      el('button', { class: 'p', onclick: search }, 'Search'))),
    me.role === 'owner' && view === 'docs' ? uploadCard(search) : null, list, el('div', { id: 'detail' }));
  search();
}
function uploadCard(after) {
  const file = el('input', { type: 'file' }), name = el('input', { placeholder: 'title (optional)' }), cat = el('input', { placeholder: 'category' }), desc = el('input', { placeholder: 'description' });
  return el('div', { class: 'card' }, el('b', {}, 'Upload a document'), el('div', { class: 'row' }, file, name, cat, desc,
    el('button', { class: 'p', onclick: guard(async () => {
      const fd = new FormData(); if (!file.files[0]) throw new Error('choose a file');
      fd.append('file', file.files[0]); fd.append('name', name.value); fd.append('category', cat.value); fd.append('description', desc.value);
      await api('POST', '/documents', fd, true); say('Uploaded'); file.value = name.value = cat.value = desc.value = ''; after();
    }) }, 'Upload')), el('div', { class: 'mut' }, 'pdf, png, jpg, txt, csv, docx, xlsx, pptx - max 10 MB'));
}
async function openDoc(id) {
  const box = document.getElementById('detail');
  try {
    const d = await api('GET', '/documents/' + id), isOwner = d.my_access === 'owner', canEdit = d.my_access !== 'read';
    const name = el('input', { value: d.name }), cat = el('input', { value: d.category }), desc = el('input', { value: d.description });
    const vf = el('input', { type: 'file' });
    const parts = [el('h3', {}, d.name), el('div', { class: 'mut' }, `Owner ${d.owner.name} - your access: ${d.my_access}`),
      el('table', {}, el('thead', {}, el('tr', {}, ['Version', 'File', 'Size', 'SHA-256', 'By', 'When', ''].map(h => el('th', {}, h)))),
        el('tbody', {}, d.versions.map(v => el('tr', {}, el('td', {}, 'v' + v.version_no), el('td', {}, v.original_filename), el('td', {}, v.size),
          el('td', {}, el('pre', {}, v.sha256.slice(0, 16) + '...')), el('td', {}, v.by), el('td', {}, fmt(v.created_at)),
          el('td', {}, el('a', { href: `/api/documents/${d.id}/download?version=${v.version_no}` }, 'Download'))))))];
    if (canEdit) parts.push(el('div', { class: 'row' }, name, cat, desc, el('button', { onclick: guard(async () => { await api('PATCH', '/documents/' + id, { name: name.value, category: cat.value, description: desc.value }); say('Saved'); openDoc(id); }) }, 'Save details')),
      el('div', { class: 'row' }, vf, el('button', { onclick: guard(async () => { const fd = new FormData(); if (!vf.files[0]) throw new Error('choose a file'); fd.append('file', vf.files[0]); await api('POST', `/documents/${id}/versions`, fd, true); say('New version uploaded'); openDoc(id); }) }, 'Upload new version')));
    if (isOwner) parts.push(el('div', { id: 'grants' }), el('div', { id: 'docaudit' }),
      el('div', { class: 'row' }, el('button', { class: 'd', onclick: guard(async () => { if (confirm('Move to trash?')) { await api('DELETE', '/documents/' + id); say('Moved to trash'); render(); } }) }, 'Delete')));
    box.replaceChildren(el('div', { class: 'card' }, parts));
    if (isOwner) { grantsPanel(id); docAudit(id); }
    box.scrollIntoView();
  } catch (e) { say(e.message, true); }
}
async function grantsPanel(id) {
  const host = document.getElementById('grants'), j = await api('GET', `/documents/${id}/grants`);
  const u = el('input', { placeholder: 'username' }), lvl = el('select', {}, el('option', { value: 'read' }, 'read'), el('option', { value: 'edit' }, 'edit'));
  const exp = el('input', { type: 'datetime-local', title: 'optional expiry' });
  const sugBox = el('div'); let sid = null;
  const grant = guard(async () => { await api('PUT', `/documents/${id}/grants`, { username: u.value, level: lvl.value, expires_at: exp.value ? new Date(exp.value).toISOString() : null, suggestion_id: sid }); say('Access granted'); grantsPanel(id); docAudit(id); });
  host.replaceChildren(el('h4', {}, 'Who has access'),
    j.grants.length ? el('table', {}, el('tbody', {}, j.grants.map(g => el('tr', {}, el('td', {}, `${g.display_name} (${g.username})`), el('td', {}, g.level),
      el('td', { class: 'mut' }, g.expires_at ? 'expires ' + fmt(g.expires_at) : 'no expiry'), el('td', {}, g.suggestion_id ? el('span', { class: 'tag' }, 'suggested, you confirmed') : ''),
      el('td', {}, el('button', { class: 'd', onclick: guard(async () => { await api('DELETE', `/documents/${id}/grants/${g.user_id}`); say('Access revoked'); grantsPanel(id); docAudit(id); }) }, 'Revoke')))))) : el('p', { class: 'mut' }, 'Only you.'),
    el('div', { class: 'row' }, u, lvl, exp, el('button', { class: 'p', onclick: grant }, 'Grant access'),
      el('button', { onclick: guard(async () => { const s = await api('GET', `/documents/${id}/suggestions`); sugBox.replaceChildren(s.suggestions.length ? s.suggestions.map(x => el('div', { class: 'row' }, el('span', {}, `${x.display_name}: ${x.reason}`), el('button', { onclick: () => { u.value = x.username; sid = x.suggestion_id; say('Suggestion loaded - review the level, then press Grant access to confirm.'); } }, 'Use'))) : el('span', { class: 'mut' }, 'No suggestions.')); }) }, 'Suggest people')), sugBox,
    el('div', { class: 'mut' }, 'Suggestions are advice only (a simple heuristic, not an AI model). Nothing is shared until you press Grant access.'));
}
async function docAudit(id) {
  const j = await api('GET', `/documents/${id}/audit`);
  document.getElementById('docaudit').replaceChildren(el('h4', {}, 'Activity on this document (including refused attempts)'), evTable(j.events));
}
function evTable(ev) {
  return el('table', {}, el('thead', {}, el('tr', {}, ['#', 'When', 'Who', 'Action', 'Result', 'Detail'].map(h => el('th', {}, h)))),
    el('tbody', {}, ev.map(e => el('tr', {}, el('td', {}, e.seq), el('td', {}, fmt(e.ts)), el('td', {}, e.actor_name || '-'), el('td', {}, e.action), el('td', { class: e.outcome }, e.outcome), el('td', {}, el('pre', {}, e.detail))))));
}

// ---------- admin
async function usersView() {
  const j = await api('GET', '/admin/users');
  const f = { username: el('input', { placeholder: 'username' }), display_name: el('input', { placeholder: 'full name' }), password: el('input', { type: 'password', placeholder: 'password (10+)' }),
    role: el('select', {}, ['viewer', 'owner', 'admin'].map(r => el('option', { value: r }, r))) };
  V().replaceChildren(el('div', { class: 'card' }, el('b', {}, 'Create user'), el('div', { class: 'row' }, Object.values(f),
    el('button', { class: 'p', onclick: guard(async () => { await api('POST', '/admin/users', Object.fromEntries(Object.entries(f).map(([k, i]) => [k, i.value]))); say('User created'); usersView(); }) }, 'Create'))),
    el('div', { class: 'card' }, el('table', {}, el('thead', {}, el('tr', {}, ['User', 'Role', 'Status', ''].map(h => el('th', {}, h)))),
      el('tbody', {}, j.users.map(u => el('tr', {}, el('td', {}, `${u.display_name} (${u.username})`), el('td', {}, u.role), el('td', {}, u.active ? 'active' : 'disabled'),
        el('td', {}, u.id === me.id ? '' : el('button', { class: u.active ? 'd' : '', onclick: guard(async () => { await api('POST', `/admin/users/${u.id}/${u.active ? 'disable' : 'enable'}`); say(u.active ? 'Disabled; sessions revoked' : 'Enabled'); usersView(); }) }, u.active ? 'Disable' : 'Enable'))))))));
}
async function adminDocsView() {
  const j = await api('GET', '/admin/documents');
  V().replaceChildren(el('div', { class: 'card' }, el('p', { class: 'mut' }, 'Metadata only. Administrators cannot open document contents.'),
    el('table', {}, el('thead', {}, el('tr', {}, ['ID', 'Name', 'Owner', 'Category', 'Grants', 'Last activity', ''].map(h => el('th', {}, h)))),
      el('tbody', {}, j.documents.map(d => el('tr', {}, el('td', {}, d.id), el('td', {}, d.name), el('td', {}, d.owner), el('td', {}, d.category), el('td', {}, d.grant_count), el('td', {}, fmt(d.last_activity)), el('td', {}, d.deleted_at ? 'deleted' : '')))))));
}
async function auditView() {
  const sel = el('select', {}, [['', 'All events'], ['permission.', 'Permission changes'], ['document.', 'Document activity'], ['auth.', 'Logins']].map(([v, l]) => el('option', { value: v }, l)));
  const out = el('div'), ver = el('div');
  const load = guard(async () => { const j = await api('GET', '/admin/audit?limit=200' + (sel.value ? '&prefix=' + encodeURIComponent(sel.value) : '')); out.replaceChildren(evTable(j.events)); });
  sel.addEventListener('change', load);
  V().replaceChildren(el('div', { class: 'card' }, el('div', { class: 'row' }, sel,
    el('button', { onclick: guard(async () => { const v = await api('GET', '/admin/audit/verify'); ver.replaceChildren(el('b', { class: v.ok ? 'ok' : 'err' }, v.ok ? `Chain intact: ${v.checked} records verified. Head #${v.head && v.head.seq} ${v.head ? v.head.hash.slice(0, 16) : ''}...` : `TAMPERING DETECTED at record #${v.first_bad_seq}`)); }) }, 'Verify integrity')), ver, out));
  load();
}
async function alertsView() {
  const j = await api('GET', '/admin/alerts');
  V().replaceChildren(el('div', { class: 'card' }, j.alerts.length ? el('table', {}, el('tbody', {}, j.alerts.map(a => el('tr', {}, el('td', { class: a.severity === 'high' ? 'err' : '' }, a.severity), el('td', {}, a.message))))) : el('p', { class: 'ok' }, 'Nothing needs attention.')));
}
boot().catch(e => { $app.textContent = 'Failed to load: ' + e.message; });
