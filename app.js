const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const api = async (url, opt = {}) => { const r = await fetch(url, opt); const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || 'Kuch galat hua'); return d; };
const post = (url, body) => api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
const toast = m => { const t = $('#toast'); t.textContent = m; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2800); };
let me = null, mode = 'login';

async function init() { try { me = await api('/api/me'); } catch { me = null; } render(); }
function render() {
  $('#auth').hidden = !!me; $('#app').hidden = !me; $('#logout').hidden = !me;
  $('#who').textContent = me ? `${me.name} (ID: ${me.uid})` : '';
  if (me) tab('mine');
}
$('#switch').onclick = e => {
  e.preventDefault(); mode = mode === 'login' ? 'register' : 'login';
  $('#name').hidden = mode === 'login';
  $('#authBtn').textContent = mode === 'login' ? 'Login' : 'Account banayein';
  $('#switch').textContent = mode === 'login' ? 'Naya account banayein' : 'Pehle se account hai? Login karein';
};
$('#authForm').onsubmit = async e => {
  e.preventDefault();
  try {
    const d = await post('/api/' + mode, { name: $('#name').value, email: $('#email').value, password: $('#pass').value });
    if (mode === 'register') { toast(d.message); $('#switch').click(); } else { me = d; render(); }
  } catch (x) { toast(x.message); }
};
$('#logout').onclick = async () => { await post('/api/logout'); me = null; render(); };

document.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => tab(b.dataset.tab));
function tab(t) {
  document.querySelectorAll('.pane').forEach(p => p.hidden = p.id !== 'p-' + t);
  document.querySelectorAll('[data-tab]').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  ({ mine: loadMine, find: search, req: loadReq })[t]();
}

const cardHTML = (a, del) => `<div class="card">
  ${a.has_photo ? `<img class="pic" src="/api/photo/${a.id}" alt="${esc(a.name)}">` : `<div class="pic">${esc(a.name[0])}</div>`}
  <div class="info"><b>${esc(a.name)}</b><small>${esc(a.relation)}</small>
  ${del ? `<button class="warn" data-del="${a.id}">Hatayein</button>` : ''}</div></div>`;
// parent_id ke hisaab se nested tree (sabse purane ancestor upar)
function treeHTML(list, del) {
  const ids = new Set(list.map(x => x.id)), kids = {};
  list.forEach(x => { const p = ids.has(x.parent_id) ? x.parent_id : 0; (kids[p] ||= []).push(x); });
  const walk = p => kids[p] ? `<ul>${kids[p].map(x => `<li>${cardHTML(x, del)}${walk(x.id)}</li>`).join('')}</ul>` : '';
  return walk(0);
}

async function loadMine() {
  const list = await api('/api/ancestors/' + me.uid);
  $('#count').textContent = `${list.length} ancestors jode gaye hain`;
  $('#parentSel').innerHTML = '<option value="">Sabse upar (sabse purane ancestor)</option>' + list.map(x => `<option value="${x.id}">${esc(x.name)} ke neeche</option>`).join('');
  $('#mineGrid').innerHTML = list.length ? treeHTML(list, true) : '<p>Abhi koi ancestor nahi. Upar se pehla naam jodein.</p>';
}
$('#addForm').onsubmit = async e => {
  e.preventDefault();
  try { await api('/api/ancestors', { method: 'POST', body: new FormData(e.target) }); e.target.reset(); loadMine(); toast('Ancestor jod diya gaya'); }
  catch (x) { toast(x.message); }
};

async function search() {
  const list = await api('/api/users?q=' + encodeURIComponent($('#q').value));
  const btn = u => ({
    accepted: `<button data-view="${u.uid}" data-name="${esc(u.name)}">Parivaar dekhein</button>`,
    pending: '<button class="ghost" disabled>Request pending</button>',
    rejected: '<button class="ghost" disabled>Request reject hui</button>'
  }[u.status] || `<button data-ask="${u.uid}">Request bhejein</button>`);
  $('#results').innerHTML = list.map(u => `<div class="item"><span><b>${esc(u.name)}</b> &nbsp; ID: ${esc(u.uid)}</span>${btn(u)}</div>`).join('') || '<p>Koi user nahi mila.</p>';
}
$('#go').onclick = search;

async function loadReq() {
  const list = await api('/api/requests');
  $('#reqList').innerHTML = list.map(r => `<div class="item"><span><b>${esc(r.name)}</b> (${esc(r.uid)}) aapka parivaar dekhna chahta hai</span>
    <span><button data-acc="${r.id}">Accept</button> <button class="warn" data-rej="${r.id}">Reject</button></span></div>`).join('') || '<p>Koi nayi request nahi.</p>';
}

document.addEventListener('click', async e => {
  const d = e.target.dataset; if (!d) return;
  try {
    if (d.del) { await api('/api/ancestors/' + d.del, { method: 'DELETE' }); loadMine(); }
    if (d.ask) { await post('/api/request/' + d.ask); toast('Request bhej di gayi'); search(); }
    if (d.acc || d.rej) { await post(`/api/requests/${d.acc || d.rej}/${d.acc ? 'accept' : 'reject'}`); loadReq(); }
    if (d.view) {
      const list = await api('/api/ancestors/' + d.view);
      $('#viewer').innerHTML = `<h3>${esc(d.name)} ka parivaar</h3><div class="tree">${treeHTML(list, false) || '<p>Abhi kuch nahi joda gaya.</p>'}</div>`;
      $('#viewer').scrollIntoView({ behavior: 'smooth' });
    }
  } catch (x) { toast(x.message); }
});
$('#forgot').onclick = async e => {
  e.preventDefault();
  const email = $('#email').value; if (!email) return toast('Pehle upar email likhein');
  try { toast((await post('/api/forgot', { email })).message); } catch (x) { toast(x.message); }
};
const params = new URLSearchParams(location.search), resetTok = params.get('reset');
if (params.get('verified')) toast(params.get('verified') === '1' ? 'Email verify ho gaya. Ab login karein.' : 'Verify link galat hai');
if (resetTok) { $('#authForm').hidden = true; $('#gbtn').hidden = true; $('#resetForm').hidden = false; }
$('#resetForm').onsubmit = async e => {
  e.preventDefault();
  try { await post('/api/reset', { token: resetTok, password: $('#np').value }); history.replaceState({}, '', '/'); location.reload(); }
  catch (x) { toast(x.message); }
};
window.addEventListener('load', async () => {   // Google Sign-In button
  try {
    const { googleClientId } = await api('/api/config');
    if (!googleClientId || !window.google) return;
    google.accounts.id.initialize({ client_id: googleClientId, callback: async r => {
      try { me = await post('/api/google', { credential: r.credential }); render(); } catch (x) { toast(x.message); } } });
    google.accounts.id.renderButton($('#gbtn'), { theme: 'outline', size: 'large', text: 'continue_with', width: 280 });
  } catch {}
});
init();
