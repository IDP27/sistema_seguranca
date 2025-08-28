// =====================
// Config & Estado
// =====================
let API_BASE = 'http://127.0.0.1:8005';
let authToken = null;
let currentUser = null;

// paginação recursos
let resPage = 1;
const resSize = 10;

// paginação usuários
let usersPage = 1;
const usersSize = 10;

// helpers DOM
const $  = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// =====================
// Boot
// =====================
document.addEventListener('DOMContentLoaded', () => {
  // listeners
  bindGlobalListeners();

  // token salvo?
  const saved = localStorage.getItem('authToken');
  const savedApi = localStorage.getItem('apiBase');
  if (savedApi) {
    API_BASE = savedApi;
    const apiInput = $('#api-base');
    if (apiInput) apiInput.value = savedApi;
  }
  if (saved) {
    authToken = saved;
    fetchCurrentUser();
  }
});

// =====================
// Listeners
// =====================
function bindGlobalListeners(){
  // login
  $('#login-btn').addEventListener('click', doLogin);

  // sidebar
  $('#sidebar-toggle').addEventListener('click', () => {
    $('#sidebar').classList.toggle('collapsed');
  });

  // navegação
  $$('.nav-link').forEach(a=>{
    a.addEventListener('click', (e)=>{
      e.preventDefault();
      const sec = a.getAttribute('data-section');
      showSection(sec);
    });
  });

  // logout
  $('#logout-btn').addEventListener('click', () => {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showLogin();
  });

  // acesso
  $('#access-area-btn').addEventListener('click', handleAreaAccess);

  // recursos
  $('#apply-filters').addEventListener('click', () => { resPage = 1; loadResources(); });
  $('#add-resource-btn').addEventListener('click', ()=> openResourceModal());
  $('#resource-form').addEventListener('submit', handleResourceSubmit);
  $('#prev-page').addEventListener('click', () => { if(resPage>1){resPage--; loadResources();} });
  $('#next-page').addEventListener('click', () => { resPage++; loadResources(); });

  // logs
  $('#apply-log-filters').addEventListener('click', loadLogs);

  // usuários
  $('#apply-user-filters').addEventListener('click', ()=>{ usersPage=1; loadUsers(); });
  $('#add-user-btn').addEventListener('click', ()=> openUserModal());
  $('#user-form').addEventListener('submit', handleUserSubmit);
  $('#users-prev').addEventListener('click', ()=>{ if(usersPage>1){usersPage--; loadUsers();} });
  $('#users-next').addEventListener('click', ()=>{ usersPage++; loadUsers(); });

  // fechar modais
  $$('[data-close]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const id = btn.getAttribute('data-close');
      closeModal(id);
    });
  });
  $$('.close').forEach(x=>{
    x.addEventListener('click', ()=>{
      closeModal(x.getAttribute('data-close') || x.closest('.modal').id);
    });
  });
  window.addEventListener('click', (e)=>{
    if (e.target.classList.contains('modal')) e.target.style.display='none';
  });

  // cards clicáveis
  const cardAccesses = $('#card-accesses');
  const cardActiveUsers = $('#card-active-users');
  const cardTotalResources = $('#card-total-resources');
  if (cardAccesses) cardAccesses.addEventListener('click', ()=> showSection('logs'));
  if (cardActiveUsers) cardActiveUsers.addEventListener('click', ()=> showSection('users'));
  if (cardTotalResources) cardTotalResources.addEventListener('click', ()=> showSection('resources'));
}

// =====================
// Auth
// =====================
async function doLogin(){
  const u = $('#username').value.trim();
  const p = $('#password').value;
  const base = ($('#api-base').value || '').replace(/\/+$/,'');
  API_BASE = base || API_BASE;
  localStorage.setItem('apiBase', API_BASE);

  $('#login-error').textContent = '';

  try{
    const res = await fetch(`${API_BASE}/auth/login`, {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ username:u, password:p })
    });

    if (!res.ok){
      const err = await safeJson(res);
      $('#login-error').textContent = err?.detail || 'Credenciais inválidas';
      return;
    }

    const data = await res.json();
    authToken = data.access_token;
    localStorage.setItem('authToken', authToken);
    await fetchCurrentUser();
  }catch(e){
    $('#login-error').textContent = 'Erro de conexão. Verifique a API.';
  }
}

async function fetchCurrentUser(){
  try{
    const me = await authed(`${API_BASE}/users/me`);
    if (!me.ok){
      showLogin();
      return;
    }
    currentUser = await me.json();
    showDashboard();

    // UI conforme role
    const isAdmin   = currentUser.role === 'SECURITY_ADMIN';
    const isManager = isAdmin || currentUser.role === 'MANAGER';
    $('#logs-menu-item').style.display   = isAdmin ? 'block' : 'none';
    $('#users-menu-item').style.display  = isAdmin ? 'block' : 'none';
    $('#quick-logs-btn').style.display   = isAdmin ? 'block' : 'none';
    $('#add-resource-btn').style.display = isManager ? 'inline-block' : 'none';
    $('#clear-logs-btn').style.display   = isAdmin ? 'inline-block' : 'none';

    // Dados iniciais
    await loadOverview();
    await loadAllowedAreas();
    await loadResources();
  }catch(e){
    showLogin();
  }
}

function showLogin(){
  $('#login-screen').classList.add('active');
  $('#dashboard').classList.remove('active');
}

function showDashboard(){
  $('#login-screen').classList.remove('active');
  $('#dashboard').classList.add('active');
  $('#username-display').textContent = currentUser.username;
  $('#user-role').textContent = currentUser.role;
}

function showSection(id){
  $$('.content-section').forEach(s=>s.classList.remove('active'));
  $(`#${id}`).classList.add('active');
  $$('.nav-link').forEach(a=>{
    a.classList.toggle('active', a.getAttribute('data-section')===id);
  });
  // carregamentos sob demanda
  if (id==='logs') loadLogs();
  if (id==='users') loadUsers();
}

// =====================
// Utils
// =====================
function authed(url, options={}){
  const headers = {
    'Authorization': `Bearer ${authToken}`,
    ...(options.headers || {})
  };
  return fetch(url, { ...options, headers });
}

async function authenticatedFetch(url, options={}){
  return authed(url, options);
}

async function safeJson(res){
  try{ return await res.json(); }catch(_){ return null; }
}

function openModal(id){ $(`#${id}`).style.display='block'; }
function closeModal(id){ $(`#${id}`).style.display='none'; }

// =====================
// Overview / Cards
// =====================
async function loadOverview(){
  try{
    const res = await authed(`${API_BASE}/stats/overview`);
    if (!res.ok) return;
    const data = await res.json();
    $('#access-today').textContent   = data.accesses_today ?? 0;
    $('#active-users').textContent   = data.active_users_24h ?? 0;
    $('#total-resources').textContent= data.total_resources ?? 0;
  }catch(_){}
}

// =====================
// Controle de Acesso
// =====================
async function loadAllowedAreas(){
  try{
    const r = await authed(`${API_BASE}/areas/allowed`);
    if (!r.ok) return;
    const areas = await r.json();
    const sel = $('#area-select');
    sel.innerHTML = '<option value="">Selecione uma área</option>';

    const base = (areas.includes('*'))
      ? ['recepcao','escritorio1','gerencia','sala_reuniao']
      : areas;

    base.forEach(a=>{
      const op = document.createElement('option');
      op.value = a; op.textContent = a;
      sel.appendChild(op);
    });
  }catch(_){}
}

async function handleAreaAccess(){
  const area = $('#area-select').value;
  if (!area) { alert('Selecione uma área.'); return; }

  const resDiv = $('#access-result-content');
  try{
    const res = await authed(`${API_BASE}/areas/${encodeURIComponent(area)}/enter`, { method:'POST' });
    if (res.ok){
      const log = await res.json();
      resDiv.innerHTML = `
        <div style="text-align:center">
          <i class="fas fa-check-circle" style="font-size:48px;color:var(--success-color)"></i>
          <h4>Acesso Permitido</h4>
          <p>Área: <b>${log.area}</b></p>
          <p>${new Date(log.timestamp).toLocaleString()}</p>
        </div>`;
      await loadOverview();
    }else{
      const err = await safeJson(res);
      resDiv.innerHTML = `
        <div style="text-align:center">
          <i class="fas fa-times-circle" style="font-size:48px;color:var(--danger-color)"></i>
          <h4>Acesso Negado</h4>
          <p>${err?.detail || 'Sem permissão'}</p>
        </div>`;
    }
  }catch(_){}
}

// =====================
// Recursos
// =====================
async function loadResources(){
  const q = $('#resource-search').value.trim();
  const cat = $('#resource-category').value.trim();
  const loc = $('#resource-location').value.trim();

  const params = new URLSearchParams({ page:String(resPage), size:String(resSize), sort:'name' });
  if (q) params.set('q', q);
  if (cat) params.set('category', cat);
  if (loc) params.set('location', loc);

  try{
    const r = await authed(`${API_BASE}/resources?${params.toString()}`);
    if (!r.ok) return;
    const data = await r.json();
    renderResources(data);
  }catch(_){}
}

function renderResources(list){
  const tbody = $('#resources-tbody');
  tbody.innerHTML = '';
  (list.items||[]).forEach(it=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${it.name}</td>
      <td>${it.category}</td>
      <td>${it.quantity}</td>
      <td>${it.location || '-'}</td>
      <td>
        <button class="btn-icon-table" data-edit="${it.id}"><i class="fas fa-edit"></i></button>
        <button class="btn-icon-table" data-del="${it.id}"><i class="fas fa-trash"></i></button>
      </td>`;
    tbody.appendChild(tr);
  });

  // paginação
  const pages = Math.max(1, Math.ceil((list.total||0) / (list.size||resSize)));
  $('#page-info').textContent = `Página ${list.page} de ${pages}`;
  $('#prev-page').disabled = list.page<=1;
  $('#next-page').disabled = list.page>=pages;

  // ações
  tbody.querySelectorAll('[data-edit]').forEach(btn=>{
    btn.addEventListener('click', ()=> editResource(btn.getAttribute('data-edit')));
  });
  tbody.querySelectorAll('[data-del]').forEach(btn=>{
    btn.addEventListener('click', ()=> deleteResource(btn.getAttribute('data-del')));
  });
}

function openResourceModal(resource=null){
  $('#resource-modal-title').textContent = resource ? 'Editar Recurso' : 'Adicionar Recurso';
  $('#resource-id').value = resource?.id || '';
  $('#resource-name').value = resource?.name || '';
  $('#resource-category-modal').value = resource?.category || '';
  $('#resource-quantity').value = resource?.quantity ?? 1;
  $('#resource-location-modal').value = resource?.location || '';
  $('#resource-description').value = resource?.description || '';
  openModal('resource-modal');
}

async function editResource(id){
  const r = await authed(`${API_BASE}/resources/${id}`);
  if (!r.ok) return;
  const resource = await r.json();
  openResourceModal(resource);
}

async function handleResourceSubmit(e){
  e.preventDefault();
  const id = $('#resource-id').value;
  const payload = {
    name: $('#resource-name').value.trim(),
    category: $('#resource-category-modal').value.trim(),
    quantity: Number($('#resource-quantity').value || 0),
    location: $('#resource-location-modal').value.trim() || null,
    description: $('#resource-description').value.trim() || null,
  };

  const isEdit = !!id;
  const url = isEdit ? `${API_BASE}/resources/${id}` : `${API_BASE}/resources`;
  const method = isEdit ? 'PUT' : 'POST';

  const res = await authed(url, {
    method,
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify(payload)
  });

  if (!res.ok){
    const err = await safeJson(res);
    alert(err?.detail || 'Falha ao salvar.');
    return;
  }
  closeModal('resource-modal');
  await loadResources();
  await loadOverview();
}

async function deleteResource(id){
  if (!confirm(`Apagar recurso #${id}?`)) return;
  const r = await authed(`${API_BASE}/resources/${id}`, { method:'DELETE' });
  if (!r.ok){
    const err = await safeJson(r);
    alert(err?.detail || 'Falha ao deletar.');
    return;
  }
  await loadResources();
  await loadOverview();
}

// =====================
// Logs
// =====================
async function loadLogs(){
  const u = $('#log-user').value.trim();
  const a = $('#log-area').value.trim();
  const s = $('#log-status').value;

  const params = new URLSearchParams({ limit:'100' });
  if (u) params.set('user_id', u);
  if (a) params.set('area', a);
  if (s) params.set('allowed', s);

  const r = await authed(`${API_BASE}/logs?${params.toString()}`);
  if (!r.ok) return;
  const logs = await r.json();

  const tbody = $('#logs-tbody');
  tbody.innerHTML = '';
  logs.forEach(l=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${l.user_id}</td>
      <td>${l.area}</td>
      <td>${new Date(l.timestamp).toLocaleString()}</td>
      <td>${l.allowed ? '<span style="color:var(--success-color)">Permitido</span>' :
                         '<span style="color:var(--danger-color)">Negado</span>'}</td>
      <td>${l.reason || '-'}</td>`;
    tbody.appendChild(tr);
  });
}

// =====================
// Usuários (ADMIN)
// =====================
async function loadUsers(){
  const q = $('#user-search').value.trim();
  const role = $('#user-role-filter').value;

  const params = new URLSearchParams({ page:String(usersPage), size:String(usersSize), sort:'username' });
  if (q) params.set('q', q);
  if (role) params.set('role', role);

  const r = await authed(`${API_BASE}/users?${params.toString()}`);
  if (!r.ok) { 
    // exibe vazio se não for admin
    $('#users-tbody').innerHTML = '<tr><td colspan="4" style="text-align:center">Sem permissão ou nenhum dado.</td></tr>';
    return;
  }
  const data = await r.json();

  const tbody = $('#users-tbody');
  tbody.innerHTML = '';
  (data.items||[]).forEach(u=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${u.id}</td>
      <td>${u.username}</td>
      <td>${u.role}</td>
      <td>
        <button class="btn-icon-table" data-uedit="${u.id}"><i class="fas fa-edit"></i></button>
        <button class="btn-icon-table" data-udel="${u.id}"><i class="fas fa-trash"></i></button>
      </td>`;
    tbody.appendChild(tr);
  });

  const pages = Math.max(1, Math.ceil((data.total||0) / (data.size||usersSize)));
  $('#users-page-info').textContent = `Página ${data.page} de ${pages}`;
  $('#users-prev').disabled = data.page<=1;
  $('#users-next').disabled = data.page>=pages;

  tbody.querySelectorAll('[data-uedit]').forEach(btn=>{
    btn.addEventListener('click', ()=> openUserEdit(btn.getAttribute('data-uedit')));
  });
  tbody.querySelectorAll('[data-udel]').forEach(btn=>{
    btn.addEventListener('click', ()=> deleteUser(btn.getAttribute('data-udel')));
  });
}

function openUserModal(){
  $('#user-modal-title').textContent = 'Novo Usuário';
  $('#user-id').value = '';
  $('#new-username').value = '';
  $('#new-password').value = '';
  $('#new-role').value = 'EMPLOYEE';
  openModal('user-modal');
}

async function openUserEdit(id){
  const r = await authed(`${API_BASE}/users/${id}`);
  if (!r.ok) return;
  const u = await r.json();
  $('#user-modal-title').textContent = `Editar Usuário #${u.id}`;
  $('#user-id').value = u.id;
  $('#new-username').value = u.username;
  $('#new-password').value = ''; // opcional
  $('#new-role').value = u.role;
  openModal('user-modal');
}

async function handleUserSubmit(e){
  e.preventDefault();
  const id = $('#user-id').value;
  const isEdit = !!id;

  const payload = {
    username: $('#new-username').value.trim(),
    password: $('#new-password').value.trim() || undefined, // em update pode ficar vazio
    role: $('#new-role').value
  };

  const url = isEdit ? `${API_BASE}/users/${id}` : `${API_BASE}/auth/register`;
  const method = isEdit ? 'PUT' : 'POST';

  const r = await authed(url, {
    method,
    headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify(payload)
  });

  if (!r.ok){
    const err = await safeJson(r);
    alert(err?.detail || 'Falha ao salvar usuário');
    return;
  }
  closeModal('user-modal');
  await loadUsers();
}

async function deleteUser(id){
  if (!confirm(`Apagar usuário #${id}?`)) return;
  const r = await authed(`${API_BASE}/users/${id}`, { method:'DELETE' });
  if (!r.ok){
    const err = await safeJson(r);
    alert(err?.detail || 'Falha ao deletar usuário');
    return;
  }
  await loadUsers();
}