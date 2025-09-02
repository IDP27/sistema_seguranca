// ============================================================
// frontend.js — Lógica do frontend (SPA) para o Sistema de Segurança
// Comentado em português, em UMA ÚNICA PÁGINA.
// ============================================================

// =====================
// Config & Estado
// =====================
// Base da API (padrão local). Pode ser sobrescrita na tela de login.
let API_BASE = 'http://127.0.0.1:8005';
// Token JWT do usuário autenticado (mantido em memória e localStorage)
let authToken = null;
// Dados do usuário atual (username e role)
let currentUser = null;

// Estado de paginação (recursos)
let resPage = 1;
const resSize = 10;

// Estado de paginação (usuários)
let usersPage = 1;
const usersSize = 10;

// Helpers para seleção no DOM
const $  = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// =====================
// Boot
// =====================
// Ao carregar o DOM, conecta listeners, restaura API_BASE e token salvos.
document.addEventListener('DOMContentLoaded', () => {
  bindGlobalListeners();

  // Restaura API_BASE e token, se salvos no navegador
  const saved = localStorage.getItem('authToken');
  const savedApi = localStorage.getItem('apiBase');

  if (savedApi) {
    API_BASE = savedApi;
    const apiInput = $('#api-base');
    if (apiInput) apiInput.value = savedApi;
  }
  if (saved) {
    authToken = saved;
    fetchCurrentUser(); // tenta validar o token e carregar o dashboard
  }
});

// =====================
// Listeners
// =====================
// Registra todos os listeners de botões, navegação, modais, etc.
function bindGlobalListeners(){
  // Login
  $('#login-btn').addEventListener('click', doLogin);

  // Toggle da sidebar
  $('#sidebar-toggle').addEventListener('click', () => {
    $('#sidebar').classList.toggle('collapsed');
  });

  // Navegação entre seções (SPA)
  $$('.nav-link').forEach(a=>{
    a.addEventListener('click', (e)=>{
      e.preventDefault();
      const sec = a.getAttribute('data-section');
      showSection(sec);
    });
  });

  // Logout: limpa token e volta para tela de login
  $('#logout-btn').addEventListener('click', () => {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showLogin();
  });

  // Acesso a áreas
  $('#access-area-btn').addEventListener('click', handleAreaAccess);

  // Recursos: filtros/paginação/CRUD
  $('#apply-filters').addEventListener('click', () => { resPage = 1; loadResources(); });
  $('#add-resource-btn').addEventListener('click', ()=> openResourceModal());
  $('#resource-form').addEventListener('submit', handleResourceSubmit);
  $('#prev-page').addEventListener('click', () => { if(resPage>1){resPage--; loadResources();} });
  $('#next-page').addEventListener('click', () => { resPage++; loadResources(); });

  // Logs: filtros
  $('#apply-log-filters').addEventListener('click', loadLogs);

  // Usuários (apenas admin): filtros/paginação/CRUD
  $('#apply-user-filters').addEventListener('click', ()=>{ usersPage=1; loadUsers(); });
  $('#add-user-btn').addEventListener('click', ()=> openUserModal());
  $('#user-form').addEventListener('submit', handleUserSubmit);
  $('#users-prev').addEventListener('click', ()=>{ if(usersPage>1){usersPage--; loadUsers();} });
  $('#users-next').addEventListener('click', ()=>{ usersPage++; loadUsers(); });

  // Fechamento de modais (botões com data-close)
  $$('[data-close]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const id = btn.getAttribute('data-close');
      closeModal(id);
    });
  });
  // Ícones X de fechar
  $$('.close').forEach(x=>{
    x.addEventListener('click', ()=>{
      closeModal(x.getAttribute('data-close') || x.closest('.modal').id);
    });
  });
  // Clique fora do conteúdo fecha o modal
  window.addEventListener('click', (e)=>{
    if (e.target.classList.contains('modal')) e.target.style.display='none';
  });

  // Cards do dashboard → atalhos para seções
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
// Realiza login: envia credenciais, salva token, busca /users/me e carrega dashboard.
async function doLogin(){
  const u = $('#username').value.trim();
  const p = $('#password').value;
  const base = ($('#api-base').value || '').replace(/\/+$/,'');
  API_BASE = base || API_BASE;               // permite trocar a base da API via UI
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
    await fetchCurrentUser(); // carrega dados do usuário + UI
  }catch(e){
    $('#login-error').textContent = 'Erro de conexão. Verifique a API.';
  }
}

// Busca /users/me para validar token e configurar UI conforme role
async function fetchCurrentUser(){
  try{
    const me = await authed(`${API_BASE}/users/me`);
    if (!me.ok){
      showLogin();
      return;
    }
    currentUser = await me.json();
    showDashboard();

    // Mostra/oculta itens do menu conforme permissões
    const isAdmin   = currentUser.role === 'SECURITY_ADMIN';
    const isManager = isAdmin || currentUser.role === 'MANAGER';
    $('#logs-menu-item').style.display   = isAdmin ? 'block' : 'none';
    $('#users-menu-item').style.display  = isAdmin ? 'block' : 'none';
    $('#quick-logs-btn').style.display   = isAdmin ? 'block' : 'none';
    $('#add-resource-btn').style.display = isManager ? 'inline-block' : 'none';
    $('#clear-logs-btn').style.display   = isAdmin ? 'inline-block' : 'none';

    // Carregamento inicial do dashboard
    await loadOverview();
    await loadAllowedAreas();
    await loadResources();
  }catch(e){
    showLogin();
  }
}

// Alterna para tela de login
function showLogin(){
  $('#login-screen').classList.add('active');
  $('#dashboard').classList.remove('active');
}

// Alterna para dashboard e preenche header com usuário/role
function showDashboard(){
  $('#login-screen').classList.remove('active');
  $('#dashboard').classList.add('active');
  $('#username-display').textContent = currentUser.username;
  $('#user-role').textContent = currentUser.role;
}

// Ativa seção selecionada e carrega dados sob demanda
function showSection(id){
  $$('.content-section').forEach(s=>s.classList.remove('active'));
  $(`#${id}`).classList.add('active');
  $$('.nav-link').forEach(a=>{
    a.classList.toggle('active', a.getAttribute('data-section')===id);
  });
  if (id==='logs') loadLogs();
  if (id==='users') loadUsers();
}

// =====================
// Utils
// =====================
// Realiza fetch com header Authorization: Bearer <token>
function authed(url, options={}){
  const headers = {
    'Authorization': `Bearer ${authToken}`,
    ...(options.headers || {})
  };
  return fetch(url, { ...options, headers });
}

// Alias (compat): mesma função do authed
async function authenticatedFetch(url, options={}){
  return authed(url, options);
}

// Tenta ler JSON com proteção a erros
async function safeJson(res){
  try{ return await res.json(); }catch(_){ return null; }
}

// Abre/fecha modais simples (display: block/none)
function openModal(id){ $(`#${id}`).style.display='block'; }
function closeModal(id){ $(`#${id}`).style.display='none'; }

// =====================
// Overview / Cards
// =====================
// Busca KPIs do sistema e preenche os cards do dashboard
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
// Controle de Acesso (Áreas)
// =====================
// Carrega as áreas permitidas ao usuário atual e preenche o <select>
async function loadAllowedAreas(){
  try{
    const r = await authed(`${API_BASE}/areas/allowed`);
    if (!r.ok) return;
    const areas = await r.json();
    const sel = $('#area-select');
    sel.innerHTML = '<option value="">Selecione uma área</option>';

    // Se for admin (retorna ["*"]), mostra todas as áreas conhecidas
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

// Envia tentativa de acesso à área e exibe resultado (permitido/negado)
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
      await loadOverview(); // atualiza KPIs
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
// Recursos (CRUD + Listagem)
// =====================
// Busca lista paginada de recursos conforme filtros atuais
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

// Renderiza tabela de recursos, paginação e ações de editar/excluir
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

  // Paginação (texto e habilitação dos botões)
  const pages = Math.max(1, Math.ceil((list.total||0) / (list.size||resSize)));
  $('#page-info').textContent = `Página ${list.page} de ${pages}`;
  $('#prev-page').disabled = list.page<=1;
  $('#next-page').disabled = list.page>=pages;

  // Liga os botões de ação da tabela
  tbody.querySelectorAll('[data-edit]').forEach(btn=>{
    btn.addEventListener('click', ()=> editResource(btn.getAttribute('data-edit')));
  });
  tbody.querySelectorAll('[data-del]').forEach(btn=>{
    btn.addEventListener('click', ()=> deleteResource(btn.getAttribute('data-del')));
  });
}

// Abre modal de recurso (vazio para criar, preenchido para editar)
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

// Busca um recurso específico e abre o modal de edição
async function editResource(id){
  const r = await authed(`${API_BASE}/resources/${id}`);
  if (!r.ok) return;
  const resource = await r.json();
  openResourceModal(resource);
}

// Submit do formulário (criar/atualizar recurso)
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
  await loadOverview(); // KPIs podem mudar (ex.: total_resources)
}

// Exclui um recurso por ID (confirma antes)
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
// Logs (listagem)
// =====================
// Carrega logs (com filtros opcionalmente: user_id, area, allowed)
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
// Carrega usuários com paginação e filtros (apenas visível para admin)
async function loadUsers(){
  const q = $('#user-search').value.trim();
  const role = $('#user-role-filter').value;

  const params = new URLSearchParams({ page:String(usersPage), size:String(usersSize), sort:'username' });
  if (q) params.set('q', q);
  if (role) params.set('role', role);

  const r = await authed(`${API_BASE}/users?${params.toString()}`);
  if (!r.ok) {
    // Se não for admin, a API retorna 403 → mostra mensagem simples
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

  // Paginação de usuários
  const pages = Math.max(1, Math.ceil((data.total||0) / (data.size||usersSize)));
  $('#users-page-info').textContent = `Página ${data.page} de ${pages}`;
  $('#users-prev').disabled = data.page<=1;
  $('#users-next').disabled = data.page>=pages;

  // Ações da tabela (editar/deletar)
  tbody.querySelectorAll('[data-uedit]').forEach(btn=>{
    btn.addEventListener('click', ()=> openUserEdit(btn.getAttribute('data-uedit')));
  });
  tbody.querySelectorAll('[data-udel]').forEach(btn=>{
    btn.addEventListener('click', ()=> deleteUser(btn.getAttribute('data-udel')));
  });
}

// Abre modal de “Novo Usuário”
function openUserModal(){
  $('#user-modal-title').textContent = 'Novo Usuário';
  $('#user-id').value = '';
  $('#new-username').value = '';
  $('#new-password').value = '';
  $('#new-role').value = 'EMPLOYEE';
  openModal('user-modal');
}

// Busca usuário por ID e abre modal de edição preenchido
async function openUserEdit(id){
  const r = await authed(`${API_BASE}/users/${id}`);
  if (!r.ok) return;
  const u = await r.json();
  $('#user-modal-title').textContent = `Editar Usuário #${u.id}`;
  $('#user-id').value = u.id;
  $('#new-username').value = u.username;
  $('#new-password').value = ''; // senha opcional em update
  $('#new-role').value = u.role;
  openModal('user-modal');
}

// Submit do formulário do usuário (criar/editar)
async function handleUserSubmit(e){
  e.preventDefault();
  const id = $('#user-id').value;
  const isEdit = !!id;

  const payload = {
    username: $('#new-username').value.trim(),
    // Se em update deixar senha vazia, envia undefined para não trocar
    password: $('#new-password').value.trim() || undefined,
    role: $('#new-role').value
  };

  // Para criar: POST /auth/register | Para editar: PUT /users/{id}
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

// Exclui um usuário (apenas admin)
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