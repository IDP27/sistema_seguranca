let token = null;
let currentUser = null;

const $ = (s) => document.querySelector(s);
const api = () => ($('#baseUrl').value || '').replace(/\/+$/,''); // remove trailing '/'

function setStatus(msg, ok=true){
  const el = $('#statusLine');
  el.textContent = msg || '';
  el.style.color = ok ? '#bbf7d0' : '#fecaca';
}

function setWhoAmI(user){
  currentUser = user;
  if(!user){
    $('#whoami').textContent = 'deslogado';
    $('#btnLogout').classList.add('hidden');
    document.querySelectorAll('.adminOnly').forEach(b => b.classList.add('hidden'));
    return;
  }
  $('#whoami').textContent = `${user.username} • ${user.role}`;
  $('#btnLogout').classList.remove('hidden');
  // habilitar botões de admin/manager
  const isAdmin = user.role === 'SECURITY_ADMIN';
  const isManager = user.role === 'MANAGER';
  document.querySelectorAll('.adminOnly').forEach(b => {
    if(isAdmin || isManager) b.classList.remove('hidden');
    else b.classList.add('hidden');
  });
}

async function call(path, {method='GET', headers={}, body=null}={}){
  const h = {'Content-Type': 'application/json', ...headers};
  if(token) h['Authorization'] = 'Bearer ' + token;
  const res = await fetch(api()+path, {method, headers:h, body});
  const text = await res.text();
  let data = null; try{ data = text? JSON.parse(text) : null }catch(e){ data = text }
  if(!res.ok){ throw {status:res.status, data} }
  return data;
}

/* ======= LOGIN ======= */
$('#btnLogin').addEventListener('click', async ()=>{
  try{
    const data = await call('/auth/login', {
      method:'POST',
      body: JSON.stringify({username: $('#username').value, password: $('#password').value})
    });
    token = data.access_token;
    setStatus('Login OK');
    const me = await call('/users/me');
    setWhoAmI(me);
  }catch(err){
    setStatus('Falha no login: ' + (err.data?.detail || err.status), false);
    console.error(err);
  }
});

$('#btnLogout').addEventListener('click', async ()=>{
  try{ await call('/auth/logout', {method:'POST'}); }catch(_){}
  token = null; setWhoAmI(null); setStatus('Você saiu (token descartado).');
});

$('#btnMe').addEventListener('click', async ()=>{
  try{ const me = await call('/users/me'); setWhoAmI(me); setStatus('Token válido.'); }
  catch(err){ setWhoAmI(null); setStatus('Não autenticado: ' + (err.data?.detail || err.status), false); }
});

/* ======= ÁREAS ======= */
$('#btnAllowed').addEventListener('click', async ()=>{
  try{
    const areas = await call('/areas/allowed');
    $('#areasOut').textContent = JSON.stringify(areas, null, 2);
  }catch(err){
    $('#areasOut').textContent = 'Erro: ' + (err.data?.detail || err.status);
  }
});

$('#btnEnterArea').addEventListener('click', async ()=>{
  const area = $('#enterAreaName').value.trim();
  if(!area) return alert('Informe uma área');
  try{
    const r = await call(`/areas/${encodeURIComponent(area)}/enter`, {method:'POST'});
    $('#areasOut').textContent = 'OK: ' + JSON.stringify(r, null, 2);
  }catch(err){
    $('#areasOut').textContent = 'Erro: ' + (err.data?.detail || err.status);
  }
});

/* ======= RECURSOS ======= */
$('#btnListResources').addEventListener('click', listResources);
async function listResources(){
  const params = new URLSearchParams();
  const q = $('#resQ').value.trim(); if(q) params.set('q', q);
  const cat = $('#resCat').value.trim(); if(cat) params.set('category', cat);
  const loc = $('#resLoc').value.trim(); if(loc) params.set('location', loc);
  const min = $('#resMin').value; if(min!=='') params.set('min_qty', min);
  const max = $('#resMax').value; if(max!=='') params.set('max_qty', max);
  params.set('page', $('#resPage').value || '1');
  params.set('size', $('#resSize').value || '10');
  params.set('sort', $('#resSort').value);
  try{
    const data = await call('/resources?'+params.toString());
    renderResources(data);
  }catch(err){
    $('#resourcesBox').textContent = 'Erro: ' + (err.data?.detail || err.status);
  }
}

function renderResources(list){
  if(!list || !list.items || list.items.length===0){
    $('#resourcesBox').textContent = 'Sem recursos.';
    return;
  }
  const rows = list.items.map(it => `
    <tr>
      <td class="mono">${it.id}</td>
      <td>${it.name}</td>
      <td>${it.category}</td>
      <td>${it.quantity}</td>
      <td>${it.location||'-'}</td>
      <td>${it.description||'-'}</td>
    </tr>
  `).join('');
  $('#resourcesBox').innerHTML = `
    <div class="table">
      <table>
        <thead><tr><th>ID</th><th>Nome</th><th>Categoria</th><th>Qtd</th><th>Local</th><th>Descrição</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div class="small muted">Total: ${list.total} • Página: ${list.page} • Itens/página: ${list.size}</div>
  `;
}

$('#btnCreateResource').addEventListener('click', async ()=>{
  const body = {
    name: $('#rcName').value.trim(),
    category: $('#rcCat').value.trim(),
    quantity: Number($('#rcQty').value || 0),
    location: $('#rcLoc').value.trim() || null,
    description: $('#rcDesc').value.trim() || null,
  };
  if(!body.name || !body.category) return alert('Preencha nome e categoria');
  try{
    const r = await call('/resources', {method:'POST', body: JSON.stringify(body)});
    setStatus('Recurso criado (#'+r.id+')');
    listResources();
  }catch(err){
    setStatus('Erro ao criar: '+(err.data?.detail||err.status), false);
  }
});

$('#btnUpdateResource').addEventListener('click', async ()=>{
  const id = ($('#resId').value||'').trim();
  if(!id) return alert('Informe o ID do recurso para atualizar');
  const body = {};
  if($('#rcName').value.trim()) body.name = $('#rcName').value.trim();
  if($('#rcCat').value.trim()) body.category = $('#rcCat').value.trim();
  if($('#rcQty').value !== '') body.quantity = Number($('#rcQty').value);
  body.location = $('#rcLoc').value.trim() || null;
  body.description = $('#rcDesc').value.trim() || null;
  try{
    await call('/resources/'+encodeURIComponent(id), {method:'PUT', body: JSON.stringify(body)});
    setStatus('Recurso atualizado (#'+id+')');
    listResources();
  }catch(err){
    setStatus('Erro ao atualizar: '+(err.data?.detail||err.status), false);
  }
});

$('#btnDeleteResource').addEventListener('click', async ()=>{
  const id = ($('#resId').value||'').trim();
  if(!id) return alert('Informe o ID do recurso para deletar');
  if(!confirm('Apagar recurso #'+id+'?')) return;
  try{
    await call('/resources/'+encodeURIComponent(id), {method:'DELETE'});
    setStatus('Recurso deletado (#'+id+')');
    listResources();
  }catch(err){
    setStatus('Erro ao deletar: '+(err.data?.detail||err.status), false);
  }
});

/* ======= LOGS (ADMIN) ======= */
$('#btnListLogs').addEventListener('click', async ()=>{
  const qs = new URLSearchParams();
  const u = $('#lgUser').value; if(u!=='') qs.set('user_id', u);
  const a = $('#lgArea').value.trim(); if(a) qs.set('area', a);
  const al = $('#lgAllowed').value; if(al!=='') qs.set('allowed', al);
  const lim = $('#lgLimit').value; if(lim!=='') qs.set('limit', lim);
  try{
    const r = await call('/logs' + (qs.toString()?('?'+qs.toString()):''));
    $('#logsOut').textContent = JSON.stringify(r, null, 2);
  }catch(err){
    $('#logsOut').textContent = 'Erro: ' + (err.data?.detail||err.status);
  }
});

$('#btnUpdateLog').addEventListener('click', async ()=>{
  const id = ($('#logId').value||'').trim();
  if(!id) return alert('Informe o ID do log');
  let body={};
  const raw = $('#logUpdateBody').value.trim();
  if(raw){ try{ body = JSON.parse(raw) }catch(e){ return alert('JSON inválido'); } }
  try{
    const r = await call('/logs/'+encodeURIComponent(id), {method:'PUT', body: JSON.stringify(body)});
    $('#logsOut').textContent = JSON.stringify(r, null, 2);
    setStatus('Log atualizado (#'+id+')');
  }catch(err){
    setStatus('Erro ao atualizar log: '+(err.data?.detail||err.status), false);
  }
});

$('#btnDeleteLog').addEventListener('click', async ()=>{
  const id = ($('#logId').value||'').trim();
  if(!id) return alert('Informe o ID do log');
  if(!confirm('Apagar log #'+id+'?')) return;
  try{
    await call('/logs/'+encodeURIComponent(id), {method:'DELETE'});
    setStatus('Log deletado (#'+id+')'); $('#btnListLogs').click();
  }catch(err){
    setStatus('Erro ao deletar log: '+(err.data?.detail||err.status), false);
  }
});

$('#btnDeleteAllLogs').addEventListener('click', async ()=>{
  if(!confirm('Zerar TODOS os logs?')) return;
  try{
    await call('/logs', {method:'DELETE'});
    setStatus('Todos os logs zerados'); $('#btnListLogs').click();
  }catch(err){
    setStatus('Erro ao zerar logs: '+(err.data?.detail||err.status), false);
  }
});