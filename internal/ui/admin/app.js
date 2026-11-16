'use strict';const $=id=>document.getElementById(id);let token=sessionStorage.getItem('admin-token')||'',filter='pending',data={accounts:[],devices:[]},profileRequest=0,profileLoading=false;document.body.classList.toggle('dark',localStorage.getItem('theme')==='dark');$('theme').onclick=()=>{document.body.classList.toggle('dark');localStorage.setItem('theme',document.body.classList.contains('dark')?'dark':'light')};function toast(s){$('toast').textContent=s;$('toast').hidden=false;setTimeout(()=>$('toast').hidden=true,6000)}function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}async function api(path,body){const r=await fetch('/api/admin/'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:body===undefined?undefined:JSON.stringify(body)}),v=await r.json();if(r.status===401){token='';sessionStorage.removeItem('admin-token');showLogin()}if(!r.ok)throw Error(v.error||'Ошибка сервера');return v}function showLogin(){$('login-card').hidden=!!token;$('content').hidden=!token;$('logout').hidden=!token;if(!token)resetProfile()}function confirm(title,description){$('confirm-title').textContent=title;$('confirm-description').textContent=description;const d=$('confirm');d.returnValue='';d.showModal();return new Promise(resolve=>d.addEventListener('close',()=>resolve(d.returnValue==='ok'),{once:true}))}function button(text,cls,fn){const b=el('button',text,cls);b.onclick=async()=>{b.disabled=true;try{await fn()}catch(e){toast(e.message)}finally{b.disabled=false}};return b}async function status(id,status){if(await confirm(status==='active'?'Открыть доступ?':'Закрыть доступ?','Изменение применяется ко всем устройствам аккаунта.')){await api('account',{id,status});await refresh()}}function render(){$('accounts-view').hidden=filter==='profile';$('profile-view').hidden=filter!=='profile';const accounts=data.accounts||[],devices=data.devices||[];$('pending-count').textContent=accounts.filter(a=>a.status==='pending').length;$('active-count').textContent=accounts.filter(a=>a.status==='active').length;$('devices-count').textContent=devices.filter(d=>!d.revoked&&Date.parse(d.expires)>Date.now()).length;$('list-title').textContent=filter==='pending'?'Заявки на регистрацию':'Все аккаунты';const list=$('accounts');list.replaceChildren();for(const a of accounts.filter(a=>filter==='all'||a.status==='pending').sort((a,b)=>Date.parse(b.created)-Date.parse(a.created))){const r=el('div',undefined,'list-row'),copy=el('div',undefined,'row-copy'),st=el('span',{pending:'Ожидает решения',active:'Активен',blocked:'Заблокирован',rejected:'Отклонён'}[a.status]||a.status,'admin-status '+a.status);copy.append(el('strong',a.login),el('p','Регистрация: '+new Date(a.created).toLocaleString('ru')),st);if(a.rules?.length)copy.append(el('p','Разрешено: '+a.rules.join(', '),'admin-rules'));const actions=el('div',undefined,'row-actions');if(a.status!=='active')actions.append(button('Одобрить ↗','primary',()=>status(a.id,'active')));if(a.status==='pending')actions.append(button('Отклонить','secondary danger',()=>status(a.id,'rejected')));if(a.status==='active')actions.append(button('Заблокировать','secondary danger',()=>status(a.id,'blocked')));r.append(copy,actions);const owned=devices.filter(d=>d.account_id===a.id);for(const d of owned){const item=el('div',undefined,'row-copy');item.append(el('p',d.name+' · '+d.platform+' · '+(d.revoked?'отозван':'активен')));if(!d.revoked)item.append(button('Отозвать устройство','secondary',async()=>{if(await confirm('Отозвать '+d.name+'?','Устройство потеряет доступ к VPN.')){await api('revoke',{id:d.id});await refresh()}}));r.append(item)}list.append(r)}if(!list.childElementCount)list.append(el('div','Новых заявок пока нет.','empty'))}async function refresh(){if(!token)return;try{data=await api('accounts');render();showLogin();if(filter==='profile'&&!$('server-profile').value&&!profileLoading)await loadProfile()}catch(e){toast(e.message)}}$('login-form').onsubmit=async e=>{e.preventDefault();try{const v=await api('login',{password:$('password').value});token=v.token;sessionStorage.setItem('admin-token',token);$('password').value='';await refresh()}catch(e){toast(e.message)}};$('logout').onclick=async()=>{try{await api('logout',{})}finally{token='';sessionStorage.removeItem('admin-token');showLogin()}};$('refresh').onclick=refresh;document.querySelectorAll('[data-filter]').forEach(b=>b.onclick=()=>{filter=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x===b));render();if(filter==='profile')loadProfile()});showLogin();refresh();setInterval(refresh,15000);
function resetProfile() {
  profileRequest++;
  profileLoading = false;
  $('server-profile').value = '';
  $('profile-status').textContent = '';
  $('profile-status').classList.remove('profile-error');
  $('profile-copy').disabled = true;
  $('profile-download').disabled = true;
  $('profile-refresh').disabled = false;
}

async function loadProfile() {
  if (!token) return;
  const request = ++profileRequest;
  profileLoading = true;
  $('server-profile').value = '';
  $('profile-copy').disabled = true;
  $('profile-download').disabled = true;
  $('profile-refresh').disabled = true;
  $('profile-status').classList.remove('profile-error');
  $('profile-status').textContent = 'Получаем профиль сервера…';
  try {
    const result = await api('bootstrap');
    if (request !== profileRequest || !token) return;
    if (typeof result.profile !== 'string' || !result.profile.startsWith('linevpn://')) {
      throw Error('Сервер не вернул профиль. Попробуйте обновить его.');
    }
    $('server-profile').value = result.profile;
    $('profile-copy').disabled = false;
    $('profile-download').disabled = false;
    $('profile-status').textContent = 'Профиль готов. Скопируйте ссылку или скачайте её файлом.';
  } catch (error) {
    if (request !== profileRequest || !token) return;
    $('profile-status').textContent = error.message;
    $('profile-status').classList.add('profile-error');
  } finally {
    if (request === profileRequest) {
      profileLoading = false;
      $('profile-refresh').disabled = false;
    }
  }
}

async function copyProfile() {
  const field = $('server-profile');
  if (!field.value) return;
  let copied = false;
  try {
    await navigator.clipboard.writeText(field.value);
    copied = true;
  } catch {
    field.focus();
    field.select();
    field.setSelectionRange(0, field.value.length);
    try { copied = document.execCommand('copy'); } catch { /* manual copy remains available */ }
  }
  toast(copied ? 'Профиль скопирован' : 'Профиль выделен. Скопируйте его вручную.');
}

function downloadProfile() {
  const profile = $('server-profile').value;
  if (!profile) return;
  const url = URL.createObjectURL(new Blob([profile + '\n'], {type: 'text/plain;charset=utf-8'}));
  const link = el('a');
  link.href = url;
  link.download = 'linevpn-server.txt';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

$('profile-copy').onclick = copyProfile;
$('profile-download').onclick = downloadProfile;
$('profile-refresh').onclick = loadProfile;
