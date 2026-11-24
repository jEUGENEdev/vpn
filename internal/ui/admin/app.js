'use strict';const $=id=>document.getElementById(id);let token=sessionStorage.getItem('admin-token')||'',filter='pending',data={accounts:[],devices:[]},profileRequest=0,profileLoading=false;document.body.classList.toggle('dark',localStorage.getItem('theme')==='dark');$('theme').onclick=()=>{document.body.classList.toggle('dark');localStorage.setItem('theme',document.body.classList.contains('dark')?'dark':'light')};function toast(s){$('toast').textContent=s;$('toast').hidden=false;setTimeout(()=>$('toast').hidden=true,6000)}function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}async function api(path,body){const r=await fetch('/api/admin/'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:body===undefined?undefined:JSON.stringify(body)}),v=await r.json();if(r.status===401){token='';sessionStorage.removeItem('admin-token');showLogin()}if(!r.ok)throw Error(v.error||'Ошибка сервера');return v}function showLogin(){$('login-card').hidden=!!token;$('content').hidden=!token;$('logout').hidden=!token;if(!token){resetProfile();$('issued-key').value='';if($('key-result').open)$('key-result').close()}}function confirm(title,description){
  $('confirm-title').textContent=title;$('confirm-description').textContent=description;
  const d=$('confirm');d.returnValue='';
  return new Promise(resolve=>{
    const finish=accepted=>{
      d.removeEventListener('submit',submit);d.removeEventListener('cancel',cancel);d.removeEventListener('close',close);
      if(d.open)d.close(accepted?'ok':'cancel');
      resolve(accepted);
    };
    // Capture the decision before a queued close event can reach a reopened dialog.
    const submit=e=>{e.preventDefault();finish(e.submitter?.value==='ok')};
    const cancel=e=>{e.preventDefault();finish(false)};
    const close=()=>{if(!d.open)finish(d.returnValue==='ok')};
    d.addEventListener('submit',submit);d.addEventListener('cancel',cancel);d.addEventListener('close',close);
    d.showModal();
  });
}function button(text,cls,fn){const b=el('button',text,cls);b.onclick=async()=>{b.disabled=true;try{await fn()}catch(e){toast(e.message)}finally{b.disabled=false}};return b}async function status(id,status){if(await confirm(status==='active'?'Открыть доступ?':'Закрыть доступ?','Изменение применяется ко всем устройствам аккаунта.')){await api('account',{id,status});await refresh()}}function render(){$('accounts-view').hidden=filter==='profile';$('profile-view').hidden=filter!=='profile';const accounts=data.accounts||[],devices=data.devices||[];$('pending-count').textContent=accounts.filter(a=>a.status==='pending').length;$('active-count').textContent=accounts.filter(a=>a.status==='active').length;$('devices-count').textContent=devices.filter(d=>!d.revoked&&Date.parse(d.expires)>Date.now()).length;$('list-title').textContent=filter==='pending'?'Заявки на регистрацию':'Все аккаунты';const list=$('accounts');list.replaceChildren();const candidates=accounts.filter(a=>filter==='all'||a.status==='pending'),matches=candidates.filter(a=>accountMatchesSearch(a,devices));$('accounts-search-status').textContent=candidates.length?'Показано: '+matches.length+' из '+candidates.length:'';for(const a of matches.sort((a,b)=>Date.parse(b.created)-Date.parse(a.created))){const r=el('div',undefined,'list-row'),copy=el('div',undefined,'row-copy'),st=el('span',{pending:'Ожидает решения',active:'Активен',blocked:'Заблокирован',rejected:'Отклонён'}[a.status]||a.status,'admin-status '+a.status);copy.append(el('strong',a.login),el('p','Регистрация: '+new Date(a.created).toLocaleString('ru')),st);const actions=el('div',undefined,'row-actions');if(a.status!=='active')actions.append(button('Одобрить ↗','primary',()=>status(a.id,'active')));if(a.status==='pending')actions.append(button('Отклонить','secondary danger',()=>status(a.id,'rejected')));if(a.status==='active')actions.append(button('Заблокировать','secondary danger',()=>status(a.id,'blocked')));actions.append(button('Выдать новый ключ','secondary',()=>issueKey(a)));r.append(copy,actions);const owned=devices.filter(d=>d.account_id===a.id);for(const d of owned){const item=el('div',undefined,'row-copy');item.append(el('p',d.name+' · '+d.platform+' · '+(d.revoked?'отозван':'активен')));item.append(button('Удалить устройство','secondary',async()=>{if(await confirm('Удалить '+d.name+'?','Устройство исчезнет из списка, его ключи доступа и выданные им коды подключения будут удалены.')){await api('revoke',{id:d.id});await refresh()}}));r.append(item)}list.append(r)}if(!list.childElementCount)list.append(el('div',candidates.length?'Ничего не найдено. Измените или очистите поиск.':filter==='pending'?'Новых заявок пока нет.':'Аккаунтов пока нет.','empty'))}async function refresh(){if(!token)return;try{data=await api('accounts');render();showLogin();if(filter==='profile'&&!$('server-profile').value&&!profileLoading)await loadProfile()}catch(e){toast(e.message)}}$('login-form').onsubmit=async e=>{e.preventDefault();try{const v=await api('login',{password:$('password').value});token=v.token;sessionStorage.setItem('admin-token',token);$('password').value='';await refresh()}catch(e){toast(e.message)}};$('logout').onclick=async()=>{try{await api('logout',{})}finally{token='';sessionStorage.removeItem('admin-token');showLogin()}};$('refresh').onclick=refresh;document.querySelectorAll('[data-filter]').forEach(b=>b.onclick=()=>{filter=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x===b));render();if(filter==='profile')loadProfile()});showLogin();refresh();setInterval(refresh,15000);
function resetProfile() {
  profileRequest++;
  profileLoading = false;
  $('server-profile').value = '';
  $('profile-status').textContent = '';
  $('profile-status').classList.remove('profile-error');
  $('profile-copy').disabled = true;
  $('profile-download').disabled = true;
  $('profile-refresh').disabled = false;
  $('profile-rotate').disabled = false;
}

async function loadProfile() {
  if (!token) return;
  const request = ++profileRequest;
  profileLoading = true;
  $('server-profile').value = '';
  $('profile-copy').disabled = true;
  $('profile-download').disabled = true;
  $('profile-refresh').disabled = true;
  $('profile-rotate').disabled = true;
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
      $('profile-rotate').disabled = false;
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

function accountMatchesSearch(account, devices) {
  const words = $('accounts-search').value.trim().toLocaleLowerCase('ru').split(/\s+/).filter(Boolean);
  const status = {pending:'Ожидает решения', active:'Активен', blocked:'Заблокирован', rejected:'Отклонён'};
  const fields = [account.login, account.id, account.status, status[account.status],
    ...devices.filter(d => d.account_id === account.id).flatMap(d => [d.id, d.name, d.platform, d.revoked ? 'отозван' : 'активен'])];
  const text = fields.join(' ').toLocaleLowerCase('ru');
  return words.every(word => text.includes(word));
}
$('accounts-search').oninput = render;

async function issueKey(account) {
  if(!await confirm('Выдать новый ключ для '+account.login+'?', 'Старый ключ, все устройства аккаунта и коды привязки будут отозваны. Имя, статус и правила сохранятся. Передайте новый ключ владельцу безопасным способом.'))return;
  const out=await api('access-key',{id:account.id,confirm:true});
  $('key-title').textContent='Новый ключ доступа';$('key-owner').textContent='Аккаунт: '+out.login;
  $('issued-key').value=out.access_key;$('issued-key').type='password';$('key-reveal').textContent='Показать';$('key-saved').checked=false;$('key-copy-status').textContent='';
  $('key-result').showModal();await refresh();
}
$('key-result').addEventListener('cancel',e=>e.preventDefault());
$('key-result').addEventListener('close',()=>{$('issued-key').value='';$('key-owner').textContent=''});
$('key-reveal').onclick=()=>{const visible=$('issued-key').type==='password';$('issued-key').type=visible?'text':'password';$('key-reveal').textContent=visible?'Скрыть':'Показать'};
$('key-copy').onclick=async()=>{try{await navigator.clipboard.writeText($('issued-key').value);$('key-copy-status').textContent='Ключ скопирован.'}catch{const f=$('issued-key');f.type='text';f.focus();f.select();$('key-reveal').textContent='Скрыть';$('key-copy-status').textContent='Скопируйте выделенный ключ вручную.'}};
$('profile-rotate').onclick=async()=>{
  const revoke=$('profile-revoke-devices').checked;
  const revokeConfirmation=$('profile-revoke-confirmation').value.trim();
  if(revoke&&revokeConfirmation!=='REVOKE-ALL'){toast('Введите REVOKE-ALL для отзыва всех устройств.');return;}
  if(!await confirm('Перевыпустить профиль сервера?', 'Старая ссылка и все коды привязки перестанут работать. '+(revoke?'Все подключённые устройства потеряют доступ. Им потребуется новый профиль и повторный вход по личному ключу.':'Подключённые устройства сохранят доступ. Новый профиль нужен для регистрации и повторного входа.')))return;
  profileRequest++;profileLoading=true;$('profile-rotate').disabled=true;$('profile-refresh').disabled=true;
  $('server-profile').value='';$('profile-copy').disabled=true;$('profile-download').disabled=true;
  try{const out=await api('bootstrap/rotate',{confirm:true,revoke_devices:revoke,revoke_confirmation:revokeConfirmation});if(!token)return;$('server-profile').value=out.profile;$('profile-copy').disabled=false;$('profile-download').disabled=false;$('profile-status').textContent='Новый профиль готов. Старая ссылка отозвана.';$('profile-status').classList.remove('profile-error');$('profile-revoke-devices').checked=false;$('profile-revoke-confirmation').value='';}
  catch(e){$('profile-status').textContent=e.message;$('profile-status').classList.add('profile-error')}
  finally{profileLoading=false;$('profile-rotate').disabled=false;$('profile-refresh').disabled=false}
};
