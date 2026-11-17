'use strict';
const $=id=>document.getElementById(id);let token=sessionStorage.getItem('local-token')||'',state={},mode='login',lastEvent='',toastTimer,updateSequence=0,powerBusy=false;
const params=new URLSearchParams(location.hash.slice(1));if(params.has('token')){token=params.get('token');sessionStorage.setItem('local-token',token);history.replaceState(null,'',location.pathname)}
let theme=localStorage.getItem('theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
function applyTheme() {
  const dark=theme==='dark';
  document.documentElement.dataset.theme=theme;
  document.body.classList.toggle('dark',dark);
  document.querySelector('meta[name="theme-color"]').content=dark?'#141d30':'#f4f5f8';
  $('theme').textContent=dark?'Светлая тема ◐':'Тёмная тема ◐';
  $('theme').setAttribute('aria-label',dark?'Включить светлую тему':'Включить тёмную тему');
  if(window.LineBridge&&window.LineBridge.theme)window.LineBridge.theme(dark);
}
applyTheme();
$('theme').onclick=()=>{theme=theme==='dark'?'light':'dark';applyTheme();localStorage.setItem('theme',theme)};

function toast(message){$('toast').textContent=message;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,6500)}
async function api(path,data){const res=await fetch('/local/'+path,{method:data===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});const out=await res.json();if(!res.ok)throw Error(out.error||'Ошибка запроса');return out}
async function act(path,data){try{const out=await api(path,data);await update();return out}catch(e){toast(e.message);throw e}}
function element(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function button(text,cls,fn){const b=element('button',text,cls);b.onclick=async()=>{const hadFocus=document.activeElement===b;b.disabled=true;try{await fn()}catch(e){}finally{b.disabled=false;if(hadFocus&&document.activeElement===document.body&&b.isConnected&&b.getClientRects().length)b.focus({preventScroll:true})}};return b}
const viewTitles={overview:'Всё под контролем.',requests:'Вы выбираете маршрут.',rules:'Ваши разрешения.',devices:'Ваши устройства.',applications:'Приложения и маршруты.'};
function view(name) {
  if(!viewTitles[name])return;
  for(const v of document.querySelectorAll('.view'))v.hidden=v.id!=='view-'+name;
  for(const b of document.querySelectorAll('[data-view]')) {
    const active=b.dataset.view===name;
    b.classList.toggle('active',active);
    if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');
  }
  $('page-title').textContent=viewTitles[name];
  document.title=viewTitles[name]+' — Линия VPN';
  // The overview CTA disappears on navigation. Give keyboard users a stable target.
  $('page-title').focus({preventScroll:true});
  $('main-content').scrollIntoView({block:'start'});
}
for(const b of document.querySelectorAll('[data-view]'))b.onclick=()=>view(b.dataset.view);
$('open-requests').onclick=()=>view('requests');

function confirmChange(title,description){$('confirm-title').textContent=title;$('confirm-description').textContent=description;const d=$('confirm');d.returnValue='';d.showModal();return new Promise(resolve=>d.addEventListener('close',()=>resolve(d.returnValue==='ok'),{once:true}))}
async function approve(target){if(!await confirmChange('Разрешить '+target+'?','Домен и его поддомены будут использовать VPN. При сбое соединения блокируются до восстановления VPN или ручного выключения.'+(state.status==='disabled'?' Сейчас VPN выключен: до включения трафик идёт напрямую.':'')))return;await act('rules',{target,action:'approve',revision:state.revision});toast('Разрешение сохранено')}
function row(title,description,buttons){const e=element('div',undefined,'list-row'),copy=element('div',undefined,'row-copy');copy.append(element('strong',title),element('p',description));e.append(copy);const actions=element('div',undefined,'row-actions');actions.append(...buttons);e.append(actions);return e}
function empty(list,text){if(!list.childElementCount)list.append(element('div',text,'empty'))}
function renderDeviceIdentity(){const identity=state.device||{};$('device-detected').hidden=mode==='register';$('device-detected').textContent=identity.name?'Устройство: '+identity.name+' · определено автоматически':'Имя не определено. После входа выберите устройство или добавьте текущее.'}
function resetDeviceChoice(){$('device-choice-label').hidden=true;$('device-choice-hint').hidden=true;$('device-choice').required=false;$('device-choice').replaceChildren()}
function chooseDevice(devices){const field=$('device-choice');field.replaceChildren(new Option('Выберите устройство',''));for(const d of devices||[])field.add(new Option(d.name+' · '+d.platform,d.id));field.add(new Option('Добавить текущее устройство','new'));field.required=true;$('device-choice-label').hidden=false;$('device-choice-hint').hidden=false;field.focus()}
function render(){renderDeviceIdentity();const bound=!!state.account_id,reauth=state.status==='auth_required'||state.auth_required,logged=bound&&!reauth;$('tab-register').disabled=bound;$('tab-pair').disabled=bound;$('bootstrap').disabled=false;$('import-profile').disabled=false;renderPower();$('auth-hint').textContent=reauth?'Срок доступа истёк или доступ отозван. Войдите в тот же аккаунт по актуальному ключу. При отзыве профиля сначала импортируйте новый.':mode==='register'?'Выберите имя. Сервер выдаст ключ, а администратор одобрит заявку.':'Вставьте ключ доступа. Имя аккаунта появится после входа.';if(reauth&&mode!=='login')authMode('login');$('setup').hidden=logged;$('dashboard').hidden=!logged;document.querySelectorAll('[data-view]').forEach(b=>b.disabled=!logged);if(!logged)return;const rules=state.rules||[],requests=requestGroups(),devices=state.devices||[];$('account-chip').textContent=state.login||'Аккаунт · '+state.account_id.slice(0,6);$('approved-count').textContent=rules.length;$('pending-count').textContent=requests.length;$('request-count').textContent=requests.length;$('device-count').textContent=devices.filter(d=>!d.revoked&&Date.parse(d.expires)>Date.now()).length;
$('guard-warning').hidden=!window.LineBridge||state.guard||state.vpn_enabled===false;$('guard-title').textContent='Защита при остановке приложения';$('guard-description').textContent='Включите «Постоянная VPN» и «Блокировать соединения без VPN» в Android. Это предотвращает прямой доступ при остановке процесса приложения.';const off=state.vpn_enabled===false&&state.status==='disabled'&&!powerBusy,ok=!off&&state.status==='ready'&&state.tunnel&&!state.protection_blocked;$('status-badge').dataset.status=ok?'ready':'warning';$('status-label').textContent=off?'VPN ВЫКЛЮЧЕН':ok?'ЗАЩИТА ВКЛЮЧЕНА':'ОЖИДАЕМ VPN';$('hero-description').textContent=off?'Вы отключили VPN. Все адреса и приложения подключаются напрямую. Правила сохранены.':ok?'Разрешённые адреса и доверенные приложения — через VPN. Остальное — напрямую.':state.tunnel||state.guard?'VPN недоступен. Разрешённые адреса и доверенные приложения не переходят на прямое подключение.':'Туннель не запущен. Защита зависит от системной блокировки; откройте настройки VPN.';
if(state.partial_outage){$('status-label').textContent='ЧАСТИЧНЫЙ СБОЙ VPN';$('hero-description').textContent='Соединения со сбоем повторяются только через VPN. Остальные разрешённые соединения продолжают идти через VPN.';}
if(powerBusy||state.power_transition||state.power_error||state.status==='system_blocked'){
  $('status-badge').dataset.status='warning';
  $('status-label').textContent=(powerBusy||state.power_transition)?'ПЕРЕКЛЮЧАЕМ СЕТЬ':state.status==='system_blocked'?'ИНТЕРНЕТ ЗАБЛОКИРОВАН ANDROID':'ОШИБКА НАСТРОЙКИ СЕТИ';
  $('hero-description').textContent=(powerBusy||state.power_transition)?'Восстанавливаем сетевые настройки. Дождитесь завершения переключения.':state.power_error||'VPN выключен, но системная блокировка Android запрещает прямое подключение.';
}
$('address-route-description').textContent=off?'Правила сохранены. Пока VPN выключен, эти адреса тоже идут напрямую.':'Только через VPN. При сбое — блокировка до восстановления или ручного выключения.';$('address-route-tag').textContent=off?'Напрямую':state.protection_blocked?'Ожидаем VPN':'Только VPN';
renderTraffic();renderStableRules();renderStableDevices();
renderActivity();
for(const e of state.events||[]){if(Number(e.id)<=Number(lastEvent||0))continue;if(window.linevpn)window.linevpn.notify(e);lastEvent=e.id}}
async function update(){const sequence=++updateSequence;try{const fresh=await api('state');if(sequence!==updateSequence)return;state=fresh;render()}catch(e){if(powerBusy||state.power_transition)return;$('vpn-toggle').disabled=true;$('status-badge').dataset.status='warning';$('status-label').textContent='СЛУЖБА НЕ ОТВЕЧАЕТ';$('hero-description').textContent='Состояние службы неизвестно. Не отключайте системную защиту: дождитесь перезапуска службы или явно выключите VPN.'}}
function authMode(m){
  mode=m;resetDeviceChoice();renderDeviceIdentity();
  ['login','register','pair'].forEach(x=>{$('tab-'+x).classList.toggle('selected',x===m);$('tab-'+x).setAttribute('aria-pressed',String(x===m))});
  $('login-label').hidden=m!=='register';$('key-label').hidden=m!=='login';$('code-label').hidden=m!=='pair';
  $('login').required=m==='register';$('access-key').required=m==='login';$('pair-code').required=m==='pair';
  $('login').disabled=m!=='register';$('access-key').disabled=m!=='login';$('pair-code').disabled=m!=='pair';
  $('auth-submit').textContent={login:'Войти по ключу →',register:'Получить ключ и отправить заявку →',pair:'Подключить устройство →'}[m];
  $('auth-hint').textContent=m==='register'?'Выберите имя. Сохраните выданный ключ и дождитесь одобрения администратора.':'Пароль не нужен. Используйте личный ключ или одноразовый код с другого устройства.';
}
['login','register','pair'].forEach(m=>$('tab-'+m).onclick=()=>authMode(m));
async function importProfile(field){await act('bootstrap',{uri:field.value.trim()});field.value='';toast('Профиль сохранён. Аккаунт и правила сохранены.');}
$('import-profile').onclick=async()=>{try{await importProfile($('bootstrap'))}catch(e){}};
$('update-profile').onclick=async()=>{try{await importProfile($('replacement-profile'))}catch(e){}};
['login','access-key','pair-code'].forEach(id=>$(id).addEventListener('input',resetDeviceChoice));
$('auth-form').onsubmit=async e=>{
  e.preventDefault();
  const data={};
  if(!$('device-choice-label').hidden){const selected=$('device-choice').value;if(!selected)return;if(selected==='new')data.new_device=true;else data.device_id=selected}
  let selecting=false;
  if(mode==='pair')data.code=$('pair-code').value;else if(mode==='register')data.login=$('login').value;else data.access_key=$('access-key').value.trim();
  $('auth-submit').disabled=true;
  try{
    const out=await act(mode==='pair'?'pair/claim':mode,data);
    if(out.select_device){selecting=true;chooseDevice(out.devices);return}
    resetDeviceChoice();
    if(mode==='register'){showKey(out,'Заявка отправлена. Сохраните ключ');authMode('login')}else toast('Устройство подключено');
  }catch(e){}finally{if(!selecting){$('access-key').value='';$('pair-code').value=''}$('auth-submit').disabled=false}
};
function showKey(out,title){
  if(!out.access_key)throw Error('Сервер не вернул ключ');
  $('key-title').textContent=title;$('key-owner').textContent='Аккаунт: '+out.login;
  $('issued-key').value=out.access_key;$('issued-key').type='password';$('key-reveal').textContent='Показать';$('key-saved').checked=false;$('key-copy-status').textContent='';
  $('key-result').showModal();
}
$('key-result').addEventListener('cancel',e=>e.preventDefault());
$('key-result').addEventListener('close',()=>{$('issued-key').value='';$('key-owner').textContent='';});
$('key-reveal').onclick=()=>{const visible=$('issued-key').type==='password';$('issued-key').type=visible?'text':'password';$('key-reveal').textContent=visible?'Скрыть':'Показать'};
$('key-copy').onclick=async()=>{try{await navigator.clipboard.writeText($('issued-key').value);$('key-copy-status').textContent='Ключ скопирован. Сохраните его в надёжном месте.'}catch{const field=$('issued-key');field.type='text';field.focus();field.select();$('key-reveal').textContent='Скрыть';$('key-copy-status').textContent='Скопируйте выделенный ключ вручную.'}};
$('rotate-access-key').onclick=async()=>{
  if(!await confirmChange('Заменить ключ доступа?','Старый ключ, все устройства этого аккаунта и коды привязки будут отозваны. Сохраните новый ключ и войдите с ним заново.'))return;
  const b=$('rotate-access-key');b.disabled=true;
  try{const out=await act('access-key/rotate',{confirm:true});showKey(out,'Новый ключ доступа')}catch(e){}finally{b.disabled=false}
};
function renderPower(){
  const enabled=state.vpn_enabled!==false, pending=powerBusy||state.power_transition;
  $('vpn-toggle').textContent=pending?'Переключаем…':!enabled&&state.power_error?'Повторить выключение':enabled?'Выключить VPN':'Включить VPN';
  $('vpn-toggle').disabled=!!pending;$('vpn-toggle').setAttribute('aria-pressed',String(enabled));
  $('vpn-mode-note').hidden=false;
  $('vpn-mode-note').textContent=pending?'Переключаем сетевые настройки. Фоновая служба может кратковременно перезапуститься.':state.power_error?'Не удалось переключить сеть: '+state.power_error:state.status==='system_blocked'?'Android блокирует интернет: прямой режим не запущен. Повторите переключение.':enabled?'Разрешённые адреса и доверенные приложения используют только VPN. При сбое ждут восстановления. Прямой доступ — после ручного выключения.':'VPN выключен. Все соединения идут напрямую, без VPN-сервера. Правила сохранены.';
}
async function waitForPower(enabled){
  const deadline=Date.now()+60000;
  while(Date.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,500));
    let fresh;
    try{fresh=await api('state')}catch{continue}
    ++updateSequence;state=fresh;render();
    if(fresh.power_error)throw Error(fresh.power_error);
    if(fresh.status==='system_blocked')throw Error('Android блокирует интернет. Отключите блокировку без VPN в настройках.');
    if(!fresh.power_transition&&fresh.vpn_enabled===enabled){lastEvent='';return;}
  }
  throw Error('Служба не завершила переключение. Проверьте её состояние; сеть ещё не подтверждена.');
}
$('vpn-toggle').onclick=async()=>{
  if(powerBusy||state.power_transition)return;
  const enabled=state.vpn_enabled===false&&!state.power_error;
  if(!enabled&&!await confirmChange('Выключить VPN?','Весь трафик этого устройства, включая разрешённые адреса и доверенные приложения, будет идти напрямую. Правила сохранятся.'))return;
  ++updateSequence;powerBusy=true;render();
  try{
    const out=await api('vpn',{enabled,confirm:!enabled});
    ++updateSequence;state=out;render();
    if(out.power_transition)await waitForPower(enabled);
    if(state.power_error)throw Error(state.power_error);
    if(state.status==='system_blocked')throw Error('Android блокирует интернет. Отключите блокировку без VPN в настройках.');
    toast(enabled?'VPN включён. Проверяем соединение.':'VPN выключен. Все соединения идут напрямую.');
  }catch(e){toast(e.message);await update()}finally{powerBusy=false;render()}
};
$('rule-form').onsubmit=async e=>{e.preventDefault();try{await approve($('rule-input').value.trim());$('rule-input').value=''}catch(e){}};
$('pair-device').onclick=async()=>{try{const out=await act('pair',{});$('pair-result').hidden=false;$('pair-result').textContent=out.code+' · действует 5 минут'}catch(e){}};
authMode('login');initTraffic();initActivity();update();setInterval(update,2500);

$("guard-settings").onclick=()=>{if(window.LineBridge)window.LineBridge.settings()};
