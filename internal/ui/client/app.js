'use strict';
const $=id=>document.getElementById(id);let token=sessionStorage.getItem('local-token')||'',state={},mode='login',lastEvent='',toastTimer,updateSequence=0,powerBusy=false;
const params=new URLSearchParams(location.hash.slice(1));if(params.has('token')){token=params.get('token');sessionStorage.setItem('local-token',token);history.replaceState(null,'',location.pathname)}
let theme=localStorage.getItem('theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');document.body.classList.toggle('dark',theme==='dark');if(window.LineBridge&&window.LineBridge.theme)window.LineBridge.theme(theme==='dark');$('theme').onclick=()=>{theme=theme==='dark'?'light':'dark';document.body.classList.toggle('dark',theme==='dark');if(window.LineBridge&&window.LineBridge.theme)window.LineBridge.theme(theme==='dark');localStorage.setItem('theme',theme)};
function toast(message){$('toast').textContent=message;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,6500)}
async function api(path,data){const res=await fetch('/local/'+path,{method:data===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});const out=await res.json();if(!res.ok)throw Error(out.error||'Ошибка запроса');return out}
async function act(path,data){try{const out=await api(path,data);await update();return out}catch(e){toast(e.message);throw e}}
function element(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function button(text,cls,fn){const b=element('button',text,cls);b.onclick=async()=>{b.disabled=true;try{await fn()}catch(e){}finally{b.disabled=false}};return b}
function view(name){for(const v of document.querySelectorAll('.view'))v.hidden=v.id!=='view-'+name;document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===name));$('page-title').textContent={overview:'Всё под контролем.',requests:'Вы выбираете маршрут.',rules:'Ваши разрешения.',devices:'Ваши устройства.',applications:'Приложения и маршруты.'}[name]}
for(const b of document.querySelectorAll('[data-view]'))b.onclick=()=>view(b.dataset.view);$('open-requests').onclick=()=>view('requests');
function confirmChange(title,description){$('confirm-title').textContent=title;$('confirm-description').textContent=description;const d=$('confirm');d.returnValue='';d.showModal();return new Promise(resolve=>d.addEventListener('close',()=>resolve(d.returnValue==='ok'),{once:true}))}
async function approve(target){if(!await confirmChange('Разрешить '+target+'?','При включённом VPN домен и все его поддомены будут подключаться только через VPN. При сбое подключение блокируется.'+(state.vpn_enabled===false?' Сейчас VPN выключен: до включения трафик идёт напрямую.':'')))return;await act('rules',{target,action:'approve',revision:state.revision});toast('Разрешение сохранено')}
function row(title,description,buttons){const e=element('div',undefined,'list-row'),copy=element('div',undefined,'row-copy');copy.append(element('strong',title),element('p',description));e.append(copy);const actions=element('div',undefined,'row-actions');actions.append(...buttons);e.append(actions);return e}
function empty(list,text){if(!list.childElementCount)list.append(element('div',text,'empty'))}
function render(){const bound=!!state.account_id,reauth=state.status==='auth_required'||state.auth_required,logged=bound&&!reauth;$('tab-register').disabled=bound;$('tab-pair').disabled=bound;$('bootstrap').disabled=false;$('import-profile').disabled=false;renderPower();$('auth-hint').textContent=reauth?'Срок доступа истёк или доступ отозван. Войдите в тот же аккаунт по актуальному ключу. При отзыве профиля сначала импортируйте новый.':mode==='register'?'Выберите имя. Сервер выдаст ключ, а администратор одобрит заявку.':'Вставьте ключ доступа. Имя аккаунта появится после входа.';if(reauth&&mode!=='login')authMode('login');$('setup').hidden=logged;$('dashboard').hidden=!logged;if(!logged)return;const rules=state.rules||[],requests=requestGroups(),devices=state.devices||[];$('account-chip').textContent=state.login||'Аккаунт · '+state.account_id.slice(0,6);$('approved-count').textContent=rules.length;$('pending-count').textContent=requests.length;$('request-count').textContent=requests.length;$('device-count').textContent=devices.filter(d=>!d.revoked&&Date.parse(d.expires)>Date.now()).length;
$('guard-warning').hidden=!!state.guard||!window.LineBridge;const off=state.vpn_enabled===false,ok=!off&&state.status==='ready'&&state.tunnel;$('status-label').textContent=off?'VPN ВЫКЛЮЧЕН':ok?'ЗАЩИТА ВКЛЮЧЕНА':state.tunnel?'ОДОБРЕННЫЕ АДРЕСА ЗАБЛОКИРОВАНЫ':'ПРОВЕРЬТЕ СИСТЕМНУЮ ЗАЩИТУ';$('hero-description').textContent=off?'Вы отключили VPN. Все адреса и приложения подключаются напрямую. Правила сохранены.':state.status==='degraded'?'Защищённое соединение прервалось. Повторяем только через VPN; прямого обхода нет.':ok?'Разрешённые адреса и доверенные приложения — через VPN. Остальное — напрямую.':state.tunnel?'Сервер недоступен. Одобренные адреса заблокированы до восстановления связи.':'Туннель не запущен. Включите службу VPN; состояние системной блокировки проверьте в настройках устройства.';
$('address-route-description').textContent=off?'Правила сохранены. Пока VPN выключен, эти адреса тоже идут напрямую.':'Через VPN. Если связь пропадёт, соединение остановится.';$('address-route-tag').textContent=off?'Напрямую':'Защищено';
renderTraffic();renderStableRules();renderStableDevices();
const al=$('activity-list');al.replaceChildren();for(const e of (state.events||[]).slice(-3).reverse()){const item=element('div',undefined,'activity-item');item.append(element('strong',e.title),element('p',e.message),element('time',new Date(e.at).toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'})));if(e.kind==='suggestion')item.append(button('Рассмотреть адрес','secondary',()=>approve(e.target)));al.append(item)}if(!al.childElementCount)al.append(element('div','Сеть работает по вашим правилам.','empty small'));
for(const e of state.events||[]){if(Number(e.id)<=Number(lastEvent||0))continue;if(window.linevpn)window.linevpn.notify(e);lastEvent=e.id}}
async function update(){const sequence=++updateSequence;try{const fresh=await api('state');if(sequence!==updateSequence)return;state=fresh;render()}catch(e){$('vpn-toggle').disabled=true;$('status-label').textContent='СЛУЖБА НЕ ОТВЕЧАЕТ';$('hero-description').textContent='Проверьте фоновую службу. Не отключайте системную блокировку, если хотите сохранить защиту.'}}
function authMode(m){
  mode=m;
  ['login','register','pair'].forEach(x=>$('tab-'+x).classList.toggle('selected',x===m));
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
$('auth-form').onsubmit=async e=>{
  e.preventDefault();
  const platform=window.LineBridge?'android':navigator.userAgent.includes('Mac')?'darwin':navigator.userAgent.includes('Windows')?'windows':'linux';
  const data={name:$('device-name').value,platform};
  if(mode==='pair')data.code=$('pair-code').value;else if(mode==='register')data.login=$('login').value;else data.access_key=$('access-key').value.trim();
  $('auth-submit').disabled=true;
  try{
    const out=await act(mode==='pair'?'pair/claim':mode,data);
    if(mode==='register'){showKey(out,'Заявка отправлена. Сохраните ключ');authMode('login')}else toast('Устройство подключено');
  }catch(e){}finally{$('access-key').value='';$('pair-code').value='';$('auth-submit').disabled=false}
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
  const enabled=state.vpn_enabled!==false;
  $('vpn-toggle').textContent=powerBusy?'Переключаем…':enabled?'Выключить VPN':'Включить VPN';
  $('vpn-toggle').disabled=powerBusy;$('vpn-toggle').setAttribute('aria-pressed',String(enabled));
  $('vpn-mode-note').hidden=enabled;
}
$('vpn-toggle').onclick=async()=>{
  if(powerBusy)return;
  const enabled=state.vpn_enabled===false;
  if(!enabled&&!await confirmChange('Выключить VPN?','Весь трафик этого устройства, включая разрешённые адреса и доверенные приложения, будет идти напрямую. Правила сохранятся.'))return;
  powerBusy=true;renderPower();
  try{await act('vpn',{enabled,confirm:!enabled});toast(enabled?'VPN включён. Проверяем соединение.':'VPN выключен. Трафик идёт напрямую.')}catch(e){}finally{powerBusy=false;renderPower()}
};
$('rule-form').onsubmit=async e=>{e.preventDefault();try{await approve($('rule-input').value.trim());$('rule-input').value=''}catch(e){}};
$('pair-device').onclick=async()=>{try{const out=await act('pair',{});$('pair-result').hidden=false;$('pair-result').textContent=out.code+' · действует 5 минут'}catch(e){}};
authMode('login');initTraffic();update();setInterval(update,2500);

$("guard-settings").onclick=()=>{if(window.LineBridge)window.LineBridge.settings()};
