// Behavioral DOM checks for restricted hosts without a browser. These do not
// replace test-ui.cjs: layout, native dialogs and screenshots need Chromium.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {JSDOM} = require(process.env.JSDOM_MODULE || 'jsdom');
const root = path.resolve(__dirname, '../internal/ui');
const app = {id:'a'.repeat(64),name:'Browser',path:'/apps/first/browser',platform:'linux',decision:'addresses',target:'api.example.net'};
const other = {...app,id:'b'.repeat(64),path:'/apps/second/browser',target:'old.example.org'};
const event = (id, target, source, kind='suggestion') => ({id:String(id),at:`2026-11-17T07:0${id}:00Z`,title:`Событие ${id}`,message:'Ошибка подключения',target,source,kind});
const fixture = {
  account_id:'test',device_id:'phone',status:'ready',tunnel:true,guard:true,revision:1,
  rules:['example.net','8.8.8.8','2001:db8::1'],
  rule_sources:{'example.net':{sources:[app],unknown_source:true},'8.8.8.8':{sources:[],unknown_source:true}},
  applications:[app,other],pending_applications:[],attribution_available:true,
  devices:[{id:'phone',name:'Мой телефон',platform:'android',expires:'2027-01-01'}, {id:'desktop',name:'Ноутбук',platform:'darwin',expires:'2027-01-01'}],
  request_groups:[{target:'example.net',count:2,sources:[],requests:[{target:'api.example.net',sources:[app]}]}, {target:'8.8.8.8',count:2,requests:[{target:'8.8.8.8'}]}],
  events:[event(1,'old.example.org',other),event(2,'2001:db8::1'),event(3,'',null,'outage'),event(4,'api.example.net',app,'application')]
};
const accounts = {accounts:[{id:'alice-id',login:'Alice',status:'active',created:'2026-01-01'}, {id:'bob-id',login:'Bob',status:'pending',created:'2026-02-01'}], devices:[{id:'phone-id',account_id:'alice-id',name:'Рабочий телефон',platform:'android',expires:'2027-01-01'}]};
const writes = [];
const copy = value => JSON.parse(JSON.stringify(value));
const tick = () => new Promise(resolve => setImmediate(resolve));
function load(name, scripts) {
  const dom = new JSDOM(fs.readFileSync(path.join(root,name,'index.html'),'utf8'), {url:`http://localhost/${name}/`,runScripts:'outside-only',pretendToBeVisual:true});
  const w = dom.window;
  w.matchMedia = () => ({matches:false});
  w.setInterval = () => 1;
  // DOM has no layout engine; scrolling is exercised by the Chromium suite.
  w.HTMLElement.prototype.scrollIntoView = function() {};
  w.HTMLDialogElement.prototype.showModal = function() { this.open = true; };
  w.HTMLDialogElement.prototype.close = function(value) { this.returnValue = value; this.open = false; this.dispatchEvent(new w.Event('close')); };
  w.sessionStorage.setItem(name === 'client' ? 'local-token' : 'admin-token','test-only');
  w.fetch = async (url, options) => {
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      writes.push({url,body});
      if (url === '/local/traffic-mode') fixture.traffic_mode = body.mode;
      if (url === '/local/applications') fixture.applications.find(a => a.id === body.id).decision = body.decision;
      if (url === '/api/admin/account') accounts.accounts.find(a => a.id === body.id).status = body.status;
    }
    return {ok:true,status:200,json:async () => copy(name === 'client' ? fixture : accounts)};
  };
  for (const script of scripts) vm.runInContext(fs.readFileSync(path.join(root,name,script),'utf8'),dom.getInternalVMContext(),{filename:script});
  return dom;
}
function input(w, id, value) {
  const node = w.document.getElementById(id);
  node.focus(); node.value = value; node.dispatchEvent(new w.Event('input'));
  assert.equal(w.document.activeElement, node, id + ' must be visible and focusable');
}
function visible(w, selector) { return [...w.document.querySelectorAll(selector)].filter(node => !node.hidden); }

(async () => {
  const client = load('client',['traffic.js','activity.js','app.js']);
  const w = client.window, d = w.document, $ = id => d.getElementById(id);
  try {
    await tick();
    assert.equal($('dashboard').hidden,false,'client failed to render');
    assert.ok($('traffic-mode'), 'missing device-wide traffic mode control');
    assert.equal($('traffic-mode').value, 'selective');
    let changing=$('traffic-mode').onchange;
    $('traffic-mode').value='all';
    let transition=changing();
    await tick();
    assert.equal($('confirm').open,true,'full mode lacks explicit device-wide consent');
    assert.equal(fixture.traffic_mode,undefined,'mode changed before consent');
    $('confirm').close('cancel');await transition;
    assert.equal($('traffic-mode').value,'selective','cancel did not restore selection');
    $('traffic-mode').value='all';transition=changing();await tick();
    $('confirm').close('ok');await transition;
    assert.equal(fixture.traffic_mode,'all');
    assert.match($('traffic-mode-description').textContent,/всех приложений/);
    assert.match($('hero-description').textContent,/DNS/);
    assert.equal($('other-route-tag').textContent,'Только VPN');
    fixture.pending_applications=[{...app,decision:'pending'}];
    await w.eval('update()');
    assert.equal($('application-prompt').open,false,'full mode still asks for individual app permission');
    fixture.pending_applications=[];
    $('traffic-mode').value='selective';transition=changing();await tick();
    $('confirm').close('ok');await transition;
    assert.equal(fixture.traffic_mode,'selective');
    assert.equal(fixture.applications[0].decision,'addresses','mode changed saved application decisions');
    const originalFetch=w.fetch;
    w.fetch=async(url,options)=>url==='/local/traffic-mode'?{ok:false,json:async()=>({error:'save failed'})}:originalFetch(url,options);
    $('traffic-mode').value='all';transition=changing();await tick();$('confirm').close('ok');await transition;
    assert.equal($('traffic-mode').value,'selective','failed save falsely displayed full mode');
    assert.match($('toast').textContent,/save failed/);
    w.fetch=originalFetch;
    assert.equal(writes.filter(x=>x.url==='/local/traffic-mode').length,2,'unexpected mode writes');
    const firstAppCard=$('applications-list').firstElementChild;
    firstAppCard.querySelector('.deny-vpn').click();await tick();await tick();
    assert.deepEqual(writes.at(-1),{url:'/local/applications',body:{id:app.id,decision:'denied'}});
    assert.match(firstAppCard.textContent,/VPN запрещён/);
    assert.equal(firstAppCard.querySelector('.deny-vpn').disabled,true);
    assert.equal(fixture.applications[1].decision,'addresses','denial changed another application');
    const beforeScope={native_app_scope:fixture.native_app_scope,guard:fixture.guard,status:fixture.status,protection_blocked:fixture.protection_blocked};
    Object.assign(fixture,{native_app_scope:true,guard:false,status:'blocked',protection_blocked:true});
    await w.eval('update()');
    assert.match(firstAppCard.querySelector('.row-copy p').textContent,/Вне VPN.*обычная сеть и DNS/,'excluded app falsely shown as protected during an outage');
    Object.assign(fixture,{guard:true});await w.eval('update()');
    assert.match(firstAppCard.querySelector('.row-copy p').textContent,/заблокирован настройкой Android/);
    Object.assign(fixture,beforeScope);await w.eval('update()');
    firstAppCard.querySelector('.secondary:not(.deny-vpn)').click();await tick();await tick();
    assert.equal(fixture.applications[0].decision,'addresses');
    assert.match(firstAppCard.textContent,/VPN только для разрешённых адресов/);
    writes.length=0;

    fixture.policy_sync_pending=2;
    fixture.policy_sync_error='Для сохранения решений обновите сервер';
    await w.eval('update()');
    assert.equal($('policy-sync-status').hidden,false,'unsaved rules warning hidden');
    assert.match($('policy-sync-status').textContent,/2.*переустановкой/);
    assert.match($('policy-sync-status').textContent,/обновите сервер/);
    fixture.policy_sync_pending=0;
    fixture.policy_sync_error='';
    await w.eval('update()');
    assert.equal($('policy-sync-status').hidden,true,'saved rules still reported unsaved');
    d.querySelector('[data-view="requests"]').click();
    input(w,'traffic-search','  FIRST   BROWSER ');
    assert.equal(visible(w,'#requests-list > .request-group').length,1,'nested source path not found');
    const group = d.querySelector('#requests-list > .request-group');
    group.querySelector('details').open = true;
    group.querySelector('.source-details').open = true;
    assert.match(group.querySelector('.application-path').textContent,/\/apps\/first\/browser/);
    fixture.request_groups.reverse();
    await w.eval('update()');
    assert.equal(d.querySelector('#requests-list > .request-group'),group,'polling moved the group');
    assert.equal(group.querySelector('details').open,true);
    assert.equal(group.querySelector('.source-details').open,true);
    assert.equal(d.activeElement,$('traffic-search'));
    assert.equal($('traffic-search').value,'  FIRST   BROWSER ');
    assert.equal($('request-count').textContent,'2','search changed overall totals');
    input(w,'traffic-search','8.8.8');
    assert.equal(visible(w,'#requests-list > .request-group').length,1);
    input(w,'traffic-search','not-present');
    assert.equal(visible(w,'#requests-list > .request-group').length,0);
    assert.match($('traffic-search-status').textContent,/Ничего не найдено/);
    input(w,'traffic-search','');
    assert.equal(visible(w,'#requests-list > .request-group').length,2);

    for (const [field,selector,query] of [
      ['rules','#rules-list > .list-row',' 2001:DB8 '],
      ['rules','#rules-list > .list-row','FIRST browser'],
      ['applications','#applications-list > .list-row','SECOND browser'],
      ['applications','#applications-list > .list-row','api.example'],
      ['devices','#devices-list > .list-row','МОЙ android'],
      ['devices','#devices-list > .list-row','desktop']
    ]) {
      d.querySelector(`[data-view="${field}"]`).click();
      input(w,field+'-search',query);
      assert.equal(visible(w,selector).length,1,field+' search failed');
      input(w,field+'-search','missing-value');
      assert.equal(visible(w,selector).length,0);
      assert.match($(field+'-search-status').textContent,/Ничего не найдено/);
      input(w,field+'-search','');
    }

    assert.match($('rules-list').textContent,/есть запросы с неизвестным источником/);
    assert.match($('rules-list').textContent,/Запросов с этого устройства ещё не наблюдали/);
    assert.equal(visible(w,'#activity-list > .activity-item').length,3);
    d.querySelector('[data-view="overview"]').click();
    input(w,'activity-search','SECOND browser');
    const older = visible(w,'#activity-list > .activity-item');
    assert.equal(older.length,1,'search did not include old events');
    assert.match(older[0].textContent,/old.example.org/);
    assert.match(older[0].querySelector('.application-path').textContent,/\/apps\/second\/browser/);
    older[0].querySelector('button').click();
    await tick();
    assert.match($('confirm-title').textContent,/old.example.org/,'wrong filtered approval target');
    $('confirm').close('cancel');
    await tick();
    input(w,'activity-search','2001:DB8');
    assert.match(visible(w,'#activity-list > .activity-item')[0].textContent,/Приложение-источник не определено/);
    input(w,'activity-search','Событие службы');
    assert.equal(visible(w,'#activity-list > .activity-item').length,1);
    input(w,'activity-search','not-present');
    assert.equal(visible(w,'#activity-list > .activity-item').length,0);
    assert.match($('activity-search-status').textContent,/Ничего не найдено/);
    input(w,'activity-search','');
    $('activity-toggle').click();
    assert.equal(visible(w,'#activity-list > .activity-item').length,4);
    const saved = d.querySelector('#activity-list > .activity-item');
    const savedButton = saved.querySelector('button');
    savedButton.focus();
    fixture.events.push({...event(5,'latest.example.net',app),title:'<img src=x onerror=alert(1)>'});
    await w.eval('update()');
    assert.equal(d.querySelectorAll('#activity-list > .activity-item')[1],saved,'new events replaced old rows');
    assert.equal(d.activeElement,savedButton,'new events lost focus');
    assert.equal(d.querySelectorAll('#activity-list img').length,0,'event text interpreted as HTML');
    assert.equal(writes.length,0,'search or cancellation changed policy');
    fixture.events = fixture.events.slice(1);
    await w.eval('update()');
    assert.equal(d.querySelectorAll('#activity-list > .activity-item').length,4,'evicted event stayed in history');
    $('activity-toggle').click();
    assert.equal(visible(w,'#activity-list > .activity-item').length,3);
  } finally { w.close(); }

  const admin = load('admin',['app.js']);
  const a = admin.window, ad = a.document;
  try {
    await tick();
    ad.querySelector('[data-filter="all"]').click();
    input(a,'accounts-search',' ALICE ');
    assert.equal(ad.querySelectorAll('#accounts > .list-row').length,1);
    input(a,'accounts-search','Рабочий ANDROID');
    assert.equal(ad.querySelectorAll('#accounts > .list-row').length,1);
    await a.eval('refresh()');
    assert.equal(ad.activeElement,ad.getElementById('accounts-search'));
    assert.equal(ad.getElementById('accounts-search').value,'Рабочий ANDROID');
    ad.querySelector('#accounts .danger').click();
    await tick();
    ad.getElementById('confirm').close('ok');
    await tick(); await tick();
    assert.equal(accounts.accounts[0].status,'blocked','filtered action hit wrong account');
    assert.equal(accounts.accounts[1].status,'pending');
    ad.querySelector('[data-filter="pending"]').click();
    assert.equal(ad.querySelectorAll('#accounts > .list-row').length,0,'search bypassed pending filter');
    ad.querySelector('[data-filter="all"]').click();
    input(a,'accounts-search','not-present');
    assert.match(ad.getElementById('accounts').textContent,/Ничего не найдено/);
    input(a,'accounts-search','');
    assert.equal(ad.querySelectorAll('#accounts > .list-row').length,2);
  } finally { a.close(); }
  await testCombinedAuthentication();
  await testReopenedConfirmation();
  console.log('DOM checks passed: sources, historical search, every list, stable polling, correct action targets and safe text rendering.');
})().catch(error => { console.error(error); process.exitCode = 1; });

async function testReopenedConfirmation() {
  for (const name of ['client', 'admin']) {
    const dom=load(name,name==='client'?['traffic.js','activity.js','app.js']:['app.js']);
    const w=dom.window,d=w.document.getElementById('confirm'),queued=[];
    try {
      await tick();
      // Native dialog.close queues its event; a user can reopen before it runs.
      d.close=function(value){this.returnValue=value;this.open=false;queued.push(()=>this.dispatchEvent(new w.Event('close')))};
      const submit=value=>{
        const button=d.querySelector(`button[value="${value}"]`);
        if(d.querySelector('form').dispatchEvent(new w.SubmitEvent('submit',{bubbles:true,cancelable:true,submitter:button})))d.close(value);
      };
      const ask=()=>w.eval(`${name==='client'?'confirmChange':'confirm'}('Confirm test','Test-only action')`);
      const cancelled=ask();submit('cancel');
      const accepted=ask();
      queued.shift()();
      assert.equal(d.open,true,'old close event dismissed the new confirmation');
      submit('ok');while(queued.length)queued.shift()();
      assert.equal(await cancelled,false,'cancelled action was approved by a later confirmation');
      assert.equal(await accepted,true,'old close event consumed the new confirmation');
      const escaped=ask();
      if(d.dispatchEvent(new w.Event('cancel',{cancelable:true})))d.close('');
      while(queued.length)queued.shift()();
      assert.equal(await escaped,false,'Escape approved the action');
    } finally { w.close(); }
  }
}

async function testCombinedAuthentication() {
  const dom = load('client', ['traffic.js', 'activity.js', 'app.js']);
  const w = dom.window, d = w.document, $ = id => d.getElementById(id);
  const key = 'lnv_' + 'A'.repeat(43), code = 'pair-test-code';
  const state = {...copy(fixture), account_id:'', status:'setup', auth_required:false,
    device:{name:'',platform:'darwin'}, login:'Alice', vpn_enabled:true};
  const calls = [];
  let restartPower = false;
  w.HTMLElement.prototype.scrollIntoView = function() {};
  w.fetch = async (url, options) => {
    const body = options.body ? JSON.parse(options.body) : null;
    if (body) calls.push({url,body});
    let out = state;
    if (url === '/local/login' || url === '/local/pair/claim') {
      assert.equal(body.name, undefined, 'renderer supplied a device name');
      assert.equal(body.platform, undefined, 'renderer guessed platform');
      assert.equal(url.endsWith('login') ? body.access_key : body.code, url.endsWith('login') ? key : code);
      if (!body.device_id && !body.new_device && !state.device.name) out = {select_device:true,devices:[{id:'desktop',name:'Saved laptop',platform:'darwin'}]};
      else { Object.assign(state, {account_id:'test',status:'ready',auth_required:false}); out = {ok:true}; }
    } else if (url === '/local/register') {
      assert.equal(body.login,'new-user');
      assert.equal(body.access_key,undefined);
      assert.equal(body.password,undefined);
      out = {login:body.login,access_key:key,status:'pending'};
    } else if (url === '/local/access-key/rotate') {
      assert.equal(body.confirm,true);
      assert.equal(body.current_key,key,'rotation did not prove knowledge of current key');
      out = {login:'Alice',access_key:key};
    } else if (url === '/local/vpn') {
      state.vpn_enabled = body.enabled;
      state.status = body.enabled ? 'setup' : 'disabled';
      if(restartPower){state.power_transition=true;state.status='switching';}
    }
    return {ok:true,status:200,json:async()=>copy(out)};
  };
  const submit = () => $('auth-form').onsubmit(new w.Event('submit',{cancelable:true}));
  try {
    await tick(); await w.eval('update()');
    assert.equal($('setup').hidden,false);
    assert.equal(d.getElementById('password'),null);
    assert.equal(d.getElementById('device-name'),null);
    input(w,'access-key',key);
    await submit();
    assert.equal($('device-choice-label').hidden,false);
    assert.equal($('access-key').value,key,'selection discarded the login key before the second step');
    assert.equal($('device-choice').required,true);
    $('device-choice').value='desktop';
    await submit();
    assert.equal(calls.at(-1).body.device_id,'desktop');
    assert.equal($('access-key').value,'','successful login retained key');
    assert.equal($('dashboard').hidden,false);
    assert.equal($('accounts-search'),null);

    const beforeRotate=calls.length;
    // HTML pattern uses Unicode sets (v), including its stricter escaping rules.
    const keyPattern=new RegExp('^(?:'+$('rotation-current-key').pattern+')$','v');
    assert.equal(keyPattern.test(key),true);
    assert.equal(keyPattern.test('lnv_'+'?'.repeat(43)),false);
    const cancelled=$('rotate-access-key').onclick();await tick();
    input(w,'rotation-current-key',key);$('rotation-cancel').click();await cancelled;
    assert.equal(calls.length,beforeRotate,'cancel submitted rotation');
    assert.equal($('rotation-current-key').value,'','cancel retained current key');
    const rotating=$('rotate-access-key').onclick();await tick();
    input(w,'rotation-current-key',key);$('key-rotation').close('rotate');await rotating;
    assert.equal(calls.at(-1).url,'/local/access-key/rotate');
    assert.equal($('rotation-current-key').value,'','rotation retained current key');
    assert.equal($('issued-key').value,key,'rotation lost one-time result');
    $('key-result').close('saved');

    Object.assign(state,{account_id:'',status:'setup'}); await w.eval('update()');
    $('tab-pair').click();input(w,'pair-code',code);
    await submit();
    assert.equal($('pair-code').value,code,'selection discarded pairing code');
    $('device-choice').value='new'; await submit();
    assert.equal(calls.at(-1).body.new_device,true);
    assert.equal($('pair-code').value,'');

    Object.assign(state,{account_id:'',status:'setup'}); await w.eval('update()');
    $('tab-register').click();input(w,'login','new-user');await submit();
    assert.equal($('key-result').open,true);
    assert.equal($('key-result').getAttribute('aria-labelledby'),'key-title');
    assert.equal($('issued-key').type,'password');
    assert.equal($('issued-key').value,key);
    assert.equal($('key-saved').required,true);
    $('key-result').close('saved');
    assert.equal($('issued-key').value,'');
    assert.equal(JSON.stringify(w.localStorage).includes(key)||JSON.stringify(w.sessionStorage).includes(key),false);

    Object.assign(state,{account_id:'test',status:'disabled',auth_required:true,vpn_enabled:false});
    await w.eval('update()');
    assert.equal($('setup').hidden,false,'disabled VPN hid revoked account');
    assert.equal($('tab-register').disabled,true,'revoked account allowed replacement');
    await $('vpn-toggle').onclick();
    assert.equal($('setup').hidden,false,'power toggle hid required login');
    assert.equal($('dashboard').hidden,true);
    Object.assign(state,{account_id:'test',auth_required:false,status:'ready',vpn_enabled:true,guard:false,power_error:'',power_transition:false});
    restartPower=true;await w.eval('update()');
    const switchOff=$('vpn-toggle').onclick();
    await tick();$('confirm').close('ok');await tick();
    assert.equal($('vpn-toggle').disabled,true);
    assert.match($('vpn-mode-note').textContent,/Переключаем/);
    assert.doesNotMatch($('toast').textContent,/настройки восстановлены/);
    Object.assign(state,{status:'disabled',power_transition:false,tunnel:false,guard:false});
    await switchOff;
    assert.equal($('vpn-toggle').textContent,'Включить VPN');
    assert.match($('toast').textContent,/Все соединения идут напрямую/);
    restartPower=false;
    Object.assign(state,{account_id:'test',auth_required:false,status:'switching',vpn_enabled:false,power_transition:true});
    await w.eval('update()');
    assert.equal($('vpn-toggle').disabled,true);
    assert.match($('status-label').textContent,/ПЕРЕКЛЮЧАЕМ/);
    assert.doesNotMatch($('vpn-mode-note').textContent,/идёт напрямую|восстановлены/);
    Object.assign(state,{status:'network_error',power_transition:false,power_error:'DNS restore failed'});
    await w.eval('update()');
    assert.equal($('vpn-toggle').textContent,'Повторить выключение');
    assert.match($('hero-description').textContent,/DNS restore failed/);
    Object.assign(state,{status:'system_blocked',power_error:'',guard:true});
    w.LineBridge={settings(){},theme(){}};
    await w.eval('update()');
    assert.equal($('guard-warning').hidden,true);
    assert.match($('vpn-mode-note').textContent,/Android блокирует интернет/);
    Object.assign(state,{status:'ready',vpn_enabled:true,tunnel:true,guard:false,direct_fallback:false,power_error:'',sync_pending:true});
    await w.eval('update()');
    assert.equal($('status-label').textContent,'ЗАЩИТА ВКЛЮЧЕНА','API failure changed transport status');
    assert.equal($('sync-warning').hidden,false);
    assert.match($('sync-warning').textContent,/соединения остаются активны/);
    assert.equal($('guard-warning').hidden,false);
    assert.match($('vpn-mode-note').textContent,/Прямой доступ.*ручного выключения/);
    Object.assign(state,{status:'degraded',partial_outage:true,sync_pending:false,vpn_issues:[{target:'<img src=x onerror=alert(1)>.example',network:'tcp',port:443,at:'2026-11-17T10:00:00Z',source:{name:'Browser'}}]});
    await w.eval('update()');
    assert.equal($('status-label').textContent,'ОШИБКИ ОТДЕЛЬНЫХ СОЕДИНЕНИЙ');
    assert.match($('hero-description').textContent,/Повторные попытки идут через VPN/);
    assert.equal($('address-route-tag').textContent,'Только VPN');
    assert.match(w.eval("powerRouteNote('Разрешение')"),/Ошибка части соединений/);
    assert.equal($('sync-warning').hidden,true);
    assert.equal($('vpn-issues').hidden,false);
    assert.match($('vpn-issues-list').textContent,/443.*TCP.*Browser/);
    assert.equal($('vpn-issues-list').querySelectorAll('img').length,0,'diagnostic target became HTML');
    state.vpn_issues=[{target:'2a06:98c1:3101::ac40:9000',network:'tcp',port:443,at:'2026-11-17T10:00:00Z',source:{name:'Приложение'}}];
    await w.eval('update()');
    assert.match($('vpn-issues-list').textContent,/\[2a06:98c1:3101::ac40:9000\]:443.*TCP.*Только через VPN/);
    Object.assign(state,{status:'ready',partial_outage:false,vpn_issues:[],guard:true});
    await w.eval('update()');
    assert.equal($('vpn-issues').hidden,true);
    assert.equal($('guard-warning').hidden,true,'working Android lockdown shown as a warning');
    Object.assign(state,{status:'blocked',vpn_enabled:true,tunnel:true,guard:false,protection_blocked:true,power_error:''});
    await w.eval('update()');
    assert.equal($('status-label').textContent,'ОЖИДАЕМ VPN');
    assert.match($('hero-description').textContent,/не переходят на прямое/);
    assert.equal($('guard-warning').hidden,false,'Android crash protection guidance hidden');
    assert.match($('vpn-mode-note').textContent,/только VPN/);
    assert.equal($('vpn-toggle').textContent,'Выключить VPN');
    Object.assign(state,{status:'degraded',partial_outage:true});
    await w.eval('update()');
    assert.equal($('status-label').textContent,'ОШИБКИ ОТДЕЛЬНЫХ СОЕДИНЕНИЙ');
    assert.match($('hero-description').textContent,/остальные соединения продолжают работать/);
    assert.equal($('address-route-tag').textContent,'Ожидаем VPN');
    assert.match(w.eval("powerRouteNote('Разрешение')"),/только VPN/);
    Object.assign(state,{status:'ready',protection_blocked:false,partial_outage:false,guard:true});
    await w.eval('update()');
    assert.equal($('guard-warning').hidden,true,'working Android lockdown shown as a warning');
    Object.assign(state,{native_app_scope:true,traffic_mode:'selective',guard:true});
    await w.eval('update()');
    assert.equal($('guard-warning').hidden,false,'Android selective lockdown silently disconnects excluded apps');
    assert.match($('guard-title').textContent,/блокирует приложения вне VPN/);
    assert.match($('traffic-mode-description').textContent,/обычный DNS/);
    assert.match($('traffic-mode-description').textContent,/может быть обнаружено/);
    Object.assign(state,{native_app_scope:false});
    // Even failed native enable must leave the explicit off button usable.
    Object.assign(state,{status:'network_error',power_error:'TUN failed'});
    await w.eval('update()');
    assert.equal($('vpn-toggle').textContent,'Выключить VPN');
    const offAfterFailure=$('vpn-toggle').onclick();
    await tick();$('confirm').close('ok');await offAfterFailure;
    assert.equal(calls.at(-1).body.enabled,false);
    console.log('DOM integration passed: key login, device selection, pairing, one-time key and revoked-session power toggle.');
  } finally { w.close(); }
}
