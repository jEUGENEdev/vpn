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
  w.HTMLDialogElement.prototype.showModal = function() { this.open = true; };
  w.HTMLDialogElement.prototype.close = function(value) { this.returnValue = value; this.open = false; this.dispatchEvent(new w.Event('close')); };
  w.sessionStorage.setItem(name === 'client' ? 'local-token' : 'admin-token','test-only');
  w.fetch = async (url, options) => {
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      writes.push({url,body});
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
}
function visible(w, selector) { return [...w.document.querySelectorAll(selector)].filter(node => !node.hidden); }

(async () => {
  const client = load('client',['traffic.js','activity.js','app.js']);
  const w = client.window, d = w.document, $ = id => d.getElementById(id);
  try {
    await tick();
    assert.equal($('dashboard').hidden,false,'client failed to render');
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
  console.log('DOM checks passed: sources, historical search, every list, stable polling, correct action targets and safe text rendering.');
})().catch(error => { console.error(error); process.exitCode = 1; });

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
    assert.match($('toast').textContent,/настройки восстановлены/);
    restartPower=false;
    Object.assign(state,{account_id:'test',auth_required:false,status:'switching',vpn_enabled:false,power_transition:true});
    await w.eval('update()');
    assert.equal($('vpn-toggle').disabled,true);
    assert.match($('status-label').textContent,/ПЕРЕКЛЮЧАЕМ/);
    assert.doesNotMatch($('vpn-mode-note').textContent,/идёт напрямую|восстановлены/);
    Object.assign(state,{status:'network_error',power_transition:false,power_error:'DNS restore failed'});
    await w.eval('update()');
    assert.equal($('vpn-toggle').textContent,'Повторить переключение');
    assert.match($('hero-description').textContent,/DNS restore failed/);
    Object.assign(state,{status:'system_blocked',power_error:'',guard:true});
    w.LineBridge={settings(){},theme(){}};
    await w.eval('update()');
    assert.equal($('guard-warning').hidden,false);
    assert.match($('vpn-mode-note').textContent,/Android блокирует интернет/);
    console.log('DOM integration passed: key login, device selection, pairing, one-time key and revoked-session power toggle.');
  } finally { w.close(); }
}
