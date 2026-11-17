// Local UI contract test. All account/domain data below is a test fixture.
const fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'../internal/ui/client');
const state={account_id:'test-account',device_id:'test-device',status:'ready',tunnel:true,guard:true,rules:['example.com','example.org','8.8.8.8'],requests:[{target:'api.example.net',direct_failed:true,count:4,last_seen:new Date().toISOString()}],devices:[{id:'test-device',name:'Личный ноутбук',platform:'darwin',expires:'2027-02-01',revoked:false},{id:'phone',name:'Мой телефон',platform:'android',expires:'2027-02-01',revoked:false}],revision:1,events:[]};
const bootstrapProfile='linevpn://8.8.8.8:8443?pin='+'A'.repeat(43);let bootstrapFailure=false;
const admin={accounts:[{id:'pending-user',login:'new-user',status:'pending',created:new Date().toISOString(),rules:[]}],devices:[]};
const server=http.createServer(async(req,res)=>{if(req.url.startsWith('/api/admin/')){let raw='';for await(const b of req)raw+=b;const data=raw?JSON.parse(raw):{};res.setHeader('Content-Type','application/json');if(req.url==='/api/admin/login'){res.end(JSON.stringify({token:'admin-test'}));return}if(req.headers.authorization!=='Bearer admin-test')throw Error('admin auth missing');if(req.url==='/api/admin/bootstrap'){res.statusCode=bootstrapFailure?503:200;res.end(JSON.stringify(bootstrapFailure?{error:'Профиль временно недоступен'}:{profile:bootstrapProfile}));return}if(req.url==='/api/admin/account')admin.accounts.find(a=>a.id===data.id).status=data.status;res.end(JSON.stringify(req.url==='/api/admin/accounts'?admin:{ok:true}));return}if(req.url.startsWith('/local/')){if(req.headers.authorization!=='Bearer ui-test')throw Error('auth missing');let data='';for await(const chunk of req)data+=chunk;if(req.url==='/local/applications'){const body=JSON.parse(data);const application=state.applications.find(a=>a.id===body.id);if(!application)throw Error('unknown app');application.decision=body.decision;state.pending_applications=state.pending_applications.filter(a=>a.id!==body.id);state.app_tunnel=state.applications.some(a=>a.decision==='trusted')}if(req.url==='/local/dismiss'){const body=JSON.parse(data);state.request_groups=(state.request_groups||[]).filter(g=>g.target!==body.target)}if(req.url==='/local/rules'){const body=JSON.parse(data);if(body.action==='approve'){state.rules.push(body.target);state.requests=[]}else state.rules=state.rules.filter(x=>x!==body.target);state.revision++}res.setHeader('Content-Type','application/json');res.end(JSON.stringify(req.url==='/local/state'?state:{ok:true}));return}const file=req.url.startsWith('/admin/')?path.join(root,'../admin',req.url==='/admin/'?'index.html':req.url.slice(7)):path.join(root,req.url==='/'?'index.html':req.url);res.setHeader('Content-Type',file.endsWith('.css')?'text/css':file.endsWith('.js')?'text/javascript':'text/html');res.end(fs.readFileSync(file))});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||undefined,headless:true,args:['--no-sandbox']});const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(`http://127.0.0.1:${server.address().port}/#token=ui-test`);await page.locator('#dashboard').waitFor({state:'visible'});await page.screenshot({path:'build/ui-desktop.png',fullPage:true});await page.getByRole('button',{name:'Разобрать запросы'}).click();await page.locator('#requests-list').getByRole('button',{name:'Разрешить VPN'}).click();await page.locator('#confirm').getByRole('button',{name:'Подтвердить'}).click();await page.waitForFunction(()=>document.getElementById('approved-count').textContent==='4');await page.locator('[data-view="rules"]').click();await page.locator('#rule-input').fill('<img src=x onerror=alert(1)>.example.com');await page.locator('#rule-form .primary').click();if(await page.locator('#confirm img').count())throw Error('HTML injection');await page.getByRole('button',{name:'Отмена',exact:true}).click();await page.locator('[data-view="overview"]').click();await page.setViewportSize({width:390,height:844});await page.screenshot({path:'build/ui-android.png',fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('mobile overflow');await page.locator('#theme').click();await page.screenshot({path:'build/ui-dark.png',fullPage:true});await testTraffic(page);await testListSearch(page);await page.setViewportSize({width:1440,height:1000});await page.goto(`http://127.0.0.1:${server.address().port}/admin/`);await page.locator('#password').fill('test-only-password');await page.getByRole('button',{name:'Войти →',exact:true}).click();await page.locator('#content').waitFor({state:'visible'});await page.screenshot({path:'build/ui-admin.png',fullPage:true});await page.getByRole('button',{name:'Одобрить ↗',exact:true}).click();await page.locator('#confirm').getByRole('button',{name:'Подтвердить'}).click();await page.waitForFunction(()=>document.getElementById('pending-count').textContent==='0');if(admin.accounts[0].status!=='active')throw Error('admin approval failed');await testAdminSearch(page);await testAdminProfile(page);if(errors.length)throw Error(errors.join('\n'));await browser.close();server.close();console.log('UI approval, request sources, history/list search, stable polling, application consent, exports and responsive layouts passed')})().catch(e=>{console.error(e);server.close();process.exit(1)});
async function testAdminProfile(page) {
  await page.locator('[data-filter="profile"]').click();
  await page.waitForFunction(expected => document.getElementById('server-profile').value === expected, bootstrapProfile);
  if (!(await page.locator('#server-profile').evaluate(el => el.readOnly))) throw Error('profile must be read-only');
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.locator('#profile-copy').click();
  if (await page.evaluate(() => navigator.clipboard.readText()) !== bootstrapProfile) throw Error('profile clipboard mismatch');
  const downloadReady = page.waitForEvent('download');
  await page.locator('#profile-download').click();
  const download = await downloadReady;
  if (download.suggestedFilename() !== 'linevpn-server.txt' ||
      fs.readFileSync(await download.path(), 'utf8') !== bootstrapProfile + '\n') throw Error('profile download mismatch');
  await page.screenshot({path:'build/ui-admin-profile.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.locator('#theme').click();
  await page.screenshot({path:'build/ui-admin-profile-mobile.png',fullPage:true});
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)) throw Error('mobile admin profile overflow');

  // Clipboard permissions can be denied on a mobile browser. The URI must remain selectable.
  await page.evaluate(() => {
    Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async () => {throw Error('denied')}}});
    document.execCommand = () => false;
  });
  await page.locator('#profile-copy').click();
  await page.waitForFunction(() => document.getElementById('toast').textContent.includes('вручную'));
  if (!(await page.locator('#server-profile').evaluate(el => el.selectionStart === 0 && el.selectionEnd === el.value.length))) {
    throw Error('manual profile copy fallback failed');
  }

  bootstrapFailure = true;
  await page.locator('#profile-refresh').click();
  await page.waitForFunction(() => document.getElementById('profile-status').textContent.includes('временно недоступен'));
  if (await page.locator('#server-profile').inputValue() ||
      !(await page.locator('#profile-copy').isDisabled()) ||
      !(await page.locator('#profile-download').isDisabled())) throw Error('failed refresh left stale export controls');
  bootstrapFailure = false;
  await page.locator('#profile-refresh').click();
  await page.waitForFunction(expected => document.getElementById('server-profile').value === expected, bootstrapProfile);
  await page.locator('#logout').click();
  await page.locator('#login-card').waitFor({state:'visible'});
  if (await page.locator('#server-profile').inputValue() || await page.locator('#profile-view').isVisible()) {
    throw Error('logout retained a visible profile');
  }
}

async function testTraffic(page) {
  const application = {id:'a'.repeat(64),name:'Example Browser',path:'/Applications/Example Browser.app/Contents/MacOS/Browser',platform:'darwin',decision:'pending',first_seen:'2026-01-01',target:'api.example.com'};
  state.applications = [application]; state.pending_applications = []; state.attribution_available = true;
  const request = (target, sources=[]) => ({target,direct_failed:true,count:2,first_seen:'2026-01-01',last_seen:new Date().toISOString(),sources,unknown_source:!sources.length});
  state.request_groups = [
    {target:'example.com',count:4,sources:[application],requests:[request('api.example.com',[application]),request('cdn.example.com',[application])]},
    {target:'8.8.8.8',count:2,sources:[],unknown_source:true,requests:[request('8.8.8.8')]},
    {target:'other.example.org',count:2,sources:[],unknown_source:true,requests:[request('other.example.org')]}
  ];
  await page.evaluate(() => update());
  await page.locator('[data-view="requests"]').click();
  await page.setViewportSize({width:1440,height:1000});
  const first = page.locator('#requests-list > .request-group').first();
  await first.locator('summary').click();
  await first.locator('.target-list button').first().focus();
  const order = await page.locator('#requests-list > .request-group').evaluateAll(nodes => nodes.map(n => n.dataset.key));
  await page.evaluate(() => { window.savedGroup=document.querySelector('#requests-list > .request-group');window.savedFocus=document.activeElement; });
  state.request_groups.reverse(); state.request_groups[2].count=900;
  for(let i=0;i<3;i++) await page.evaluate(() => update());
  const after = await page.locator('#requests-list > .request-group').evaluateAll(nodes => nodes.map(n => n.dataset.key));
  if(JSON.stringify(order)!==JSON.stringify(after))throw Error('polling moved existing request groups');
  if(!await page.evaluate(() => window.savedGroup===document.querySelector('#requests-list > .request-group') && window.savedGroup.querySelector('details').open && document.activeElement===window.savedFocus))throw Error('polling replaced focused row or collapsed details');
  if(!await first.getByText('Example Browser',{exact:false}).first().isVisible())throw Error('application source missing');
  if(!await page.locator('#requests-list').getByText('Приложение-источник не определено',{exact:true}).first().isVisible())throw Error('unknown source must be explicit');
  await page.locator('#traffic-search').fill('Example Browser');
  if(await page.locator('#requests-list > .request-group:visible').count()!==1)throw Error('application search failed');
  await page.locator('#traffic-search').fill('');
  await page.screenshot({path:'build/ui-traffic-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'build/ui-traffic-mobile.png',fullPage:true});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('traffic mobile overflow');

  state.pending_applications = [application];
  await page.evaluate(() => update());
  await page.locator('#application-prompt').waitFor({state:'visible'});
  await page.screenshot({path:'build/ui-application-prompt.png',fullPage:true});
  await page.locator('#application-prompt').getByRole('button',{name:'Только выбранные адреса',exact:true}).click();
  await page.waitForFunction(() => !document.getElementById('application-prompt').open);
  await page.waitForFunction(() => state.applications?.[0]?.decision==='addresses');
  for(let i=0;i<3;i++)await page.evaluate(() => update());
  if(await page.locator('#application-prompt').isVisible())throw Error('application prompt spam');
  const rules = JSON.stringify(state.rules);
  await page.locator('[data-view="applications"]').click();
  await page.getByRole('button',{name:'Доверить весь трафик',exact:true}).click();
  await page.locator('#confirm').getByRole('button',{name:'Подтвердить',exact:true}).click();
  await page.waitForFunction(() => document.getElementById('applications-list').textContent.includes('весь трафик через VPN'));
  if(JSON.stringify(state.rules)!==rules)throw Error('application trust changed shared domain rules');
  await page.screenshot({path:'build/ui-applications-mobile.png',fullPage:true});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('applications mobile overflow');
  await page.getByRole('button',{name:'Только по адресам',exact:true}).click();
  await page.waitForFunction(() => document.getElementById('applications-list').textContent.includes('VPN только для разрешённых адресов'));
  state.request_groups = [];state.requests=[];
  await page.evaluate(() => update());
  await page.locator('[data-view="requests"]').click();
  if(!await page.getByText('Прямые подключения работают.',{exact:false}).isVisible())throw Error('recovered direct traffic did not clear proposals');
  const cancelledApp = {...application,id:'c'.repeat(64),name:'Cancelled app',decision:'pending'};
  state.applications.push(cancelledApp);state.pending_applications=[cancelledApp];
  await page.evaluate(() => { nextApplicationPrompt=0; return update(); });
  await page.locator('#application-prompt').waitFor({state:'visible'});
  if(await page.locator('#application-prompt').evaluate(el => el.returnValue !== ''))throw Error('new prompt inherited the previous decision');
  await page.keyboard.press('Escape');
  await page.locator('#application-prompt').waitFor({state:'hidden'});
  await page.evaluate(() => update());
  if(cancelledApp.decision!=='pending')throw Error('Escape granted application consent');
  const recoveredApp = {...application,id:'d'.repeat(64),name:'Recovered app',decision:'pending'};
  state.applications.push(recoveredApp);state.pending_applications=[recoveredApp];
  await page.evaluate(() => { nextApplicationPrompt=0; return update(); });
  await page.locator('#application-prompt').waitFor({state:'visible'});
  state.pending_applications=[];
  await page.evaluate(() => update());
  await page.locator('#application-prompt').waitFor({state:'hidden'});
}

function seedSearchFixtures() {
  const browser = {id:'a'.repeat(64),name:'Example Browser',path:'/Applications/Example Browser.app/Contents/MacOS/Browser',platform:'darwin',decision:'addresses',target:'api.example.com'};
  const other = {...browser,id:'b'.repeat(64),path:'/opt/Second Browser/browser',platform:'linux',target:'archive.example.net'};
  state.applications = [browser, other]; state.pending_applications = [];
  state.rules = ['example.com', '8.8.8.8', '2001:db8::1'];
  state.rule_sources = {'example.com':{sources:[browser],unknown_source:true}};
  state.devices = [{id:'test-device',name:'Личный ноутбук',platform:'darwin',expires:'2027-02-01'}, {id:'phone',name:'Мой телефон',platform:'android',expires:'2027-02-01'}];
  state.request_groups = [
    {target:'example.net',count:2,sources:[],requests:[{target:'archive.example.net',sources:[other]}]},
    {target:'8.8.8.8',count:2,sources:[],unknown_source:true,requests:[{target:'8.8.8.8'}]}
  ];
  const event = (id, kind, target, source) => ({id:String(id),kind,title:'Событие '+id,message:'Проверка подключения',target,source,at:new Date(Date.UTC(2026,10,17,7,id)).toISOString()});
  state.events = [event(1,'suggestion','archive.example.net',other), event(2,'suggestion','2001:db8::1'),
    event(3,'outage',''), event(4,'application','api.example.com',browser),
    event(5,'outage','blocked.example.com',browser), event(6,'recovered','api.example.com',browser)];
}

async function testListSearch(page) {
  seedSearchFixtures();
  await page.evaluate(() => update());
  await page.locator('[data-view="requests"]').click();
  await page.locator('#traffic-search').fill('SECOND browser');
  if (await page.locator('#requests-list > .request-group:visible').count() !== 1) throw Error('nested source path search failed');
  const group = page.locator('#requests-list > .request-group:visible');
  await group.locator('.request-details > summary').click();
  await group.locator('.source-details > summary').click();
  if (!await group.getByText('/opt/Second Browser/browser', {exact:false}).isVisible()) throw Error('source path not accessible without hover');
  await page.locator('#traffic-search').fill('8.8.8');
  if (await page.locator('#requests-list > .request-group:visible').count() !== 1) throw Error('IP search failed');
  await page.locator('#traffic-search').fill('absent.example');
  if (!await page.locator('#traffic-search-status').getByText('Ничего не найдено.', {exact:false}).isVisible()) throw Error('request search empty state missing');
  if (await page.locator('#request-count').textContent() !== '2') throw Error('search changed global pending count');
  await page.locator('#traffic-search').fill('');

  await page.locator('[data-view="rules"]').click();
  await page.locator('#rules-search').fill('Example Browser');
  if (await page.locator('#rules-list > .list-row:visible').count() !== 1) throw Error('rule source search failed');
  await page.locator('#rules-search').fill('  2001:DB8  ');
  if (await page.locator('#rules-list > .list-row:visible').count() !== 1) throw Error('IPv6 rule search failed');
  await page.evaluate(() => update());
  if (!await page.locator('#rules-search').evaluate(el => document.activeElement === el && el.value === '  2001:DB8  ')) throw Error('polling lost search/focus');
  await page.locator('#rules-search').fill('absent');
  if (await page.locator('#rules-list > .list-row:visible').count() || !(await page.locator('#rules-search-status').textContent()).includes('Ничего не найдено')) throw Error('rules empty search failed');
  await page.locator('#rules-search').fill('');
  if (await page.locator('#rules-list > .list-row:visible').count() !== 3) throw Error('clearing search did not restore rules');

  await page.locator('[data-view="applications"]').click();
  await page.locator('#applications-search').fill('SECOND browser');
  if (await page.locator('#applications-list > .list-row:visible').count() !== 1) throw Error('same-named application paths cannot be distinguished');
  await page.locator('#applications-search').fill('API.EXAMPLE');
  if (await page.locator('#applications-list > .list-row:visible').count() !== 1) throw Error('application destination search failed');
  await page.locator('#applications-search').fill('');

  await page.locator('[data-view="devices"]').click();
  await page.locator('#devices-search').fill('  МОЙ   android ');
  if (await page.locator('#devices-list > .list-row:visible').count() !== 1) throw Error('device name/platform search failed');
  await page.locator('#devices-search').fill('test-device');
  if (await page.locator('#devices-list > .list-row:visible').count() !== 1) throw Error('device ID search failed');
  await page.locator('#devices-search').fill('');

  await page.locator('[data-view="overview"]').click();
  if (await page.locator('#activity-list > .activity-item:visible').count() !== 3) throw Error('activity preview should show three entries');
  await page.locator('#activity-search').fill('SECOND browser');
  if (await page.locator('#activity-list > .activity-item:visible').count() !== 1 || !(await page.locator('#activity-list > .activity-item:visible').textContent()).includes('archive.example.net')) throw Error('history search skipped older events');
  await page.locator('#activity-list > .activity-item:visible .source-details > summary').click();
  if (!await page.locator('#activity-list').getByText('/opt/Second Browser/browser', {exact:false}).isVisible()) throw Error('event source path missing');
  const count = state.rules.length;
  await page.locator('#activity-list > .activity-item:visible button').click();
  if (!(await page.locator('#confirm-title').textContent()).includes('archive.example.net')) throw Error('filtered event approval targets wrong address');
  await page.getByRole('button',{name:'Отмена',exact:true}).click();
  if (state.rules.length !== count) throw Error('search or cancelled approval changed routing');
  await page.locator('#activity-search').fill('2001:DB8');
  if (!await page.locator('#activity-list > .activity-item:visible').getByText('Приложение-источник не определено',{exact:true}).isVisible()) throw Error('unknown source not explicit in history');
  await page.locator('#activity-search').fill('Событие службы');
  if (await page.locator('#activity-list > .activity-item:visible').count() !== 1) throw Error('system events confused with unknown owners');
  await page.locator('#activity-search').fill('not-present');
  if (await page.locator('#activity-list > .activity-item:visible').count() || !(await page.locator('#activity-search-status').textContent()).includes('Ничего не найдено')) throw Error('history empty search failed');
  await page.locator('#activity-search').fill('');
  await page.locator('#activity-toggle').click();
  if (await page.locator('#activity-list > .activity-item:visible').count() !== 6) throw Error('history expansion failed');
  await page.locator('#activity-list button').first().focus();
  await page.evaluate(() => { window.savedEvent = document.querySelector('#activity-list > .activity-item'); window.savedEventFocus = document.activeElement; });
  state.events.push({id:'7',kind:'outage',title:'<img src=x onerror=alert(1)>',message:'Новый сбой',target:'latest.example.com',source:state.applications[0],at:'2026-11-17T07:07:00Z'});
  await page.evaluate(() => update());
  if (!await page.evaluate(() => window.savedEvent === document.querySelectorAll('#activity-list > .activity-item')[1] && window.savedEventFocus === document.activeElement)) throw Error('new activity replaced existing rows/focus');
  if (await page.locator('#activity-list img').count()) throw Error('event HTML injection');
  await page.screenshot({path:'build/ui-activity-mobile.png',fullPage:true});
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)) throw Error('activity mobile overflow');
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#theme').click();
  await page.screenshot({path:'build/ui-activity-desktop.png',fullPage:true});
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)) throw Error('activity desktop overflow');
}

async function testAdminSearch(page) {
  admin.accounts.push({id:'alice-id',login:'alice',status:'active',created:'2026-01-01',rules:[]});
  admin.devices.push({id:'alice-phone',account_id:'alice-id',name:'Рабочий телефон',platform:'android',expires:'2027-02-01'});
  await page.locator('[data-filter="all"]').click();
  await page.locator('#refresh').click();
  await page.locator('#accounts-search').fill(' ALICE ');
  if (await page.locator('#accounts > .list-row').count() !== 1) throw Error('admin login search failed');
  await page.locator('#accounts-search').fill('рабочий ANDROID');
  if (await page.locator('#accounts > .list-row').count() !== 1) throw Error('admin device search failed');
  await page.evaluate(() => refresh());
  if (!await page.locator('#accounts-search').evaluate(el => document.activeElement === el && el.value === 'рабочий ANDROID')) throw Error('admin polling reset search/focus');
  await page.locator('#accounts').getByRole('button',{name:'Заблокировать',exact:true}).click();
  await page.locator('#confirm').getByRole('button',{name:'Подтвердить',exact:true}).click();
  await page.waitForFunction(() => document.getElementById('accounts').textContent.includes('Заблокирован'));
  if (admin.accounts[1].status !== 'blocked' || admin.accounts[0].status !== 'active') throw Error('search action selected wrong account');
  await page.locator('[data-filter="pending"]').click();
  if (await page.locator('#accounts > .list-row').count()) throw Error('search bypassed pending filter');
  await page.locator('[data-filter="all"]').click();
  await page.locator('#accounts-search').fill('no-match');
  if (!(await page.locator('#accounts').textContent()).includes('Ничего не найдено')) throw Error('admin search empty state missing');
  await page.locator('#accounts-search').fill('');
  if (await page.locator('#accounts > .list-row').count() !== 2) throw Error('admin search clear failed');
}
