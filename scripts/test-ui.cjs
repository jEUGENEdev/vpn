// Local UI contract test. All account/domain data below is a test fixture.
const fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'../internal/ui/client');
const state={account_id:'test-account',device_id:'test-device',status:'ready',tunnel:true,guard:true,rules:['example.com','example.org','8.8.8.8'],requests:[{target:'api.example.net',count:4,last_seen:new Date().toISOString()}],devices:[{id:'test-device',name:'Личный ноутбук',platform:'darwin',expires:'2027-02-01',revoked:false},{id:'phone',name:'Мой телефон',platform:'android',expires:'2027-02-01',revoked:false}],revision:1,events:[]};
const bootstrapProfile='linevpn://8.8.8.8:8443?pin='+'A'.repeat(43);let bootstrapFailure=false;
const admin={accounts:[{id:'pending-user',login:'new-user',status:'pending',created:new Date().toISOString(),rules:[]}],devices:[]};
const server=http.createServer(async(req,res)=>{if(req.url.startsWith('/api/admin/')){let raw='';for await(const b of req)raw+=b;const data=raw?JSON.parse(raw):{};res.setHeader('Content-Type','application/json');if(req.url==='/api/admin/login'){res.end(JSON.stringify({token:'admin-test'}));return}if(req.headers.authorization!=='Bearer admin-test')throw Error('admin auth missing');if(req.url==='/api/admin/bootstrap'){res.statusCode=bootstrapFailure?503:200;res.end(JSON.stringify(bootstrapFailure?{error:'Профиль временно недоступен'}:{profile:bootstrapProfile}));return}if(req.url==='/api/admin/account')admin.accounts[0].status=data.status;res.end(JSON.stringify(req.url==='/api/admin/accounts'?admin:{ok:true}));return}if(req.url.startsWith('/local/')){if(req.headers.authorization!=='Bearer ui-test')throw Error('auth missing');let data='';for await(const chunk of req)data+=chunk;if(req.url==='/local/rules'){const body=JSON.parse(data);if(body.action==='approve'){state.rules.push(body.target);state.requests=[]}else state.rules=state.rules.filter(x=>x!==body.target);state.revision++}res.setHeader('Content-Type','application/json');res.end(JSON.stringify(req.url==='/local/state'?state:{ok:true}));return}const file=req.url.startsWith('/admin/')?path.join(root,'../admin',req.url==='/admin/'?'index.html':req.url.slice(7)):path.join(root,req.url==='/'?'index.html':req.url);res.setHeader('Content-Type',file.endsWith('.css')?'text/css':file.endsWith('.js')?'text/javascript':'text/html');res.end(fs.readFileSync(file))});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||undefined,headless:true,args:['--no-sandbox']});const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(`http://127.0.0.1:${server.address().port}/#token=ui-test`);await page.locator('#dashboard').waitFor({state:'visible'});await page.screenshot({path:'build/ui-desktop.png',fullPage:true});await page.getByRole('button',{name:'Разобрать запросы'}).click();await page.locator('#requests-list').getByRole('button',{name:'Разрешить VPN'}).click();await page.locator('#confirm').getByRole('button',{name:'Подтвердить'}).click();await page.waitForFunction(()=>document.getElementById('approved-count').textContent==='4');await page.locator('[data-view="rules"]').click();await page.locator('#rule-input').fill('<img src=x onerror=alert(1)>.example.com');await page.locator('#rule-form .primary').click();if(await page.locator('#confirm img').count())throw Error('HTML injection');await page.getByRole('button',{name:'Отмена',exact:true}).click();await page.locator('[data-view="overview"]').click();await page.setViewportSize({width:390,height:844});await page.screenshot({path:'build/ui-android.png',fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('mobile overflow');await page.locator('#theme').click();await page.screenshot({path:'build/ui-dark.png',fullPage:true});await page.setViewportSize({width:1440,height:1000});await page.goto(`http://127.0.0.1:${server.address().port}/admin/`);await page.locator('#password').fill('test-only-password');await page.getByRole('button',{name:'Войти →',exact:true}).click();await page.locator('#content').waitFor({state:'visible'});await page.screenshot({path:'build/ui-admin.png',fullPage:true});await page.getByRole('button',{name:'Одобрить ↗',exact:true}).click();await page.locator('#confirm').getByRole('button',{name:'Подтвердить'}).click();await page.waitForFunction(()=>document.getElementById('pending-count').textContent==='0');if(admin.accounts[0].status!=='active')throw Error('admin approval failed');await testAdminProfile(page);if(errors.length)throw Error(errors.join('\n'));await browser.close();server.close();console.log('UI approval, escaping, mobile layout and theme checks passed')})().catch(e=>{console.error(e);server.close();process.exit(1)});
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
