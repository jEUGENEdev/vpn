'use strict';
const assert=require('node:assert/strict');
const {createControl,elevationCommand,pickExecutable}=require('../apps/desktop/control.cjs');
const id='a'.repeat(43),receipt='b'.repeat(43);
(async()=>{
 for(const platform of ['darwin','win32'])await testSettingsSession(platform);
 for(const [platform,system,selected,agent] of [
  ['darwin','darwin','/Applications/Тест.app','/Library/Application Support/LineVPN/linevpn-agent'],
  ['win32','windows',"C:\\Test's Apps\\Тест.exe",'C:\\Program Files\\LineVPN\\resources\\agent\\linevpn-agent.exe'],
 ]){
  const info={id:'a'.repeat(64),path:selected,name:'Тест',platform:system};
  let calls=0;
  const choose=async options=>{
   assert.deepEqual(options.properties,['openFile']);
   if(platform==='win32')assert.deepEqual(options.filters[0].extensions,['exe']);
   return {canceled:false,filePaths:[selected]};
  };
  const exec=async(program,args)=>{
   calls++;assert.equal(program,agent);assert.deepEqual(args,['--identify-application',selected]);
   return {stdout:JSON.stringify(info)};
  };
  assert.deepEqual(await pickExecutable(choose,platform,'C:\\Program Files\\LineVPN\\resources',exec),info);
  assert.equal(await pickExecutable(async()=>({canceled:true,filePaths:[]}),platform,'',exec),null);
  assert.equal(calls,1,'cancelled file picker launched a process');
 }
 const [exe,args]=elevationCommand('win32',"C:\\Program Files\\Сеть's\\resources",id,'C:\\Windows');
 assert.match(exe,/WindowsPowerShell/);assert.match(args.at(-1),/-Verb RunAs/);assert.match(args.at(-1),/Сеть''s/);
 assert.throws(()=>elevationCommand('darwin','',"'invalid",''),/Неверное/);
 let currentToken='first';
 const rotating=createControl({token:()=>currentToken,fetchImpl:async(_url,opts)=>({ok:true,json:async()=>opts.headers.Authorization})});
 assert.equal(await rotating('state'),'Bearer first');
 currentToken='second';assert.equal(await rotating('state'),'Bearer second','stale status token after service restart');
 await testPinnedStatusChannel();
 console.log('PASS: one OS approval for consecutive settings changes on Windows and macOS');
})().catch(e=>{console.error(e);process.exitCode=1});

async function testSettingsSession(platform) {
 const staged=[], changes=[], commands=[];
 const grant='s'.repeat(96), selected={id:'a'.repeat(64),path:'/Applications/Test.app/Contents/MacOS/Test',name:'Test',platform:'darwin'};
 let cancelled=false, picked=null, enabled=true, stateReads=0, failStateOnce=false, denyGrant=false;
 const response=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});
 const fetchImpl=async(url,opts)=>{
  const path=new URL(url).pathname, auth=opts.headers.Authorization;
  if(path==='/local/state'){
   assert.equal(auth,'Bearer read-only');stateReads++;
   if(failStateOnce){failStateOnce=false;throw Error('restarting')}
   return response({vpn_enabled:enabled});
  }
  if(path==='/local/control/request'){
   assert.equal(auth,'Bearer read-only');
   staged.push(JSON.parse(opts.body).action);return response({id,receipt},201);
  }
  if(path==='/local/control/result/'+id){
   assert.equal(auth,'Bearer '+receipt);
   const body=staged.at(-1)==='settings-session'?{token:grant,expires_at:Math.floor(Date.now()/1000)+3600}:{saved:true};
   return response({status:200,body});
  }
  assert.ok(path.startsWith('/local/control/settings/'),'unmediated write');
  if(denyGrant)return response({error:'Сеанс завершён'},401);
  assert.equal(auth,'Bearer '+grant);
  const action=path.slice('/local/control/settings/'.length),data=JSON.parse(opts.body);
  changes.push({action,data});
  if(action==='vpn'){enabled=data.enabled;failStateOnce=true}
  return response(action==='applications/add'?data:{saved:true});
 };
 const execute=async(program,args)=>{
  commands.push({program,args});
  if(cancelled)throw Error('cancel');
 };
 const api=createControl({platform,resources:'C:\\Program Files\\Сеть\\resources',systemRoot:'C:\\Windows',token:'read-only',fetchImpl,execute,
  selectApplication:async()=>picked,delay:async()=>{}});
 await api('state');assert.equal(commands.length,0);
 assert.equal(await api('pick-application'),null);assert.equal(commands.length,0,'cancelled picker requested admin');
 cancelled=true;
 await assert.rejects(()=>api('traffic-mode',{mode:'all'}),/подтверждение/);
 assert.equal(changes.length,0,'cancel changed policy');
 cancelled=false;
 assert.deepEqual(await api('applications',{id:'app',decision:'trusted'}),{saved:true});
 await api('rules',{action:'approve',target:'example.com'});
 await api('dismiss',{target:'example.net'});
 assert.deepEqual(await api('vpn',{enabled:false,confirm:true}),{vpn_enabled:false});
 await api('traffic-mode',{mode:'selective'});
 picked=selected;assert.deepEqual(await api('pick-application'),selected);
 assert.equal(commands.length,2,'a setting or service power cycle repeated OS approval');
 assert.deepEqual(staged,['settings-session','settings-session']);
 assert.deepEqual(changes.map(item=>item.action),['applications','rules','dismiss','vpn','traffic-mode','applications/add']);
 assert.ok(stateReads>=3,'did not wait through service restart');
 await assert.rejects(()=>api('applications/add',selected),/Неверная команда/);
 await assert.rejects(()=>api('pick-application',selected),/Неверная команда/);
 await assert.rejects(()=>api('../vpn',{}),/Неверная команда/);
 await api('access-key/rotate',{current_key:'fixture-secret'});
 assert.equal(staged.at(-1),'access-key/rotate','settings grant used for account keys');
 for(const {args} of commands)for(const secret of ['read-only',receipt,grant,'fixture-secret','trusted'])assert.ok(!args.join(' ').includes(secret),'secret or policy in command line');
 denyGrant=true;await assert.rejects(()=>api('rules',{action:'approve',target:'example.com'}));
 denyGrant=false;await api('rules',{action:'approve',target:'example.com'});
 assert.equal(staged.at(-1),'settings-session','invalid grant was retained');
}

async function testPinnedStatusChannel(){
 const fs=require('node:fs'),os=require('node:os'),https=require('node:https');
 const {execFileSync}=require('node:child_process');
 const {X509Certificate}=require('node:crypto');
 const {pinnedFetch}=require('../apps/desktop/control.cjs');
 const directory=fs.mkdtempSync(pathForTest().join(os.tmpdir(),'set-tls-'));
 let server;
 try {
  for(const name of ['real','impostor'])execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',directory+'/'+name+'.key','-out',directory+'/'+name+'.pem','-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});
  let received=0;
  server=https.createServer({key:fs.readFileSync(directory+'/real.key'),cert:fs.readFileSync(directory+'/real.pem')},(req,res)=>{received++;res.statusCode=req.method==='POST'?403:200;res.end('{"ok":true}')});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address='https://127.0.0.1:'+server.address().port+'/local/state';
  const options={method:'GET',headers:{Authorization:'Bearer status-fixture'},signal:AbortSignal.timeout(5000)};
  const cert=name=>new X509Certificate(fs.readFileSync(directory+'/'+name+'.pem')).raw.toString('base64');
  const response=await pinnedFetch(address,options,cert('real'));assert.deepEqual(await response.json(),{ok:true});
  await assert.rejects(()=>pinnedFetch(address,options,cert('impostor')),/сертификата/);
  assert.equal(received,1,'credentials reached untrusted loopback server');
  const rejected=await pinnedFetch(address,{...options,method:'POST',body:'{"id":"fixture"}'},cert('real'));assert.equal(rejected.status,403);assert.equal(rejected.ok,false);
  console.log('PASS: real desktop TLS validates the service certificate before sending data');
 }finally{if(server)await new Promise(resolve=>server.close(resolve));fs.rmSync(directory,{recursive:true,force:true})}
}
function pathForTest(){return require('node:path')}
