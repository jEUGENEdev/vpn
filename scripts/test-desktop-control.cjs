'use strict';
const assert=require('node:assert/strict');
const {createControl,elevationCommand}=require('../apps/desktop/control.cjs');
const id='a'.repeat(43),receipt='b'.repeat(43);
(async()=>{
 const writes=[],commands=[];let allowed=false,failElevation=false;
 const fetchImpl=async(url,opts)=>{
  writes.push({url,opts});
  if(url.endsWith('/control/request'))return {ok:true,json:async()=>({id,receipt})};
  if(url.includes('/control/result/')){assert.equal(opts.headers.Authorization,'Bearer '+receipt);return {ok:true,json:async()=>({status:200,body:{saved:true}})}}
  if(url.endsWith('/state'))return {ok:true,json:async()=>({vpn_enabled:allowed})};
  throw Error('unmediated write');
 };
 const execute=async(program,args)=>{commands.push({program,args});if(failElevation)throw Error('cancel');allowed=true;};
 const api=createControl({token:'read-only',platform:'darwin',resources:'/Applications/Сеть.app',fetchImpl,execute,delay:async()=>{}});
 const result=await api('applications',{id:'app',decision:'trusted'});assert.deepEqual(result,{saved:true});
 assert.equal(commands.length,1);assert.equal(commands[0].program,'/usr/bin/osascript');
 assert.ok(commands[0].args.join(' ').includes('administrator privileges'));
 for(const secret of ['read-only',receipt,'trusted'])assert.ok(!commands[0].args.join(' ').includes(secret),'secret/payload in argv');
 await api('state');assert.equal(commands.length,1,'status requested elevation');
 failElevation=true;await assert.rejects(()=>api('traffic-mode',{mode:'all'}),/подтверждение/);
 assert.equal(writes.filter(x=>x.url.includes('/control/result/')).length,1,'read result after cancelled approval');
 await assert.rejects(()=>api('../vpn',{}),/Неверная команда/);
 assert.throws(()=>elevationCommand('darwin','',"';touch /tmp/x",''),/Неверное/);
 const [exe,args]=elevationCommand('win32',"C:\\Program Files\\Сеть's\\resources",id,'C:\\Windows');
 assert.match(exe,/WindowsPowerShell/);assert.match(args.at(-1),/-Verb RunAs/);assert.match(args.at(-1),/Сеть''s/);
 failElevation=false;await api('vpn',{enabled:true});
 assert.ok(writes.every(x=>x.url.endsWith('/state')||x.url.includes('/control/')),'public mutation endpoint called');
 let currentToken='first';
 const rotating=createControl({token:()=>currentToken,fetchImpl:async(_url,opts)=>({ok:true,json:async()=>opts.headers.Authorization})});
 assert.equal(await rotating('state'),'Bearer first');
 currentToken='second';assert.equal(await rotating('state'),'Bearer second','stale status token after service restart');
 await testPinnedStatusChannel();
 console.log('PASS: desktop broker requires elevation, hides secrets, validates actions and handles cancellation');
})().catch(e=>{console.error(e);process.exitCode=1});

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
  server=https.createServer({key:fs.readFileSync(directory+'/real.key'),cert:fs.readFileSync(directory+'/real.pem')},(req,res)=>{received++;res.end('{"ok":true}')});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address='https://127.0.0.1:'+server.address().port+'/local/state';
  const options={method:'GET',headers:{Authorization:'Bearer status-fixture'},signal:AbortSignal.timeout(5000)};
  const cert=name=>new X509Certificate(fs.readFileSync(directory+'/'+name+'.pem')).raw.toString('base64');
  const response=await pinnedFetch(address,options,cert('real'));assert.deepEqual(await response.json(),{ok:true});
  await assert.rejects(()=>pinnedFetch(address,options,cert('impostor')),/сертификата/);
  assert.equal(received,1,'credentials reached untrusted loopback server');
  console.log('PASS: real desktop TLS validates the service certificate before sending data');
 }finally{if(server)await new Promise(resolve=>server.close(resolve));fs.rmSync(directory,{recursive:true,force:true})}
}
function pathForTest(){return require('node:path')}
