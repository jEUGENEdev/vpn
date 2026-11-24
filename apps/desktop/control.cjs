'use strict';
const {execFile} = require('node:child_process');
const path = require('node:path');
const {promisify} = require('node:util');
const run = promisify(execFile);
const base = 'https://127.0.0.1:17891';
const https=require('node:https');
const {X509Certificate}=require('node:crypto');
const actions = new Set(['bootstrap','login','register','pair/claim','rules','dismiss','pair','revoke','applications','vpn','traffic-mode','access-key/rotate']);
const ticketPattern = /^[A-Za-z0-9_-]{43}$/;

// Only an opaque request ID is placed in process arguments. Credentials, server
// profiles and result receipts never enter the elevated command line.
function elevationCommand(platform, resources, id, systemRoot) {
  if (!ticketPattern.test(id)) throw Error('Неверное подтверждение');
  if (platform === 'darwin') {
    const command = "'/Library/Application Support/LineVPN/linevpn-agent' --approve-control " + id;
    return ['/usr/bin/osascript', ['-e', 'do shell script ' + JSON.stringify(command) + ' with administrator privileges']];
  }
  if (platform === 'win32') {
    const agent = path.win32.join(resources, 'agent', 'linevpn-agent.exe');
    const quoted = "'" + agent.replaceAll("'", "''") + "'";
    const script = "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath " + quoted + " -ArgumentList @('--approve-control','" + id + "') -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode";
    return [path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile','-NonInteractive','-Command',script]];
  }
  throw Error('Управление поддерживается в Windows и macOS');
}

function createControl({token, session, platform=process.platform, resources=process.resourcesPath, systemRoot=process.env.SystemRoot, fetchImpl, execute=run, delay=ms=>new Promise(resolve=>setTimeout(resolve,ms))}) {
  let busy=false;
  const transport=fetchImpl||((url,options)=>pinnedFetch(url,options,session().certificate));
  async function request(pathName, body, bearer=token) {
    const response=await transport(base+'/local/'+pathName, {method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+(typeof bearer==='function'?bearer():bearer),'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(pathName==='state'?3000:30000)});
    const data=await response.json();
    if (!response.ok) throw Error(data.error||'Служба отклонила запрос');
    return data;
  }
  return async (action,data) => {
    if (action==='state' && data===undefined) return request('state');
    if (!actions.has(action) || !data || typeof data!=='object' || Array.isArray(data) || Buffer.byteLength(JSON.stringify(data))>30000) throw Error('Неверная команда');
    if (busy) throw Error('Завершите текущее системное подтверждение');
    busy=true;
    try {
      const ticket=await request('control/request',{action,data});
      if (!ticketPattern.test(ticket.id) || !ticketPattern.test(ticket.receipt)) throw Error('Неверный ответ службы');
      const [program,args]=elevationCommand(platform,resources,ticket.id,systemRoot);
      try { await execute(program,args,{timeout:180000,maxBuffer:8192,windowsHide:true}); }
      catch { throw Error('Системное подтверждение отменено или завершилось ошибкой. Проверьте текущее состояние.'); }
      let result;
      try { result=await request('control/result/'+ticket.id,undefined,ticket.receipt); }
      catch (error) { if(action!=='vpn')throw error; }
      if(result?.pending)throw Error('Результат ещё не получен; проверьте состояние');
      if(result && (result.status<200||result.status>=300))throw Error(result.body?.error||'Служба отклонила изменение');
      // Power changes restart the service, so its in-memory receipt may be gone.
      // The helper only exits successfully after the authenticated commit reply.
      if (action==='vpn') {
        for(let attempt=0;attempt<60;attempt++) {
          let state;
          try {state=await request('state')}catch { /* readiness retry; never repeat a mutation */ }
          if(state?.power_error)throw Error(state.power_error);
          if(state&&!state.power_transition&&state.vpn_enabled===data.enabled)return state;
          await delay(500);
        }
        throw Error('Служба не подтвердила состояние VPN. Проверьте состояние перед повторным изменением.');
      }
      return result.body;
    } finally {busy=false;}
  };
}
// Trust only the certificate read from the service-owned status file. Never use
// NODE_TLS_REJECT_UNAUTHORIZED, a global certificate exception, or HTTP fallback.
function pinnedFetch(url,options,certificate){
 const destination=new URL(url);
 if(destination.protocol!=='https:'||destination.hostname!=='127.0.0.1'||destination.username||destination.password)throw Error('Недоверенный адрес службы');
 const ca=new X509Certificate(Buffer.from(certificate,'base64')).toString();
 return new Promise((resolve,reject)=>{
  const req=https.request(destination,{method:options.method,headers:options.headers,agent:false,ca,rejectUnauthorized:true,minVersion:'TLSv1.3',signal:options.signal},res=>{
   const chunks=[];let size=0;
   res.on('data',chunk=>{size+=chunk.length;if(size>8*1024*1024){res.destroy(Error('Ответ службы слишком большой'));return}chunks.push(chunk)});
   res.on('error',reject);
   res.on('end',()=>{try{const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));resolve({status:res.statusCode,ok:res.statusCode>=200&&res.statusCode<300,json:async()=>value})}catch{reject(Error('Неверный ответ службы'))}});
  });
  req.on('error',error=>{
   const code=typeof error.code==='string'&&/^[A-Z0-9_]{1,80}$/.test(error.code)?' ('+error.code+')':'';
   reject(Error('Служба недоступна или не прошла проверку сертификата'+code));
  });
  if(options.body!==undefined)req.write(options.body);
  req.end();
 });
}
module.exports={createControl,elevationCommand,pinnedFetch};
