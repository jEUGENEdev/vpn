'use strict';
// Disposable native acceptance uses the same pinned TLS transport as Electron.
const fs=require('node:fs');
const {pinnedFetch}=require('../apps/desktop/control.cjs');
(async()=>{
 if(process.env.GITHUB_ACTIONS!=='true')throw Error('Disposable native CI hosts only');
 const request=JSON.parse(fs.readFileSync(0,'utf8'));
 const response=await pinnedFetch(request.url,{
  method:request.body===null?'GET':'POST',
  headers:{Authorization:'Bearer '+request.token,'Content-Type':'application/json'},
  ...(request.body===null?{}:{body:JSON.stringify(request.body)}),
  signal:AbortSignal.timeout(30000)
 },request.certificate);
 process.stdout.write(JSON.stringify({status:response.status,body:await response.json()}));
})().catch(error=>{console.error(error.message);process.exitCode=1});
