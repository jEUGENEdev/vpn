'use strict';
// Run the actual main process with OS surfaces stubbed; no service is installed.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const main=fs.readFileSync(process.argv[2]||path.join(__dirname,'../apps/desktop/main.cjs'),'utf8');
let ready=false,interval,loads=0;const dialogs=[];
const app={isPackaged:false,getPath:()=>'/fixture',setPath(){},setName(){},setAppUserModelId(){},requestSingleInstanceLock:()=>true,
 on(){},whenReady:()=>Promise.resolve(),getLoginItemSettings:()=>({}),quit(){}};
class Window {
 constructor(){this.webContents={setWindowOpenHandler(){},on(){},mainFrame:{}};}
 removeMenu(){} on(){} async loadURL(){loads++;} show(){} focus(){}
}
class Tray {setToolTip(){} on(){} setContextMenu(){}}
class Notice {on(){} show(){}}
const electron={app,BrowserWindow:Window,ipcMain:{on(){},handle(){}},Notification:Notice,
 dialog:{showMessageBox:async(_window,options)=>{dialogs.push(options);return {response:0}}},shell:{},Tray,
 Menu:{buildFromTemplate:x=>x},nativeImage:{createFromPath:()=>({})},screen:{getPrimaryDisplay:()=>({workAreaSize:{width:1440,height:1000}})}};
vm.runInNewContext(main,{
 require:name=>name==='electron'?electron:name==='node:fs'?{mkdirSync(){},readFileSync:()=> 'fixture-token'}:
 name==='./control.cjs'?{createControl:()=>async()=>{if(!ready)throw Error('starting');return {events:[]}}}:require(name),
 __dirname:'/fixture/app',process:{platform:'win32',env:{PROGRAMDATA:'C:\\ProgramData'},argv:[]},
 setInterval:fn=>{interval=fn},console,URL,
});
(async()=>{
 for(let i=0;i<10&&!interval;i++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(loads,1,'installed UI must load while the service is still starting');
 assert.equal(dialogs.length,0,'startup is not proof that the service is absent');
 await interval();await interval();assert.equal(dialogs.length,0,'startup grace period');
 await interval();assert.equal(dialogs.length,1);
 assert.ok(!dialogs[0].detail.includes('выберите восстановление'));
 assert.ok(dialogs[0].detail.includes('Удалите'));
 assert.ok(!dialogs[0].detail.toLowerCase().includes('восстанов'));
 assert.ok(dialogs[0].detail.includes('ключ доступа'));
 ready=true;await interval();assert.equal(loads,1,'recovery must not reload the UI or lose input');
 console.log('PASS: installed UI loads before service readiness; grace period and explicit clean-install guidance');
})().catch(error=>{console.error(error);process.exitCode=1});
