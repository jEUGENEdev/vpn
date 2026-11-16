'use strict';
const {app,BrowserWindow,ipcMain,Notification,dialog,shell}=require('electron');
const fs=require('node:fs');const path=require('node:path');
let win,failures=0,lastFailure=0;const noticeTimes=new Map();const seenEvents=new Set();
const base='http://127.0.0.1:17891';
const stateDir=process.platform==='win32'?path.join(process.env.PROGRAMDATA,'LineVPN'):'/var/lib/linevpn';
function notify(event){if(!event||!['outage','recovered','suggestion'].includes(event.kind))return;if(event.id){const id=event.at+':'+event.id;if(seenEvents.has(id))return;seenEvents.add(id);if(seenEvents.size>300)seenEvents.delete(seenEvents.values().next().value)}const now=Date.now(),key=event.kind==='suggestion'?'suggestion':event.kind;const interval=event.kind==='suggestion'?300000:900000;if(now-(noticeTimes.get(key)||0)<(event.kind==='recovered'?60000:interval))return;noticeTimes.set(key,now);new Notification({title:String(event.title).slice(0,100),body:String(event.message).slice(0,500)}).show()}
app.setAppUserModelId('dev.linevpn.desktop');
if(!app.requestSingleInstanceLock())app.quit();else{
app.on('second-instance',()=>{win?.show();win?.focus()});
app.whenReady().then(async()=>{
 win=new BrowserWindow({width:1240,height:850,minWidth:760,minHeight:620,title:'Линия VPN',backgroundColor:'#f4f5f8',webPreferences:{preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true}});win.removeMenu();
 win.webContents.setWindowOpenHandler(()=>({action:'deny'}));win.webContents.on('will-navigate',(event,url)=>{if(!url.startsWith(base+'/'))event.preventDefault()});
 ipcMain.on('network-event',(event,value)=>{if(event.senderFrame?.url.startsWith(base+'/'))notify(value)});
 let loaded=false;async function check(){try{const token=fs.readFileSync(path.join(stateDir,'ui-token'),'utf8').trim();const res=await fetch(base+'/local/state',{headers:{Authorization:'Bearer '+token},signal:AbortSignal.timeout(2500)});if(!res.ok)throw Error('service');const state=await res.json();failures=0;if(!loaded){loaded=true;await win.loadURL(base+'/#token='+encodeURIComponent(token))}if(lastFailure){notify({kind:'recovered',title:'Защита восстановлена',message:'Фоновая служба снова работает.'});lastFailure=0}for(const event of state.events||[])notify(event)}catch(e){failures++;if(failures>=2&&Date.now()-lastFailure>900000){lastFailure=Date.now();notify({kind:'outage',title:'Служба VPN не отвечает',message:'Системная блокировка остаётся включённой, если служба уже была установлена. Откройте Линию для восстановления.'})}if(!loaded&&failures===1){const result=await dialog.showMessageBox(win,{type:'warning',title:'Установка фоновой службы',message:'Нужно установить службу Линии',detail:process.platform==='darwin'?'Откройте Install-Service.command в DMG. Потребуется пароль администратора.':'Служба устанавливается вместе с MSI. Запустите установщик LineVPN повторно и выберите восстановление, затем откройте приложение.',buttons:['Открыть папку службы','Позже']});if(result.response===0)shell.openPath(path.join(process.resourcesPath,'agent'))}}}
 await check();setInterval(check,5000);
});app.on('window-all-closed',()=>app.quit());}
