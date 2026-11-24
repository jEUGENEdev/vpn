'use strict';
const {app,BrowserWindow,ipcMain,Notification,dialog,shell,Tray,Menu,nativeImage,screen}=require('electron');
const fs=require('node:fs');const path=require('node:path');
const {createControl,pickExecutable}=require('./control.cjs');
const {pathToFileURL}=require('node:url');
const uiPath=path.join(__dirname,app.isPackaged?'ui/index.html':'../../internal/ui/client/index.html');
const uiURL=pathToFileURL(uiPath).href;
const userData=path.join(app.getPath('appData'),'LineVPN');
fs.mkdirSync(userData,{recursive:true});
app.setPath('userData',userData);
app.setName('Сеть');
const iconPath=path.join(__dirname,'branding','set.png');
let controlAPI;
let win,tray,quitting=false,failures=0,lastFailure=0;const noticeTimes=new Map();const seenEvents=new Set();
const smokeReport=process.env.GITHUB_ACTIONS==='true'?process.env.LINEVPN_SMOKE_TEST_REPORT:'';
const stateDir=process.platform==='win32'?path.join(process.env.PROGRAMDATA,'LineVPN'):'/var/lib/linevpn';
function notify(event){if(!event||!['outage','recovered','suggestion','application'].includes(event.kind))return;if(event.id){const id=event.at+':'+event.id;if(seenEvents.has(id))return;seenEvents.add(id);if(seenEvents.size>300)seenEvents.delete(seenEvents.values().next().value)}const now=Date.now(),key=['suggestion','application'].includes(event.kind)?'suggestion':event.kind;const interval=['suggestion','application'].includes(event.kind)?300000:900000;if(now-(noticeTimes.get(key)||0)<(event.kind==='recovered'?60000:interval))return;noticeTimes.set(key,now);const notice=new Notification({title:String(event.title).slice(0,100),body:String(event.message).slice(0,500),icon:iconPath});notice.on('click',()=>{win?.show();win?.focus()});notice.show()}
app.setAppUserModelId('dev.linevpn.desktop');
if(!app.requestSingleInstanceLock())app.quit();else{
app.on('before-quit',()=>{quitting=true});
app.on('second-instance',()=>{win?.show();win?.focus()});
app.whenReady().then(async()=>{
 if(app.isPackaged&&!smokeReport){
  const legacyMarker=path.join(app.getPath('userData'),'background-enabled-set');
  const marker=process.platform==='win32'?legacyMarker+'-033':legacyMarker;
  if(!fs.existsSync(marker)){
   // Migrate our renamed launcher while retaining an explicitly disabled login item.
   const openAtLogin=!fs.existsSync(legacyMarker)||app.getLoginItemSettings({path:path.join(path.dirname(process.execPath),'LineVPN.exe'),args:['--background']}).openAtLogin;
   if(openAtLogin)app.setLoginItemSettings({openAtLogin:true,openAsHidden:true,args:['--background']});
   fs.mkdirSync(path.dirname(marker),{recursive:true});fs.writeFileSync(marker,'1');
  }
 }
 const workArea=screen.getPrimaryDisplay().workAreaSize;
 win=new BrowserWindow({show:!process.argv.includes("--background")&&!app.getLoginItemSettings().wasOpenedAtLogin,width:Math.min(1240,workArea.width),height:Math.min(850,workArea.height),minWidth:Math.min(640,workArea.width),minHeight:Math.min(480,workArea.height),title:'Сеть',icon:iconPath,backgroundColor:'#f4f5f8',webPreferences:{preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true}});win.removeMenu();win.on('close',e=>{if(!quitting){e.preventDefault();win.hide()}});
 const trayIcon=nativeImage.createFromPath(path.join(__dirname,'branding','tray.png'));
 tray=new Tray(trayIcon);tray.setToolTip('Сеть · уведомления работают в фоне');tray.on('click',()=>{win.show();win.focus()});tray.setContextMenu(Menu.buildFromTemplate([{label:'Открыть Сеть',click:()=>{win.show();win.focus()}},{type:'separator'},{label:'Удалить Сеть',click:async()=>{if(process.platform==='darwin'){await shell.openPath(path.join(process.resourcesPath,'agent','Uninstall-LineVPN.command'))}else{await shell.openExternal('ms-settings:appsfeatures')}}},{label:'Завершить интерфейс и уведомления',click:()=>{quitting=true;app.quit()}}]));
 win.webContents.setWindowOpenHandler(()=>({action:'deny'}));win.webContents.on('will-navigate',(event,url)=>{if(url.split('#')[0]!==uiURL)event.preventDefault()});
 function trustedFrame(event){return event.sender===win.webContents&&event.senderFrame===win.webContents.mainFrame&&event.senderFrame.url.split('#')[0]===uiURL}
 ipcMain.on('network-event',(event,value)=>{if(trustedFrame(event))notify(value)});
 ipcMain.handle('local-request',(event,action,data)=>{if(!trustedFrame(event)||!controlAPI)throw Error('Недоверенный источник команды');return controlAPI(action,data)});
 // Load the installed UI even while the service is starting; never leave a blank window.
 controlAPI=createControl({selectApplication:()=>pickExecutable(options=>dialog.showOpenDialog(win,options)),token:()=>fs.readFileSync(path.join(stateDir,'ui-token'),'utf8').trim(),session:()=>JSON.parse(fs.readFileSync(path.join(stateDir,'ui-session.json'),'utf8'))});
 await win.loadURL(uiURL);
 let startupNoticeShown=false,checking=false;
 async function check(){
  if(checking)return;
  checking=true;
  try{
   const state=await controlAPI('state');failures=0;
   if(smokeReport){const valid=await win.webContents.executeJavaScript("document.readyState === 'complete' && !!document.getElementById('auth-form')");if(!valid)throw Error('Packaged client UI did not load');fs.writeFileSync(smokeReport,'PASS: packaged Electron UI loaded with authenticated service state\n');app.exit(0);return}
   if(lastFailure){notify({kind:'recovered',title:'Служба снова работает',message:'Состояние VPN и маршрутов показано в приложении.'});lastFailure=0}
   for(const event of state.events||[])notify(event);
  }catch(e){
   failures++;
   if(smokeReport){console.error('Packaged UI smoke test failed:',e.message);app.exit(1);return}
   // Allow startup/restart time. An API error is not proof that no service exists.
   if(failures>=4&&!startupNoticeShown){
    startupNoticeShown=true;
    await dialog.showMessageBox(win,{type:'warning',title:'Нет связи со службой «Сеть»',message:'Фоновая служба не ответила',detail:process.platform==='darwin'?'Откройте «Установщик Сеть» из нового DMG, выберите «Удалить», затем запустите установщик снова и выберите «Установить». Локальные настройки и вход будут удалены. Понадобятся профиль сервера и ключ доступа.':'Удалите «Сеть» в параметрах Windows → Приложения, затем установите новый MSI. Локальные настройки и вход будут удалены. Понадобятся профиль сервера и ключ доступа. Если Windows запросит перезагрузку, выполните её перед установкой.',buttons:['Понятно']});
   }
   if(failures>=4&&Date.now()-lastFailure>900000){lastFailure=Date.now();notify({kind:'outage',title:'Служба VPN не отвечает',message:'Состояние VPN неизвестно. Системная защита сохраняется; дождитесь службы или явно выключите VPN.'})}
  }finally{checking=false}
 }
 await check();setInterval(check,5000);
});app.on('window-all-closed',()=>{});}
