const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('linevpn',{pickApplication:()=>ipcRenderer.invoke('local-request','pick-application'),notify:event=>ipcRenderer.send('network-event',event),request:(action,data)=>ipcRenderer.invoke('local-request',action,data)});
