const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('linevpn',{notify:event=>ipcRenderer.send('network-event',event),request:(action,data)=>ipcRenderer.invoke('local-request',action,data)});
