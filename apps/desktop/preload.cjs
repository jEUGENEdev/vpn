const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('linevpn',{notify:event=>ipcRenderer.send('network-event',event)});
