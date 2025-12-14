const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveApiKeys: (apiKeys) => ipcRenderer.invoke('save-api-keys', apiKeys),
  savePreferences: (preferences) => ipcRenderer.invoke('save-preferences', preferences),

  // Dark mode
  getDarkMode: () => ipcRenderer.invoke('get-dark-mode'),
  setDarkMode: (darkMode) => ipcRenderer.invoke('set-dark-mode', darkMode),

  // About dialog
  showAbout: () => ipcRenderer.invoke('show-about'),

  // Platform info
  platform: process.platform,
  isElectron: true
});
