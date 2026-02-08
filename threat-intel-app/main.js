const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { fork } = require('child_process');
const Store = require('electron-store');

// Initialize electron-store for settings
const store = new Store({
  name: 'threat-intel-settings',
  defaults: {
    apiKeys: {
      virusTotal: '',
      abuseIPDB: '',
      urlScan: '',
      greyNoise: '',
      shodan: '',
      alienVault: '',
      mxToolbox: '',
      hybridAnalysis: ''
    },
    preferences: {
      darkMode: true,
      serverPort: 3001
    }
  },
  encryptionKey: 'threat-intel-checker-v1'
});

let mainWindow;
let serverProcess;

// Server port
const SERVER_PORT = store.get('preferences.serverPort', 3001);

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 800,
    minHeight: 600,
    title: 'Threat Intel Checker',
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true
    },
    autoHideMenuBar: true,
    backgroundColor: '#1a1a2e'
  });

  // In development, load from React dev server
  // In production, load from built files
  const isDev = !app.isPackaged;

  if (isDev) {
    mainWindow.loadURL(`http://localhost:${SERVER_PORT}`);
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, 'src', 'build', 'index.html'));
  }

  // Handle external links - only allow https URLs to prevent protocol handler abuse
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function startServer() {
  return new Promise((resolve, reject) => {
    const serverPath = path.join(__dirname, 'server', 'index.js');

    // Set environment variables for the server
    const env = {
      ...process.env,
      PORT: SERVER_PORT,
      VIRUSTOTAL_API_KEY: store.get('apiKeys.virusTotal', ''),
      ABUSEIPDB_API_KEY: store.get('apiKeys.abuseIPDB', ''),
      URLSCAN_API_KEY: store.get('apiKeys.urlScan', ''),
      GREYNOISE_API_KEY: store.get('apiKeys.greyNoise', ''),
      SHODAN_API_KEY: store.get('apiKeys.shodan', ''),
      ALIENVAULT_OTX_API_KEY: store.get('apiKeys.alienVault', ''),
      MXTOOLBOX_API_KEY: store.get('apiKeys.mxToolbox', ''),
      HYBRID_ANALYSIS_API_KEY: store.get('apiKeys.hybridAnalysis', '')
    };

    serverProcess = fork(serverPath, [], { env, silent: true });

    serverProcess.stdout.on('data', (data) => {
      console.log(`Server: ${data}`);
    });

    serverProcess.stderr.on('data', (data) => {
      console.error(`Server Error: ${data}`);
    });

    serverProcess.on('message', (message) => {
      if (message === 'ready') {
        console.log(`Server started on port ${SERVER_PORT}`);
        resolve();
      }
    });

    serverProcess.on('error', (error) => {
      console.error('Failed to start server:', error);
      reject(error);
    });

    // Give server time to start
    setTimeout(resolve, 2000);
  });
}

function stopServer() {
  if (serverProcess) {
    serverProcess.kill();
    serverProcess = null;
  }
}

// IPC Handlers for settings
ipcMain.handle('get-settings', () => {
  return {
    apiKeys: store.get('apiKeys'),
    preferences: store.get('preferences')
  };
});

ipcMain.handle('save-api-keys', (event, apiKeys) => {
  store.set('apiKeys', apiKeys);
  // Restart server with new API keys
  stopServer();
  startServer();
  return { success: true };
});

ipcMain.handle('save-preferences', (event, preferences) => {
  store.set('preferences', preferences);
  return { success: true };
});

ipcMain.handle('get-dark-mode', () => {
  return store.get('preferences.darkMode', true);
});

ipcMain.handle('set-dark-mode', (event, darkMode) => {
  store.set('preferences.darkMode', darkMode);
  return { success: true };
});

ipcMain.handle('show-about', () => {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'About Threat Intel Checker',
    message: 'Threat Intel Checker',
    detail: `Version: ${app.getVersion()}\n\nA standalone threat intelligence lookup tool.\n\nQueries 9+ threat intelligence sources in parallel:\n- VirusTotal\n- AbuseIPDB\n- URLScan.io\n- GreyNoise\n- Shodan\n- AlienVault OTX\n- MXToolbox\n- Hybrid Analysis\n- ARIN RDAP`,
    buttons: ['OK']
  });
});

// App lifecycle
app.whenReady().then(async () => {
  try {
    await startServer();
    createWindow();
  } catch (error) {
    console.error('Failed to start application:', error);
    dialog.showErrorBox('Startup Error', `Failed to start the application: ${error.message}`);
    app.quit();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  stopServer();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  stopServer();
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  dialog.showErrorBox('Error', `An unexpected error occurred: ${error.message}`);
});
