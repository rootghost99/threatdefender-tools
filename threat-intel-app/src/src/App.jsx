import React, { useState, useEffect } from 'react';
import ThreatIntelLookup from './components/ThreatIntelLookup';
import Settings from './components/Settings';

function App() {
  const [darkMode, setDarkMode] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [apiStatus, setApiStatus] = useState(null);

  // Load dark mode preference from Electron store
  useEffect(() => {
    const loadDarkMode = async () => {
      if (window.electronAPI) {
        const isDark = await window.electronAPI.getDarkMode();
        setDarkMode(isDark);
      }
    };
    loadDarkMode();
  }, []);

  // Check API status on load
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await fetch('/api/status');
        const data = await response.json();
        setApiStatus(data);
      } catch (error) {
        console.error('Failed to check API status:', error);
      }
    };
    checkStatus();
  }, [showSettings]); // Refresh when settings close

  const toggleDarkMode = async () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    if (window.electronAPI) {
      await window.electronAPI.setDarkMode(newMode);
    }
  };

  const handleShowAbout = () => {
    if (window.electronAPI) {
      window.electronAPI.showAbout();
    }
  };

  // Count configured APIs
  const configuredCount = apiStatus
    ? Object.values(apiStatus.configuredApis || {}).filter(Boolean).length + (apiStatus.arinRdap ? 1 : 0)
    : 0;

  return (
    <div className={`min-h-screen ${darkMode ? 'dark bg-gray-900' : 'light bg-gray-100'}`}>
      {/* Header */}
      <header className={`${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border-b shadow-md`}>
        <div className="max-w-4xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-2xl">🛡️</span>
              <div>
                <h1 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  Threat Intel Checker
                </h1>
                <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  Multi-source threat intelligence lookup
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {/* API Status Indicator */}
              <div
                className={`px-3 py-1 rounded-full text-xs font-semibold cursor-pointer ${
                  configuredCount >= 5
                    ? darkMode ? 'bg-green-900 text-green-300' : 'bg-green-100 text-green-800'
                    : configuredCount >= 2
                    ? darkMode ? 'bg-yellow-900 text-yellow-300' : 'bg-yellow-100 text-yellow-800'
                    : darkMode ? 'bg-red-900 text-red-300' : 'bg-red-100 text-red-800'
                }`}
                onClick={() => setShowSettings(true)}
                title="Click to configure API keys"
              >
                {configuredCount}/9 APIs
              </div>

              {/* Settings Button */}
              <button
                onClick={() => setShowSettings(true)}
                className={`p-2 rounded-lg transition ${
                  darkMode
                    ? 'hover:bg-gray-700 text-gray-300'
                    : 'hover:bg-gray-100 text-gray-600'
                }`}
                title="Settings"
              >
                ⚙️
              </button>

              {/* Dark Mode Toggle */}
              <button
                onClick={toggleDarkMode}
                className={`p-2 rounded-lg transition ${
                  darkMode
                    ? 'hover:bg-gray-700 text-gray-300'
                    : 'hover:bg-gray-100 text-gray-600'
                }`}
                title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              >
                {darkMode ? '☀️' : '🌙'}
              </button>

              {/* About Button */}
              <button
                onClick={handleShowAbout}
                className={`p-2 rounded-lg transition ${
                  darkMode
                    ? 'hover:bg-gray-700 text-gray-300'
                    : 'hover:bg-gray-100 text-gray-600'
                }`}
                title="About"
              >
                ℹ️
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-6 py-8">
        {showSettings ? (
          <Settings
            darkMode={darkMode}
            onClose={() => setShowSettings(false)}
            apiStatus={apiStatus}
          />
        ) : (
          <ThreatIntelLookup darkMode={darkMode} />
        )}
      </main>

      {/* Footer */}
      <footer className={`${darkMode ? 'bg-gray-800 border-gray-700 text-gray-400' : 'bg-white border-gray-200 text-gray-500'} border-t py-4 mt-auto`}>
        <div className="max-w-4xl mx-auto px-6 text-center text-sm">
          <p>Threat Intel Checker v1.0.0 • Standalone Windows Application</p>
          <p className="text-xs mt-1">
            Queries: VirusTotal, AbuseIPDB, URLScan.io, GreyNoise, Shodan, AlienVault OTX, MXToolbox, Hybrid Analysis, ARIN RDAP
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
