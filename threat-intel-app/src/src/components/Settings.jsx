import React, { useState, useEffect } from 'react';

const API_CONFIGS = [
  { key: 'virusTotal', name: 'VirusTotal', description: 'File, IP, URL, and domain reputation', url: 'https://www.virustotal.com/gui/my-apikey' },
  { key: 'abuseIPDB', name: 'AbuseIPDB', description: 'IP abuse reports and reputation', url: 'https://www.abuseipdb.com/account/api' },
  { key: 'urlScan', name: 'URLScan.io', description: 'URL and domain scanning', url: 'https://urlscan.io/user/profile/' },
  { key: 'greyNoise', name: 'GreyNoise', description: 'IP noise and RIOT classification', url: 'https://viz.greynoise.io/account/api-key' },
  { key: 'shodan', name: 'Shodan', description: 'Open ports and services', url: 'https://account.shodan.io/' },
  { key: 'alienVault', name: 'AlienVault OTX', description: 'Threat pulses and intelligence', url: 'https://otx.alienvault.com/api' },
  { key: 'mxToolbox', name: 'MXToolbox', description: 'WHOIS and ARIN data', url: 'https://mxtoolbox.com/user/api/' },
  { key: 'hybridAnalysis', name: 'Hybrid Analysis', description: 'Malware sandbox analysis', url: 'https://www.hybrid-analysis.com/my-account?tab=api-key' }
];

export default function Settings({ darkMode, onClose, apiStatus }) {
  const [apiKeys, setApiKeys] = useState({
    virusTotal: '',
    abuseIPDB: '',
    urlScan: '',
    greyNoise: '',
    shodan: '',
    alienVault: '',
    mxToolbox: '',
    hybridAnalysis: ''
  });
  const [showKeys, setShowKeys] = useState({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  // Load current settings
  useEffect(() => {
    const loadSettings = async () => {
      if (window.electronAPI) {
        const settings = await window.electronAPI.getSettings();
        if (settings?.apiKeys) {
          setApiKeys(settings.apiKeys);
        }
      }
    };
    loadSettings();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      if (window.electronAPI) {
        await window.electronAPI.saveApiKeys(apiKeys);
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch (error) {
      console.error('Failed to save settings:', error);
    } finally {
      setSaving(false);
    }
  };

  const toggleShowKey = (key) => {
    setShowKeys(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleKeyChange = (key, value) => {
    setApiKeys(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className={`rounded-lg shadow-lg ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'} p-6`}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            ⚙️ Settings
          </h2>
          <p className={`text-sm mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Configure your API keys for threat intelligence sources
          </p>
        </div>
        <button
          onClick={onClose}
          className={`p-2 rounded-lg transition ${
            darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-600'
          }`}
        >
          ✕
        </button>
      </div>

      {/* Info banner */}
      <div className={`mb-6 p-4 rounded-lg ${darkMode ? 'bg-blue-900/50 border border-blue-700' : 'bg-blue-50 border border-blue-200'}`}>
        <p className={`text-sm ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>
          <strong>Note:</strong> API keys are stored securely on your local machine and are never transmitted elsewhere.
          ARIN RDAP does not require an API key and is always available.
        </p>
      </div>

      {/* API Key inputs */}
      <div className="space-y-4">
        {API_CONFIGS.map(api => (
          <div
            key={api.key}
            className={`p-4 rounded-lg border ${
              darkMode ? 'bg-gray-700/50 border-gray-600' : 'bg-gray-50 border-gray-200'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span
                  className={`w-2 h-2 rounded-full ${
                    apiStatus?.configuredApis?.[api.key]
                      ? 'bg-green-500'
                      : 'bg-gray-400'
                  }`}
                />
                <label className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  {api.name}
                </label>
              </div>
              <a
                href={api.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-500 hover:text-blue-600"
              >
                Get API Key →
              </a>
            </div>
            <p className={`text-xs mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
              {api.description}
            </p>
            <div className="flex gap-2">
              <input
                type={showKeys[api.key] ? 'text' : 'password'}
                value={apiKeys[api.key] || ''}
                onChange={(e) => handleKeyChange(api.key, e.target.value)}
                placeholder={`Enter ${api.name} API key...`}
                className={`flex-1 px-3 py-2 rounded-lg border text-sm ${
                  darkMode
                    ? 'bg-gray-800 border-gray-600 text-white placeholder-gray-500'
                    : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              />
              <button
                type="button"
                onClick={() => toggleShowKey(api.key)}
                className={`px-3 py-2 rounded-lg text-sm ${
                  darkMode
                    ? 'bg-gray-600 text-gray-200 hover:bg-gray-500'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                {showKeys[api.key] ? '🔒' : '👁️'}
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* ARIN RDAP notice */}
      <div className={`mt-4 p-4 rounded-lg ${darkMode ? 'bg-green-900/30 border border-green-700' : 'bg-green-50 border border-green-200'}`}>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-500" />
          <span className={`font-semibold ${darkMode ? 'text-green-300' : 'text-green-800'}`}>
            ARIN RDAP
          </span>
          <span className={`text-xs ${darkMode ? 'text-green-400' : 'text-green-600'}`}>
            (Always Available)
          </span>
        </div>
        <p className={`text-xs mt-1 ${darkMode ? 'text-green-400' : 'text-green-700'}`}>
          IP ownership and registration data - no API key required
        </p>
      </div>

      {/* Save button */}
      <div className="mt-6 flex items-center justify-between">
        <button
          onClick={onClose}
          className={`px-4 py-2 rounded-lg font-semibold transition ${
            darkMode
              ? 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className={`px-6 py-2 rounded-lg font-semibold transition ${
            saving
              ? 'bg-gray-500 text-gray-300 cursor-not-allowed'
              : saved
              ? 'bg-green-600 text-white'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          {saving ? '⏳ Saving...' : saved ? '✓ Saved!' : '💾 Save API Keys'}
        </button>
      </div>
    </div>
  );
}
