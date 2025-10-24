import React, { useState } from 'react';
import KQLDiffViewer from './components/KQLDiffViewer';
import IRPlaybookGenerator from './components/IRPlaybookGenerator';
import SOCHandoffTool from './components/SOCHandoffTool';

export default function ThreatDefenderDashboard() {
  const [activeTab, setActiveTab] = useState('kql-diff');
  const [darkMode, setDarkMode] = useState(false);

  const tabs = [
    { id: 'kql-diff', name: 'KQL Diff Viewer', icon: '🔍', component: KQLDiffViewer },
    { id: 'ir-playbook', name: 'IR Playbook Generator', icon: '🚨', component: IRPlaybookGenerator },
    { id: 'soc-handoff', name: 'SOC Shift Handoff', icon: '🔄', component: SOCHandoffTool },
  ];

  const ActiveComponent = tabs.find(t => t.id === activeTab)?.component;

  return (
    <div className={`min-h-screen ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
      {/* Header */}
      <div className={`border-b ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} sticky top-0 z-50 shadow-sm`}>
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                🛡️ ThreatDefender Operations Suite
              </h1>
              <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                eGroup Enabling Technologies | ThreatHunter MSSP Team
              </p>
            </div>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`px-4 py-2 rounded-md font-semibold transition ${
                darkMode 
                  ? 'bg-gray-700 text-yellow-400 hover:bg-gray-600' 
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              {darkMode ? '☀️ Light' : '🌙 Dark'}
            </button>
          </div>

          {/* Navigation Tabs */}
          <div className="flex gap-2 overflow-x-auto">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 rounded-t-lg font-semibold whitespace-nowrap transition ${
                  activeTab === tab.id
                    ? darkMode
                      ? 'bg-gray-900 text-white border-b-2 border-blue-500'
                      : 'bg-gray-50 text-gray-900 border-b-2 border-blue-600'
                    : darkMode
                      ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                <span className="mr-2">{tab.icon}</span>
                {tab.name}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-6 py-6">
        {ActiveComponent && <ActiveComponent darkMode={darkMode} />}
      </div>

      {/* Footer */}
      <div className={`mt-12 py-6 border-t ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
        <div className="max-w-7xl mx-auto px-6 text-center">
          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            ThreatDefender Operations Suite | Built for ThreatHunter MSSP Team
          </p>
          <p className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
            eGroup Enabling Technologies © {new Date().getFullYear()}
          </p>
        </div>
      </div>
    </div>
  );
}
