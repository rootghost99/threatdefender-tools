import React, { useState } from 'react';

export default function ThreatIntelLookup({ darkMode }) {
    const [indicator, setIndicator] = useState('');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);

    const handleLookup = async () => {
        if (!indicator.trim()) return;

        setLoading(true);
        setResults(null);

        try {
            const response = await fetch('/api/ThreatIntelLookup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ indicator: indicator.trim() })
            });

            const data = await response.json();
            setResults(data);
        } catch (error) {
            console.error('Lookup failed:', error);
            setResults({ error: 'Failed to perform lookup' });
        } finally {
            setLoading(false);
        }
    };

    const getThreatLevel = (vt) => {
        if (!vt || vt.error) return 'unknown';
        if (vt.malicious > 5) return 'high';
        if (vt.malicious > 0 || vt.suspicious > 3) return 'medium';
        return 'clean';
    };

    const getThreatColor = (level) => {
        switch (level) {
            case 'high': return darkMode ? 'bg-red-900 border-red-700' : 'bg-red-50 border-red-300';
            case 'medium': return darkMode ? 'bg-yellow-900 border-yellow-700' : 'bg-yellow-50 border-yellow-300';
            case 'clean': return darkMode ? 'bg-green-900 border-green-700' : 'bg-green-50 border-green-300';
            default: return darkMode ? 'bg-gray-800 border-gray-700' : 'bg-gray-50 border-gray-300';
        }
    };

    const getScoreColor = (score) => {
        if (score > 75) return darkMode ? 'text-red-400' : 'text-red-600';
        if (score > 25) return darkMode ? 'text-yellow-400' : 'text-yellow-600';
        return darkMode ? 'text-green-400' : 'text-green-600';
    };

    const getVirusTotalUrl = (indicator, type) => {
        switch (type) {
            case 'IP':
                return `https://www.virustotal.com/gui/ip-address/${indicator}`;
            case 'Domain':
                return `https://www.virustotal.com/gui/domain/${indicator}`;
            case 'SHA1':
            case 'SHA256':
                return `https://www.virustotal.com/gui/file/${indicator}`;
            case 'URL':
                return `https://www.virustotal.com/gui/url/${btoa(indicator).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}`;
            default:
                return null;
        }
    };

    return (
        <div className={`rounded-lg shadow-md ${darkMode ? 'bg-gray-800' : 'bg-white'} p-6`}>
            <div className="mb-6">
                <h2 className={`text-xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                    🔍 Threat Intel Lookup
                </h2>
                <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Query indicators against VirusTotal and AbuseIPDB
                </p>
            </div>

            <div className="space-y-4">
                <div>
                    <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        Indicator
                    </label>
                    <input
                        type="text"
                        placeholder="Enter IP, SHA-1, SHA-256, URL, or domain..."
                        value={indicator}
                        onChange={(e) => setIndicator(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && handleLookup()}
                        className={`w-full px-4 py-3 rounded-lg border ${
                            darkMode 
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                        } focus:outline-none focus:ring-2 focus:ring-blue-500`}
                    />
                </div>

                <button
                    onClick={handleLookup}
                    disabled={loading || !indicator.trim()}
                    className={`w-full py-3 px-6 rounded-lg font-semibold transition ${
                        loading || !indicator.trim()
                            ? darkMode
                                ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                                : 'bg-gray-200 text-gray-400 cursor-not-allowed'
                            : darkMode
                                ? 'bg-blue-600 text-white hover:bg-blue-700'
                                : 'bg-blue-600 text-white hover:bg-blue-700'
                    }`}
                >
                    {loading ? '🔄 Looking up...' : '🔍 Lookup Indicator'}
                </button>
            </div>

            {results && (
                <div className="mt-6 space-y-4">
                    <div className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200'}`}>
                        <div className="flex items-center justify-between">
                            <h3 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                {results.indicator}
                            </h3>
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                                darkMode ? 'bg-blue-900 text-blue-300' : 'bg-blue-100 text-blue-800'
                            }`}>
                                {results.type}
                            </span>
                        </div>
                    </div>

                    {results.virusTotal && !results.virusTotal.error && (
                        <div className={`p-6 rounded-lg border-2 ${getThreatColor(getThreatLevel(results.virusTotal))}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                    🛡️ VirusTotal Analysis
                                </h4>
                                <a
                                    href={getVirusTotalUrl(results.indicator, results.type)}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                >
                                    View Full Report →
                                </a>
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                        Malicious
                                    </p>
                                    <p className="text-2xl font-bold text-red-600">
                                        {results.virusTotal.malicious}
                                    </p>
                                </div>
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                        Suspicious
                                    </p>
                                    <p className="text-2xl font-bold text-yellow-600">
                                        {results.virusTotal.suspicious}
                                    </p>
                                </div>
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                        Undetected
                                    </p>
                                    <p className={`text-2xl font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                        {results.virusTotal.undetected}
                                    </p>
                                </div>
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                        Harmless
                                    </p>
                                    <p className="text-2xl font-bold text-green-600">
                                        {results.virusTotal.harmless}
                                    </p>
                                </div>
                            </div>
                            <div className={`pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <strong>Reputation:</strong> {results.virusTotal.reputation}
                                </p>
                                <p className={`text-sm mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <strong>Last Analysis:</strong> {results.virusTotal.lastAnalysis !== 'N/A' 
                                        ? new Date(results.virusTotal.lastAnalysis).toLocaleString() 
                                        : 'N/A'}
                                </p>
                            </div>
                        </div>
                    )}

                    {results.abuseIPDB && !results.abuseIPDB.error && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                    🚨 AbuseIPDB Report
                                </h4>
                                <a
                                    href={`https://www.abuseipdb.com/check/${results.indicator}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                >
                                    View Full Report →
                                </a>
                            </div>
                            <div className="mb-4">
                                <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                    Abuse Confidence Score
                                </p>
                                <p className={`text-4xl font-bold ${getScoreColor(results.abuseIPDB.abuseScore)}`}>
                                    {results.abuseIPDB.abuseScore}%
                                </p>
                            </div>
                            <div className={`space-y-2 pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <strong>Total Reports:</strong> {results.abuseIPDB.totalReports}
                                </p>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <strong>Country:</strong> {results.abuseIPDB.countryCode}
                                </p>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <strong>ISP:</strong> {results.abuseIPDB.isp}
                                </p>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    <strong>Usage Type:</strong> {results.abuseIPDB.usageType}
                                </p>
                                {results.abuseIPDB.isWhitelisted && (
                                    <p className="text-sm text-green-600 font-semibold">
                                        ✅ Whitelisted
                                    </p>
                                )}
                            </div>
                        </div>
                    )}

                    {results.virusTotal?.error && results.abuseIPDB?.error && (
                        <div className={`p-4 rounded-lg border ${darkMode ? 'bg-red-900 border-red-700' : 'bg-red-50 border-red-300'}`}>
                            <p className={`text-sm ${darkMode ? 'text-red-300' : 'text-red-700'}`}>
                                ⚠️ Unable to retrieve threat intelligence data. Check API keys and connectivity.
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
