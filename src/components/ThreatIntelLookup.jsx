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

            if (!response.ok) {
                const errorText = await response.text();
                console.error('API Error:', response.status, errorText);
                setResults({ error: `API Error: ${response.status} - ${errorText}` });
                return;
            }

            const data = await response.json();
            setResults(data);
        } catch (error) {
            console.error('Lookup failed:', error);
            setResults({ error: 'Failed to perform lookup: ' + error.message });
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = (text) => {
        try {
            navigator.clipboard.writeText(text);
        } catch {}
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
                    Query indicators against VirusTotal, AbuseIPDB, URLScan, GreyNoise, Shodan, OTX, MXToolbox, and ARIN RDAP
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
                                {results.indicator || ''}
                            </h3>
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                                darkMode ? 'bg-blue-900 text-blue-300' : 'bg-blue-100 text-blue-800'
                            }`}>
                                {results.type || 'Unknown'}
                            </span>
                        </div>
                    </div>

                    {/* Quick Results Summary */}
                    <div className={`p-4 rounded-lg border-2 ${darkMode ? 'bg-gray-800 border-blue-600' : 'bg-blue-50 border-blue-400'}`}>
                        <h3 className={`text-md font-bold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                            📋 Quick Results Summary
                        </h3>
                        <div className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-800'}`}>
                            <table className="w-full border-collapse">
                                <tbody>
                                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                        <td className="py-2 pr-4 font-semibold">Indicator:</td>
                                        <td className="py-2 font-mono">{String(results.indicator || '')} ({String(results.type || 'Unknown')})</td>
                                    </tr>

                                    {results.virusTotal && !results.virusTotal.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">VirusTotal:</td>
                                            <td className="py-2">
                                                {(results.virusTotal.malicious || 0) > 0 ? (
                                                    <span className="text-red-600 font-semibold">
                                                        ⚠️ {results.virusTotal.malicious} detections ({results.virusTotal.malicious}/{(results.virusTotal.malicious || 0) + (results.virusTotal.suspicious || 0) + (results.virusTotal.undetected || 0) + (results.virusTotal.harmless || 0)})
                                                    </span>
                                                ) : (
                                                    <span className="text-green-600 font-semibold">✅ Clean (0 detections)</span>
                                                )}
                                            </td>
                                        </tr>
                                    )}

                                    {results.abuseIPDB && !results.abuseIPDB.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">AbuseIPDB:</td>
                                            <td className="py-2">
                                                Confidence: {results.abuseIPDB.abuseScore || 0}% | Reports: {results.abuseIPDB.totalReports || 0} | {results.abuseIPDB.countryCode || 'N/A'} ({results.abuseIPDB.isp || 'Unknown'})
                                            </td>
                                        </tr>
                                    )}

                                    {results.greyNoise && !results.greyNoise.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">GreyNoise:</td>
                                            <td className="py-2">
                                                {String(results.greyNoise.classification || 'unknown').toUpperCase()}
                                                {results.greyNoise.riot && ' | RIOT (Common Business Service)'}
                                                {results.greyNoise.noise && ' | Internet Noise'}
                                                {results.greyNoise.name && results.greyNoise.name !== 'N/A' && typeof results.greyNoise.name === 'string' && ` | ${results.greyNoise.name}`}
                                            </td>
                                        </tr>
                                    )}

                                    {results.shodan && results.shodan.hasData && !results.shodan.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">Shodan:</td>
                                            <td className="py-2">
                                                {results.shodan.openPortsCount || 0} open ports
                                                {results.shodan.vulnCount > 0 && ` | ${results.shodan.vulnCount} vulnerabilities`}
                                                {results.shodan.organization && typeof results.shodan.organization === 'string' && ` | ${results.shodan.organization}`}
                                            </td>
                                        </tr>
                                    )}

                                    {results.urlScan && !results.urlScan.error && !results.urlScan.scanning && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">URLScan.io:</td>
                                            <td className="py-2">
                                                {results.urlScan.verdictMalicious ? (
                                                    <span className="text-red-600 font-semibold">⚠️ Malicious</span>
                                                ) : (
                                                    <span className="text-green-600 font-semibold">✅ Clean</span>
                                                )} | Score: {results.urlScan.score || 0}
                                                {results.urlScan.ip && typeof results.urlScan.ip === 'string' && ` | IP: ${results.urlScan.ip}`}
                                            </td>
                                        </tr>
                                    )}

                                    {results.alienVault && results.alienVault.hasData && !results.alienVault.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">AlienVault OTX:</td>
                                            <td className="py-2">
                                                {results.alienVault.pulseCount} threat pulses
                                                {results.alienVault.pulses && results.alienVault.pulses.length > 0 && 
                                                 results.alienVault.pulses[0].malwareFamilies && 
                                                 Array.isArray(results.alienVault.pulses[0].malwareFamilies) &&
                                                 results.alienVault.pulses[0].malwareFamilies.length > 0 && 
                                                    ` | Malware: ${results.alienVault.pulses[0].malwareFamilies.join(', ')}`
                                                }
                                                {results.alienVault.pulses && results.alienVault.pulses.length > 0 && 
                                                 results.alienVault.pulses[0].adversary && 
                                                 typeof results.alienVault.pulses[0].adversary === 'string' &&
                                                    ` | Adversary: ${results.alienVault.pulses[0].adversary}`
                                                }
                                            </td>
                                        </tr>
                                    )}

                                    {/* MXToolbox WHOIS summary */}
                                    {results.type === 'IP' && results.mxToolbox && results.mxToolbox.hasData && !results.mxToolbox.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">MXToolbox ARIN/WHOIS:</td>
                                            <td className="py-2">
                                                {results.mxToolbox.organization || 'Unknown'} | {results.mxToolbox.netRange || 'N/A'} | {results.mxToolbox.country || 'N/A'}
                                            </td>
                                        </tr>
                                    )}

                                    {/* ARIN RDAP summary */}
                                    {results.type === 'IP' && results.arin && results.arin.hasData && !results.arin.error && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">ARIN RDAP:</td>
                                            <td className="py-2">
                                                {results.arin.org || 'Unknown'} | {results.arin.startAddress || 'N/A'} – {results.arin.endAddress || 'N/A'} | {results.arin.country || 'N/A'}
                                            </td>
                                        </tr>
                                    )}

                                    {/* No data notices */}
                                    {results.type === 'IP' && results.shodan && (!results.shodan.hasData || results.shodan.message === 'No information available for this IP') && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">Shodan:</td>
                                            <td className="py-2 text-gray-500">No data available</td>
                                        </tr>
                                    )}

                                    {results.alienVault && results.alienVault.hasData === false && (
                                        <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <td className="py-2 pr-4 font-semibold">AlienVault OTX:</td>
                                            <td className="py-2 text-gray-500">No data available</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                        <p className={`text-xs mt-3 ${darkMode ? 'text-gray-500' : 'text-gray-600'}`}>
                            💡 Screenshot this summary for ticket notes
                        </p>
                    </div>

                    {/* VirusTotal */}
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
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Malicious</p>
                                    <p className="text-2xl font-bold text-red-600">{results.virusTotal.malicious}</p>
                                </div>
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Suspicious</p>
                                    <p className="text-2xl font-bold text-yellow-600">{results.virusTotal.suspicious}</p>
                                </div>
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Undetected</p>
                                    <p className={`text-2xl font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{results.virusTotal.undetected}</p>
                                </div>
                                <div className="text-center">
                                    <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Harmless</p>
                                    <p className="text-2xl font-bold text-green-600">{results.virusTotal.harmless}</p>
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

                    {/* AlienVault OTX */}
                    {results.alienVault && !results.alienVault.error && results.alienVault.hasData && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                    🔮 AlienVault OTX Threat Intelligence
                                </h4>
                                <a
                                    href={`https://otx.alienvault.com/indicator/${results.type === 'IP' ? 'ip' : results.type === 'Domain' ? 'domain' : results.type === 'URL' ? 'url' : 'file'}/${results.indicator}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                >
                                    View Full Report →
                                </a>
                            </div>

                            <div className="mb-4">
                                <div className="flex items-center gap-3 mb-3">
                                    <div className={`px-4 py-2 rounded-lg ${darkMode ? 'bg-blue-900' : 'bg-blue-50'}`}>
                                        <p className={`text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>
                                            <strong>{results.alienVault.pulseCount}</strong> Threat Pulses
                                        </p>
                                    </div>
                                    {results.alienVault.reputation !== 0 && (
                                        <div className={`px-4 py-2 rounded-lg ${
                                            results.alienVault.reputation < 0 
                                                ? darkMode ? 'bg-red-900' : 'bg-red-50'
                                                : darkMode ? 'bg-green-900' : 'bg-green-50'
                                        }`}>
                                            <p className={`text-sm ${
                                                results.alienVault.reputation < 0
                                                    ? darkMode ? 'text-red-300' : 'text-red-700'
                                                    : darkMode ? 'text-green-300' : 'text-green-700'
                                            }`}>
                                                Reputation: {results.alienVault.reputation}
                                            </p>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {results.alienVault.pulses && results.alienVault.pulses.length > 0 && (
                                <div className="space-y-3">
                                    <p className={`text-sm font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                        Related Threat Intelligence (Top 5)
                                    </p>
                                    {results.alienVault.pulses.map((pulse, idx) => (
                                        <div key={idx} className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-800 border-gray-600' : 'bg-gray-50 border-gray-200'}`}>
                                            <div className="mb-2">
                                                <a
                                                    href={`https://otx.alienvault.com/pulse/${pulse.id}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className={`font-semibold hover:underline ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}
                                                >
                                                    {typeof pulse.name === 'string' ? pulse.name : 'Unnamed Pulse'}
                                                </a>
                                            </div>
                                            
                                            {pulse.adversary && (
                                                <div className="mb-2">
                                                    <span className={`px-2 py-1 rounded text-xs font-semibold ${darkMode ? 'bg-red-900 text-red-300' : 'bg-red-100 text-red-800'}`}>
                                                        🎯 Adversary: {typeof pulse.adversary === 'string' ? pulse.adversary : JSON.stringify(pulse.adversary)}
                                                    </span>
                                                </div>
                                            )}
                                            
                                            {pulse.malwareFamilies && pulse.malwareFamilies.length > 0 && (
                                                <div className="mb-2">
                                                    <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                        Malware Families:
                                                    </p>
                                                    <div className="flex gap-2 flex-wrap">
                                                        {pulse.malwareFamilies.map((family, fidx) => (
                                                            <span key={fidx} className={`px-2 py-1 rounded text-xs font-semibold ${darkMode ? 'bg-orange-900 text-orange-300' : 'bg-orange-100 text-orange-800'}`}>
                                                                {typeof family === 'string' ? family : (family.display_name || family.name || JSON.stringify(family))}
                                                            </span>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {pulse.tags && pulse.tags.length > 0 && (
                                                <div className="mb-2">
                                                    <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                        Tags:
                                                    </p>
                                                    <div className="flex gap-1 flex-wrap">
                                                        {pulse.tags.map((tag, tidx) => (
                                                            <span key={tidx} className={`px-2 py-1 rounded text-xs ${darkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-200 text-gray-700'}`}>
                                                                {typeof tag === 'string' ? tag : JSON.stringify(tag)}
                                                            </span>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            
                                            <div className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                                                Modified: {new Date(pulse.modified).toLocaleString()}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {results.alienVault.validations && results.alienVault.validations.length > 0 && (
                                <div className={`mt-4 pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                    <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                        Validations
                                    </p>
                                    <div className="space-y-1">
                                        {results.alienVault.validations.map((validation, idx) => (
                                            <div key={idx} className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                {typeof validation.source === 'string' ? validation.source : 'Unknown'}: {typeof validation.message === 'string' ? validation.message : JSON.stringify(validation.message)}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* URLScan */}
                    {results.urlScan && !results.urlScan.error && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                    🔎 URLScan.io Analysis
                                </h4>
                                {results.urlScan.reportUrl && (
                                    <a
                                        href={results.urlScan.reportUrl}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                    >
                                        View Full Report →
                                    </a>
                                )}
                            </div>
                            
                            {results.urlScan.scanning ? (
                                <div className={`p-4 rounded-lg ${darkMode ? 'bg-blue-900' : 'bg-blue-50'}`}>
                                    <p className={`text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>⏳ {results.urlScan.message}</p>
                                </div>
                            ) : (
                                <>
                                    <div className="mb-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                                                results.urlScan.verdictMalicious
                                                    ? 'bg-red-100 text-red-800'
                                                    : 'bg-green-100 text-green-800'
                                            }`}>
                                                {results.urlScan.verdictMalicious ? '⚠️ Malicious' : '✅ Clean'}
                                            </span>
                                            <span className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                Score: {results.urlScan.score}
                                            </span>
                                        </div>
                                        {results.urlScan.categories && results.urlScan.categories.length > 0 && (
                                            <div className="flex gap-2 flex-wrap mt-2">
                                                {results.urlScan.categories.map((cat, idx) => (
                                                    <span key={idx} className={`px-2 py-1 rounded text-xs ${darkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-200 text-gray-700'}`}>
                                                        {typeof cat === 'string' ? cat : JSON.stringify(cat)}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    
                                    {results.urlScan.screenshot && (
                                        <div className="mb-4">
                                            <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Screenshot</p>
                                            <img src={results.urlScan.screenshot} alt="URLScan Screenshot" className="w-full rounded border" />
                                        </div>
                                    )}
                                    
                                    <div className={`space-y-2 pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                        {results.urlScan.ip && (
                                            <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>IP Address:</strong> {results.urlScan.ip}</p>
                                        )}
                                        {results.urlScan.server && (
                                            <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Server:</strong> {results.urlScan.server}</p>
                                        )}
                                        {results.urlScan.scanDate && (
                                            <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Scan Date:</strong> {new Date(results.urlScan.scanDate).toLocaleString()}</p>
                                        )}
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {/* GreyNoise */}
                    {results.greyNoise && !results.greyNoise.error && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                    🌐 GreyNoise Intelligence
                                </h4>
                                <a
                                    href={`https://www.greynoise.io/viz/ip/${results.indicator}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                >
                                    View Full Report →
                                </a>
                            </div>
                            
                            <div className="mb-4">
                                <div className="flex items-center gap-2 mb-3">
                                    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                                        results.greyNoise.classification === 'malicious'
                                            ? 'bg-red-100 text-red-800'
                                            : results.greyNoise.classification === 'benign'
                                            ? 'bg-green-100 text-green-800'
                                            : 'bg-gray-100 text-gray-800'
                                    }`}>
                                        {results.greyNoise.classification.toUpperCase()}
                                    </span>
                                    
                                    {results.greyNoise.noise && (
                                        <span className={`px-3 py-1 rounded-full text-sm font-semibold ${darkMode ? 'bg-yellow-900 text-yellow-300' : 'bg-yellow-100 text-yellow-800'}`}>
                                            🔊 Internet Noise
                                        </span>
                                    )}
                                    
                                    {results.greyNoise.riot && (
                                        <span className={`px-3 py-1 rounded-full text-sm font-semibold ${darkMode ? 'bg-blue-900 text-blue-300' : 'bg-blue-100 text-blue-800'}`}>
                                            🏢 Common Business Service
                                        </span>
                                    )}
                                </div>
                                
                                {results.greyNoise.name && results.greyNoise.name !== 'N/A' && (
                                    <p className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.greyNoise.name}</p>
                                )}
                            </div>
                            
                            <div className={`space-y-2 pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                {results.greyNoise.lastSeen && results.greyNoise.lastSeen !== 'N/A' && (
                                    <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Last Seen:</strong> {new Date(results.greyNoise.lastSeen).toLocaleString()}</p>
                                )}
                                {results.greyNoise.message && (
                                    <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Note:</strong> {results.greyNoise.message}</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Shodan */}
                    {results.shodan && !results.shodan.error && results.shodan.hasData && results.shodan.message !== 'No information available for this IP' && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>🔍 Shodan Reconnaissance</h4>
                                <a
                                    href={`https://www.shodan.io/host/${results.indicator}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                >
                                    View Full Report →
                                </a>
                            </div>

                            <div className="mb-4">
                                <div className="grid grid-cols-2 gap-4 mb-4">
                                    <div>
                                        <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Organization</p>
                                        <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.shodan.organization}</p>
                                    </div>
                                    <div>
                                        <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>ISP</p>
                                        <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.shodan.isp}</p>
                                    </div>
                                    <div>
                                        <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Location</p>
                                        <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.shodan.city}, {results.shodan.country}</p>
                                    </div>
                                    <div>
                                        <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>ASN</p>
                                        <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.shodan.asn}</p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-4 mb-4">
                                    <div className={`px-4 py-2 rounded-lg ${darkMode ? 'bg-blue-900' : 'bg-blue-50'}`}>
                                        <p className={`text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}><strong>{results.shodan.openPortsCount}</strong> Open Ports</p>
                                    </div>
                                    {results.shodan.vulnCount > 0 && (
                                        <div className={`px-4 py-2 rounded-lg ${darkMode ? 'bg-red-900' : 'bg-red-50'}`}>
                                            <p className={`text-sm ${darkMode ? 'text-red-300' : 'text-red-700'}`}><strong>{results.shodan.vulnCount}</strong> Vulnerabilities</p>
                                        </div>
                                    )}
                                </div>

                                {results.shodan.tags && results.shodan.tags.length > 0 && (
                                    <div className="mb-4">
                                        <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Tags</p>
                                        <div className="flex gap-2 flex-wrap">
                                            {results.shodan.tags.map((tag, idx) => (
                                                <span key={idx} className={`px-2 py-1 rounded text-xs ${darkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-200 text-gray-700'}`}>
                                                    {typeof tag === 'string' ? tag : JSON.stringify(tag)}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>

                            {results.shodan.ports && results.shodan.ports.length > 0 && (
                                <div className={`mb-4 pb-4 border-b ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                    <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Open Ports</p>
                                    <div className="flex gap-2 flex-wrap">
                                        {results.shodan.ports.map((port, idx) => (
                                            <span key={idx} className={`px-3 py-1 rounded ${darkMode ? 'bg-gray-600 text-white' : 'bg-gray-200 text-gray-900'} font-mono text-sm`}>
                                                {port}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {results.shodan.services && results.shodan.services.length > 0 && (
                                <div className={`mb-4 pb-4 border-b ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                    <p className={`text-sm font-semibold mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Services Detected</p>
                                    <div className="space-y-3">
                                        {results.shodan.services.map((service, idx) => (
                                            <div key={idx} className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className={`font-mono font-bold ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>Port {service.port}/{service.protocol}</span>
                                                    <span className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{service.product} {service.version}</span>
                                                </div>
                                                {service.banner && (
                                                    <pre className={`text-xs mt-2 p-2 rounded overflow-x-auto ${darkMode ? 'bg-gray-900 text-gray-300' : 'bg-white text-gray-700'}`}>
                                                        {service.banner}
                                                    </pre>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {results.shodan.vulnerabilities && results.shodan.vulnerabilities.length > 0 && (
                                <div className="mb-4">
                                    <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Known Vulnerabilities (Top 10)</p>
                                    <div className="space-y-1">
                                        {results.shodan.vulnerabilities.map((cve, idx) => (
                                            <a
                                                key={idx}
                                                href={`https://nvd.nist.gov/vuln/detail/${typeof cve === 'string' ? cve : ''}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className={`block p-2 rounded hover:bg-opacity-80 ${darkMode ? 'bg-red-900 text-red-300 hover:bg-red-800' : 'bg-red-50 text-red-700 hover:bg-red-100'}`}
                                            >
                                                <span className="font-mono text-sm">{typeof cve === 'string' ? cve : JSON.stringify(cve)}</span>
                                            </a>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {results.shodan.hostnames && results.shodan.hostnames.length > 0 && (
                                <div className={`pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                    <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Hostnames</p>
                                    <div className="space-y-1">
                                        {results.shodan.hostnames.map((hostname, idx) => (
                                            <p key={idx} className={`text-sm font-mono ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                {typeof hostname === 'string' ? hostname : JSON.stringify(hostname)}
                                            </p>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {results.shodan.lastUpdate && results.shodan.lastUpdate !== 'N/A' && (
                                <div className={`pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                    <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>Last updated: {new Date(results.shodan.lastUpdate).toLocaleString()}</p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* AbuseIPDB */}
                    {results.abuseIPDB && !results.abuseIPDB.error && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>🚨 AbuseIPDB Report</h4>
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
                                <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Abuse Confidence Score</p>
                                <p className={`text-4xl font-bold ${getScoreColor(results.abuseIPDB.abuseScore)}`}>{results.abuseIPDB.abuseScore}%</p>
                            </div>
                            <div className={`space-y-2 pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Total Reports:</strong> {results.abuseIPDB.totalReports}</p>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Country:</strong> {results.abuseIPDB.countryCode}</p>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>ISP:</strong> {results.abuseIPDB.isp}</p>
                                <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Usage Type:</strong> {results.abuseIPDB.usageType}</p>
                                {results.abuseIPDB.isWhitelisted && (<p className="text-sm text-green-600 font-semibold">✅ Whitelisted</p>)}
                            </div>
                        </div>
                    )}

                    {/* MXToolbox WHOIS/ARIN */}
                    {results.type === 'IP' && results.mxToolbox && !results.mxToolbox.error && results.mxToolbox.hasData && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>📋 ARIN/WHOIS Registration (MXToolbox)</h4>
                                <a
                                    href={`https://mxtoolbox.com/SuperTool.aspx?action=whois%3a${results.indicator}&run=toolpage`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                >
                                    View on MXToolbox →
                                </a>
                            </div>

                            <div className="mb-4">
                                <p className={`text-sm font-semibold mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Organization & Network</p>
                                <div className="space-y-2">
                                    <div className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                        <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>ORGANIZATION</p>
                                        <p className={`text-sm font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.mxToolbox.organization}</p>
                                    </div>
                                    
                                    <div className="grid grid-cols-2 gap-2">
                                        <div className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                            <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>NETWORK RANGE</p>
                                            <p className={`text-sm font-mono ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>{results.mxToolbox.netRange}</p>
                                        </div>
                                        
                                        <div className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                            <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>NETWORK NAME</p>
                                            <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{results.mxToolbox.netName}</p>
                                        </div>
                                    </div>

                                    <div className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                        <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>COUNTRY</p>
                                        <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{results.mxToolbox.country}</p>
                                    </div>
                                </div>
                            </div>

                            <div className={`mb-4 pb-4 border-b ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                <p className={`text-sm font-semibold mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Registration Information</p>
                                <div className="grid grid-cols-2 gap-2">
                                    <div>
                                        <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>Registration Date</p>
                                        <p className={`text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{results.mxToolbox.registrationDate}</p>
                                    </div>
                                    <div>
                                        <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>Last Updated</p>
                                        <p className={`text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{results.mxToolbox.updated}</p>
                                    </div>
                                </div>
                            </div>

                            <div className="mb-4">
                                <p className={`text-sm font-semibold mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Contact Information</p>
                                <div className="space-y-2">
                                    {results.mxToolbox.abuseContact && results.mxToolbox.abuseContact !== 'N/A' && (
                                        <div className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                            <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>🚨 ABUSE CONTACT</p>
                                            <a href={`mailto:${results.mxToolbox.abuseContact}`} className={`text-sm font-mono ${darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-700'}`}>{results.mxToolbox.abuseContact}</a>
                                        </div>
                                    )}
                                    
                                    {results.mxToolbox.techContact && results.mxToolbox.techContact !== 'N/A' && (
                                        <div className={`p-3 rounded ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                            <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>🔧 TECHNICAL CONTACT</p>
                                            <a href={`mailto:${results.mxToolbox.techContact}`} className={`text-sm font-mono ${darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-700'}`}>{results.mxToolbox.techContact}</a>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {results.mxToolbox.relatedIPs && results.mxToolbox.relatedIPs.length > 0 && (
                                <div className={`pt-4 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                    <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Related IP Addresses</p>
                                    <div className="flex flex-wrap gap-2">
                                        {results.mxToolbox.relatedIPs.map((ip, idx) => (
                                            <span key={idx} className={`px-3 py-1 rounded font-mono text-xs ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-gray-100 text-gray-700'}`}>{ip}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* ARIN RDAP (Direct) */}
                    {results.type === 'IP' && results.arin && !results.arin.error && results.arin.hasData && (
                        <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                            <div className="flex items-center justify-between mb-4">
                                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>🧭 ARIN RDAP (Direct)</h4>
                                <div className="flex gap-2">
                                    <a
                                        href={`https://rdap.arin.net/registry/ip/${encodeURIComponent(results.indicator)}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                                    >
                                        Open RDAP →
                                    </a>
                                    <button
                                        onClick={() => copyToClipboard(JSON.stringify(results.arin, null, 2))}
                                        className={`text-xs px-3 py-1 rounded ${
                                            darkMode ? 'bg-gray-600 text-gray-200 hover:bg-gray-500' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                                        }`}
                                    >
                                        Copy JSON
                                    </button>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div>
                                    <p className={`text-xs font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Organization</p>
                                    <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.arin.org}</p>
                                </div>
                                <div>
                                    <p className={`text-xs font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Network Handle</p>
                                    <p className="font-mono">{results.arin.handle}</p>
                                </div>
                                <div>
                                    <p className={`text-xs font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Range</p>
                                    <p className="font-mono">{results.arin.startAddress} - {results.arin.endAddress}</p>
                                </div>
                                <div>
                                    <p className={`text-xs font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Type</p>
                                    <p>{results.arin.type}</p>
                                </div>
                                <div>
                                    <p className={`text-xs font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Country</p>
                                    <p>{results.arin.country}</p>
                                </div>
                            </div>

                            <div className={`mt-4 pt-3 border-t ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                                <p className={`text-xs font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Abuse Contact</p>
                                <p className={`font-mono text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>
                                    {results.arin.abuseContact !== 'N/A'
                                        ? <a href={`mailto:${results.arin.abuseContact}`}>{results.arin.abuseContact}</a>
                                        : 'N/A'}
                                </p>
                                <p className={`text-xs mt-3 ${darkMode ? 'text-gray-500' : 'text-gray-600'}`}>
                                    Registered: {results.arin.registrationDate?.split('T')[0] || 'N/A'} | Updated: {results.arin.lastChanged?.split('T')[0] || 'N/A'}
                                </p>
                            </div>
                        </div>
                    )}

                    {/* MXToolbox errors */}
                    {results.type === 'IP' && results.mxToolbox && (results.mxToolbox.error || !results.mxToolbox.hasData) && (
                        <div className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-800 border-gray-600' : 'bg-gray-100 border-gray-300'}`}>
                            <div className="flex items-center gap-2">
                                <span className="text-lg">📋</span>
                                <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                    <strong>MXToolbox ARIN:</strong> {results.mxToolbox.errorMessage || 'No registration data available'}
                                </p>
                            </div>
                        </div>
                    )}

                    {/* General error */}
                    {results.error && (
                        <div className={`p-4 rounded-lg border ${darkMode ? 'bg-red-900 border-red-700' : 'bg-red-50 border-red-300'}`}>
                            <p className={`text-sm ${darkMode ? 'text-red-300' : 'text-red-700'}`}>
                                ⚠️ {results.error}
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
