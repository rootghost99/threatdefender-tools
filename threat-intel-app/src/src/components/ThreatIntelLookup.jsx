import React, { useState, useEffect } from 'react';

export default function ThreatIntelLookup({ darkMode }) {
  const [indicator, setIndicator] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [hybridAnalysisResults, setHybridAnalysisResults] = useState(null);
  const [showSplash, setShowSplash] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setShowSplash(false);
    }, 2500);
    return () => clearTimeout(timer);
  }, []);

  const handleLookup = async () => {
    if (!indicator.trim()) return;

    setLoading(true);
    setResults(null);
    setHybridAnalysisResults(null);

    try {
      const [threatIntelResponse, hybridAnalysisResponse] = await Promise.all([
        fetch('/api/ThreatIntelLookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: indicator.trim() })
        }),
        fetch('/api/HybridAnalysisLookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: indicator.trim() })
        }).catch(err => {
          console.error('Hybrid Analysis API call failed:', err);
          return { ok: false, error: err };
        })
      ]);

      if (!threatIntelResponse.ok) {
        const errorText = await threatIntelResponse.text();
        setResults({ error: `API Error: ${threatIntelResponse.status} - ${errorText}` });
      } else {
        const data = await threatIntelResponse.json();
        setResults(data);
      }

      if (hybridAnalysisResponse && hybridAnalysisResponse.ok) {
        const hybridData = await hybridAnalysisResponse.json();
        setHybridAnalysisResults(hybridData);
      }
    } catch (error) {
      console.error('Lookup failed:', error);
      setResults({ error: 'Failed to perform lookup: ' + error.message });
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

  const getVirusTotalUrl = (indicator, type) => {
    switch (type) {
      case 'IP': return `https://www.virustotal.com/gui/ip-address/${indicator}`;
      case 'Domain': return `https://www.virustotal.com/gui/domain/${indicator}`;
      case 'SHA1':
      case 'SHA256': return `https://www.virustotal.com/gui/file/${indicator}`;
      case 'URL': return `https://www.virustotal.com/gui/url/${btoa(indicator).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}`;
      default: return null;
    }
  };

  if (showSplash) {
    return (
      <div className={`flex items-center justify-center min-h-screen ${darkMode ? 'text-white' : 'text-gray-900'}`} style={{ minHeight: '60vh' }}>
        <div className="text-center">
          <div className="mb-6">
            <div className="inline-block animate-pulse text-6xl mb-4">🛡️</div>
          </div>
          <h2 className="text-2xl font-bold mb-2 animate-pulse">
            Initializing Threat Intel Checker...
          </h2>
          <div className="flex justify-center mt-6">
            <div className="flex gap-2">
              <div className={`w-3 h-3 rounded-full animate-bounce ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`} style={{ animationDelay: '0ms' }}></div>
              <div className={`w-3 h-3 rounded-full animate-bounce ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`} style={{ animationDelay: '150ms' }}></div>
              <div className={`w-3 h-3 rounded-full animate-bounce ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`} style={{ animationDelay: '300ms' }}></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`rounded-lg shadow-lg ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'} p-6`}>
      <div className="mb-6">
        <h2 className={`text-xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
          🔍 Threat Intel Lookup
        </h2>
        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
          Query indicators against 9+ threat intelligence sources in parallel
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
            Indicator
          </label>
          <input
            type="text"
            placeholder="Enter IP, SHA-1, SHA-256, MD5, URL, or domain..."
            value={indicator}
            onChange={(e) => setIndicator(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleLookup()}
            className={`w-full px-4 py-3 rounded-lg border ${
              darkMode
                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
            }`}
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
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          {loading ? '🔄 Looking up...' : '🔍 Lookup Indicator'}
        </button>
      </div>

      {results && !results.error && (
        <div className="mt-6 space-y-4">
          {/* Header */}
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

          {/* Quick Summary */}
          <div className={`p-4 rounded-lg border-2 ${darkMode ? 'bg-gray-800 border-blue-600' : 'bg-blue-50 border-blue-400'}`}>
            <h3 className={`text-md font-bold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              📋 Quick Results Summary
            </h3>
            <div className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-800'}`}>
              <table className="w-full">
                <tbody>
                  <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                    <td className="py-2 pr-4 font-semibold">Indicator:</td>
                    <td className="py-2 font-mono">{results.indicator} ({results.type})</td>
                  </tr>

                  {results.virusTotal && !results.virusTotal.error && (
                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                      <td className="py-2 pr-4 font-semibold">VirusTotal:</td>
                      <td className="py-2">
                        {(results.virusTotal.malicious || 0) > 0 ? (
                          <span className="text-red-600 font-semibold">
                            ⚠️ {results.virusTotal.malicious} detections
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
                        Confidence: {results.abuseIPDB.abuseScore || 0}% | Reports: {results.abuseIPDB.totalReports || 0} | {results.abuseIPDB.countryCode || 'N/A'}
                      </td>
                    </tr>
                  )}

                  {results.greyNoise && !results.greyNoise.error && (
                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                      <td className="py-2 pr-4 font-semibold">GreyNoise:</td>
                      <td className="py-2">
                        {(results.greyNoise.classification || 'unknown').toUpperCase()}
                        {results.greyNoise.riot && ' | RIOT (Common Business Service)'}
                        {results.greyNoise.noise && ' | Internet Noise'}
                      </td>
                    </tr>
                  )}

                  {results.shodan && results.shodan.hasData && (
                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                      <td className="py-2 pr-4 font-semibold">Shodan:</td>
                      <td className="py-2">
                        {results.shodan.openPortsCount || 0} open ports
                        {results.shodan.vulnCount > 0 && ` | ${results.shodan.vulnCount} vulnerabilities`}
                        {results.shodan.organization && ` | ${results.shodan.organization}`}
                      </td>
                    </tr>
                  )}

                  {results.alienVault && results.alienVault.hasData && (
                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                      <td className="py-2 pr-4 font-semibold">AlienVault OTX:</td>
                      <td className="py-2">
                        {results.alienVault.pulseCount} threat pulses
                      </td>
                    </tr>
                  )}

                  {hybridAnalysisResults?.hybridAnalysis?.found && (
                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                      <td className="py-2 pr-4 font-semibold">Hybrid Analysis:</td>
                      <td className="py-2">
                        {hybridAnalysisResults.hybridAnalysis.verdict === 'malicious' && (
                          <span className="text-red-600 font-semibold">⚠️ Malicious</span>
                        )}
                        {hybridAnalysisResults.hybridAnalysis.verdict === 'suspicious' && (
                          <span className="text-yellow-600 font-semibold">⚠️ Suspicious</span>
                        )}
                        {hybridAnalysisResults.hybridAnalysis.verdict === 'clean' && (
                          <span className="text-green-600 font-semibold">✅ Clean</span>
                        )}
                        {' | Threat Score: '}{hybridAnalysisResults.hybridAnalysis.threatScore || 0}/100
                      </td>
                    </tr>
                  )}

                  {results.arin && results.arin.hasData && (
                    <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                      <td className="py-2 pr-4 font-semibold">ARIN RDAP:</td>
                      <td className="py-2">
                        {results.arin.org || 'Unknown'} | {results.arin.startAddress} – {results.arin.endAddress}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
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
            </div>
          )}

          {/* Hybrid Analysis */}
          {hybridAnalysisResults?.hybridAnalysis?.found && (
            <div className={`p-6 rounded-lg border-2 ${
              hybridAnalysisResults.hybridAnalysis.verdict === 'malicious'
                ? darkMode ? 'bg-red-900 border-red-700' : 'bg-red-50 border-red-300'
                : hybridAnalysisResults.hybridAnalysis.verdict === 'suspicious'
                ? darkMode ? 'bg-yellow-900 border-yellow-700' : 'bg-yellow-50 border-yellow-300'
                : darkMode ? 'bg-green-900 border-green-700' : 'bg-green-50 border-green-300'
            }`}>
              <div className="flex items-center justify-between mb-4">
                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  🦅 Hybrid Analysis (Falcon Sandbox)
                </h4>
                {hybridAnalysisResults.hybridAnalysis.reportUrl && (
                  <a
                    href={hybridAnalysisResults.hybridAnalysis.reportUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                  >
                    View Full Report →
                  </a>
                )}
              </div>
              <div className="mb-4 flex items-center gap-3">
                <span className={`px-4 py-2 rounded-full text-lg font-bold ${
                  hybridAnalysisResults.hybridAnalysis.verdict === 'malicious'
                    ? 'bg-red-600 text-white'
                    : hybridAnalysisResults.hybridAnalysis.verdict === 'suspicious'
                    ? 'bg-yellow-600 text-white'
                    : 'bg-green-600 text-white'
                }`}>
                  {hybridAnalysisResults.hybridAnalysis.verdict === 'malicious' && '❌ Malicious'}
                  {hybridAnalysisResults.hybridAnalysis.verdict === 'suspicious' && '⚠️ Suspicious'}
                  {hybridAnalysisResults.hybridAnalysis.verdict === 'clean' && '✅ Clean'}
                </span>
                <div>
                  <p className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                    {hybridAnalysisResults.hybridAnalysis.threatScore}/100
                  </p>
                  <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Threat Score</p>
                </div>
              </div>

              {hybridAnalysisResults.hybridAnalysis.mitreTechniques?.length > 0 && (
                <div className={`mb-4 p-4 rounded-lg border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                  <h5 className={`text-md font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                    🎯 MITRE ATT&CK Techniques ({hybridAnalysisResults.hybridAnalysis.mitreTechniques.length})
                  </h5>
                  <div className="flex flex-wrap gap-2">
                    {hybridAnalysisResults.hybridAnalysis.mitreTechniques.slice(0, 8).map((t, i) => (
                      <a
                        key={i}
                        href={`https://attack.mitre.org/techniques/${t.attackId?.replace('.', '/')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={`px-2 py-1 rounded text-xs font-mono ${darkMode ? 'bg-purple-900 text-purple-300' : 'bg-purple-100 text-purple-800'}`}
                      >
                        {t.attackId}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Shodan */}
          {results.shodan?.hasData && (
            <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-700' : 'bg-white border-gray-200'}`}>
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
                  <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Open Ports</p>
                  <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.shodan.openPortsCount}</p>
                </div>
              </div>
              {results.shodan.ports?.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {results.shodan.ports.map((port, i) => (
                    <span key={i} className={`px-3 py-1 rounded font-mono text-sm ${darkMode ? 'bg-gray-600 text-white' : 'bg-gray-200 text-gray-900'}`}>
                      {port}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* GreyNoise */}
          {results.greyNoise && !results.greyNoise.error && (
            <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-700' : 'bg-white border-gray-200'}`}>
              <div className="flex items-center justify-between mb-4">
                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>🌐 GreyNoise Intelligence</h4>
                <a
                  href={`https://www.greynoise.io/viz/ip/${results.indicator}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                >
                  View Full Report →
                </a>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  results.greyNoise.classification === 'malicious'
                    ? 'bg-red-100 text-red-800'
                    : results.greyNoise.classification === 'benign'
                    ? 'bg-green-100 text-green-800'
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {results.greyNoise.classification?.toUpperCase()}
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
            </div>
          )}

          {/* AlienVault OTX */}
          {results.alienVault?.hasData && (
            <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-700' : 'bg-white border-gray-200'}`}>
              <div className="flex items-center justify-between mb-4">
                <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>🔮 AlienVault OTX</h4>
                <a
                  href={`https://otx.alienvault.com/indicator/${results.type === 'IP' ? 'ip' : 'file'}/${results.indicator}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-500 hover:text-blue-600 font-semibold text-sm"
                >
                  View Full Report →
                </a>
              </div>
              <div className={`px-4 py-2 rounded-lg inline-block ${darkMode ? 'bg-blue-900' : 'bg-blue-50'}`}>
                <p className={`text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>
                  <strong>{results.alienVault.pulseCount}</strong> Threat Pulses
                </p>
              </div>
              {results.alienVault.pulses?.length > 0 && (
                <div className="mt-4 space-y-2">
                  {results.alienVault.pulses.slice(0, 3).map((pulse, i) => (
                    <div key={i} className={`p-3 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                      <a
                        href={`https://otx.alienvault.com/pulse/${pulse.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={`font-semibold hover:underline ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}
                      >
                        {pulse.name}
                      </a>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ARIN RDAP */}
          {results.arin?.hasData && (
            <div className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-700' : 'bg-white border-gray-200'}`}>
              <h4 className={`text-lg font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>🌍 ARIN RDAP (IP Registration)</h4>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Organization</p>
                  <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.arin.org}</p>
                </div>
                <div>
                  <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Network Range</p>
                  <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.arin.startAddress} – {results.arin.endAddress}</p>
                </div>
                <div>
                  <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Handle</p>
                  <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.arin.handle}</p>
                </div>
                <div>
                  <p className={`text-sm font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Abuse Contact</p>
                  <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{results.arin.abuseContact}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Error display */}
      {results?.error && (
        <div className={`mt-6 p-4 rounded-lg ${darkMode ? 'bg-red-900 border border-red-700' : 'bg-red-50 border border-red-300'}`}>
          <p className={`${darkMode ? 'text-red-300' : 'text-red-800'}`}>
            <strong>Error:</strong> {results.error}
          </p>
        </div>
      )}
    </div>
  );
}
