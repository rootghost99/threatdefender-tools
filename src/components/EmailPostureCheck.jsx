import React, { useState } from 'react';

export default function EmailPostureCheck({ darkMode }) {
  const [domain, setDomain] = useState('');
  const [dkimSelectors, setDkimSelectors] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedSections, setExpandedSections] = useState({
    spf: false,
    dmarc: false,
    dkim: false,
    mx: false,
    mtaSts: false,
    bimi: false,
    mxToolbox: false
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const runAnalysis = async () => {
    if (!domain.trim()) {
      setError('Please enter a domain to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await fetch('/api/EmailPosture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domain.trim(),
          dkimSelectors: dkimSelectors.trim() ? dkimSelectors.split(',').map(s => s.trim()) : []
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);

      // Auto-expand sections with issues
      const newExpanded = {};
      if (data.spf?.issues) newExpanded.spf = true;
      if (data.dmarc?.issues) newExpanded.dmarc = true;
      if (data.dkim?.selectors?.some(s => s.issues)) newExpanded.dkim = true;
      if (data.mx?.issues) newExpanded.mx = true;
      setExpandedSections(newExpanded);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'pass': return '✅';
      case 'warn': return '⚠️';
      case 'fail': return '❌';
      case 'not_configured': return '⚪';
      default: return '⚪';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'pass': return darkMode ? 'text-green-400' : 'text-green-600';
      case 'warn': return darkMode ? 'text-yellow-400' : 'text-yellow-600';
      case 'fail': return darkMode ? 'text-red-400' : 'text-red-600';
      case 'not_configured': return darkMode ? 'text-gray-500' : 'text-gray-400';
      default: return darkMode ? 'text-gray-500' : 'text-gray-400';
    }
  };

  const exportMarkdown = () => {
    if (!results) return;

    let markdown = `# Email Posture Report: ${results.domain}\n\n`;
    markdown += `**Generated:** ${new Date(results.timestamp).toLocaleString()}\n\n`;
    markdown += `## Summary\n\n`;
    markdown += `- **Overall Status:** ${results.summary.overallStatus.toUpperCase()}\n`;
    markdown += `- **Passed:** ${results.summary.passCount}/${results.summary.totalChecks}\n`;
    markdown += `- **Warnings:** ${results.summary.warnCount}\n`;
    markdown += `- **Failed:** ${results.summary.failCount}\n\n`;

    if (results.summary.issues.length > 0) {
      markdown += `## Issues Found\n\n`;
      results.summary.issues.forEach(issue => {
        markdown += `- **[${issue.category}]** (${issue.severity}): ${issue.message}\n`;
      });
      markdown += `\n`;
    }

    markdown += `## SPF (Sender Policy Framework)\n\n`;
    markdown += `- **Status:** ${results.spf.status}\n`;
    if (results.spf.record) {
      markdown += `- **Record:** \`${results.spf.record}\`\n`;
      markdown += `- **DNS Lookups:** ${results.spf.lookupCount}/10\n`;
      markdown += `- **Mechanism:** ${results.spf.mechanism}\n`;
    }
    if (results.spf.issues) {
      markdown += `- **Issues:**\n`;
      results.spf.issues.forEach(i => markdown += `  - ${i}\n`);
    }
    markdown += `\n`;

    markdown += `## DMARC (Domain-based Message Authentication)\n\n`;
    markdown += `- **Status:** ${results.dmarc.status}\n`;
    if (results.dmarc.record) {
      markdown += `- **Record:** \`${results.dmarc.record}\`\n`;
      markdown += `- **Policy:** ${results.dmarc.policy}\n`;
      if (results.dmarc.reporting.aggregate) {
        markdown += `- **Aggregate Reporting:** ${results.dmarc.reporting.aggregate}\n`;
      }
    }
    if (results.dmarc.issues) {
      markdown += `- **Issues:**\n`;
      results.dmarc.issues.forEach(i => markdown += `  - ${i}\n`);
    }
    markdown += `\n`;

    markdown += `## DKIM (DomainKeys Identified Mail)\n\n`;
    markdown += `- **Status:** ${results.dkim.status}\n`;
    markdown += `- **Valid Keys:** ${results.dkim.validKeysCount}/${results.dkim.totalChecked}\n`;
    results.dkim.selectors.forEach(sel => {
      if (sel.status === 'pass' || sel.status === 'warn') {
        markdown += `\n### Selector: ${sel.selector}\n`;
        markdown += `- **Status:** ${sel.status}\n`;
        markdown += `- **Key Length:** ${sel.keyLength} bits\n`;
        if (sel.issues) {
          markdown += `- **Issues:**\n`;
          sel.issues.forEach(i => markdown += `  - ${i}\n`);
        }
      }
    });
    markdown += `\n`;

    markdown += `## MX (Mail Exchange)\n\n`;
    markdown += `- **Status:** ${results.mx.status}\n`;
    markdown += `- **Records Found:** ${results.mx.count}\n`;
    results.mx.records.forEach(mx => {
      markdown += `\n- **${mx.exchange}** (Priority: ${mx.priority})\n`;
      if (mx.vendor) markdown += `  - Vendor: ${mx.vendor}\n`;
      if (mx.ips.length > 0) markdown += `  - IPs: ${mx.ips.join(', ')}\n`;
    });
    if (results.mx.issues) {
      markdown += `\n**Issues:**\n`;
      results.mx.issues.forEach(i => markdown += `- ${i}\n`);
    }
    markdown += `\n`;

    if (results.mtaSts.status !== 'not_configured') {
      markdown += `## MTA-STS (SMTP MTA Strict Transport Security)\n\n`;
      markdown += `- **Status:** ${results.mtaSts.status}\n`;
      if (results.mtaSts.dnsRecord) {
        markdown += `- **DNS Record:** \`${results.mtaSts.dnsRecord}\`\n`;
      }
      if (results.mtaSts.issues) {
        markdown += `- **Issues:**\n`;
        results.mtaSts.issues.forEach(i => markdown += `  - ${i}\n`);
      }
      markdown += `\n`;
    }

    if (results.bimi.status !== 'not_configured') {
      markdown += `## BIMI (Brand Indicators for Message Identification)\n\n`;
      markdown += `- **Status:** ${results.bimi.status}\n`;
      if (results.bimi.record) {
        markdown += `- **Record:** \`${results.bimi.record}\`\n`;
        markdown += `- **Logo URL:** ${results.bimi.logoUrl || 'Not specified'}\n`;
      }
      markdown += `\n`;
    }

    if (results.mxToolbox && !results.mxToolbox.error) {
      markdown += `## MXToolbox Email Health\n\n`;
      markdown += `- **Email Health Score:** ${results.mxToolbox.emailHealthScore}/100\n`;
      markdown += `- **View Full Report:** ${results.mxToolbox.deepLink}\n\n`;
    }

    markdown += `---\n\n`;
    markdown += `*Report generated by ThreatDefender Email Posture Check*\n`;

    // Download
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-posture-${results.domain}-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Escape HTML to prevent XSS in exported HTML reports
  const escapeHtml = (text) => {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  const exportHTML = () => {
    if (!results) return;

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Email Posture Report - ${results.domain}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 40px auto; padding: 20px; line-height: 1.6; background: #f9fafb; }
    .header { background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; }
    h1 { margin: 0; font-size: 28px; }
    .timestamp { opacity: 0.9; margin-top: 10px; font-size: 14px; }
    .summary { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 30px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
    .summary-item { text-align: center; padding: 15px; background: #f3f4f6; border-radius: 8px; }
    .summary-value { font-size: 32px; font-weight: bold; }
    .summary-label { font-size: 12px; color: #6b7280; margin-top: 5px; text-transform: uppercase; }
    .section { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
    .section-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
    .status-pass { color: #16a34a; }
    .status-warn { color: #ea580c; }
    .status-fail { color: #dc2626; }
    .status-not_configured { color: #9ca3af; }
    .record-box { background: #f3f4f6; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 13px; margin: 10px 0; word-break: break-all; }
    .issue { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 8px 0; border-radius: 4px; }
    .issue-high { background: #fee2e2; border-left-color: #dc2626; }
    .mx-record { background: #f3f4f6; padding: 12px; margin: 8px 0; border-radius: 8px; }
    .footer { text-align: center; margin-top: 50px; padding-top: 30px; border-top: 2px solid #e5e7eb; color: #6b7280; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { background: #1e40af; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #e5e7eb; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Email Posture Report</h1>
    <div class="timestamp">Domain: ${escapeHtml(results.domain)} | Generated: ${escapeHtml(new Date(results.timestamp).toLocaleString())}</div>
  </div>

  <div class="summary">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-item">
        <div class="summary-value status-${results.summary.overallStatus}">${results.summary.overallStatus.toUpperCase()}</div>
        <div class="summary-label">Overall Status</div>
      </div>
      <div class="summary-item">
        <div class="summary-value status-pass">${results.summary.passCount}</div>
        <div class="summary-label">Passed</div>
      </div>
      <div class="summary-item">
        <div class="summary-value status-warn">${results.summary.warnCount}</div>
        <div class="summary-label">Warnings</div>
      </div>
      <div class="summary-item">
        <div class="summary-value status-fail">${results.summary.failCount}</div>
        <div class="summary-label">Failed</div>
      </div>
    </div>
    ${results.summary.issues.length > 0 ? `
      <h3>Issues Requiring Attention</h3>
      ${results.summary.issues.map(issue => `
        <div class="issue ${issue.severity === 'high' ? 'issue-high' : ''}">
          <strong>[${escapeHtml(issue.category)}]</strong> ${escapeHtml(issue.message)}
        </div>
      `).join('')}
    ` : '<p style="color: #16a34a; margin-top: 20px;">✅ No critical issues found!</p>'}
  </div>

  <div class="section">
    <div class="section-header">
      <h2>SPF (Sender Policy Framework)</h2>
      <span class="status-${results.spf.status}" style="font-size: 24px;">${getStatusIcon(results.spf.status)}</span>
    </div>
    ${results.spf.record ? `
      <div class="record-box">${escapeHtml(results.spf.record)}</div>
      <p><strong>DNS Lookups:</strong> ${escapeHtml(String(results.spf.lookupCount))}/10</p>
      <p><strong>Mechanism:</strong> ${escapeHtml(results.spf.mechanism)}</p>
    ` : '<p>No SPF record found</p>'}
    ${results.spf.issues ? results.spf.issues.map(i => `<div class="issue">${escapeHtml(i)}</div>`).join('') : ''}
  </div>

  <div class="section">
    <div class="section-header">
      <h2>DMARC (Domain-based Message Authentication)</h2>
      <span class="status-${results.dmarc.status}" style="font-size: 24px;">${getStatusIcon(results.dmarc.status)}</span>
    </div>
    ${results.dmarc.record ? `
      <div class="record-box">${escapeHtml(results.dmarc.record)}</div>
      <p><strong>Policy:</strong> ${escapeHtml(results.dmarc.policy)}</p>
      <p><strong>Percentage:</strong> ${escapeHtml(String(results.dmarc.percentage))}%</p>
      ${results.dmarc.reporting.aggregate ? `<p><strong>Aggregate Reporting:</strong> ${escapeHtml(results.dmarc.reporting.aggregate)}</p>` : ''}
    ` : '<p>No DMARC record found</p>'}
    ${results.dmarc.issues ? results.dmarc.issues.map(i => `<div class="issue">${escapeHtml(i)}</div>`).join('') : ''}
  </div>

  <div class="section">
    <div class="section-header">
      <h2>DKIM (DomainKeys Identified Mail)</h2>
      <span class="status-${results.dkim.status}" style="font-size: 24px;">${getStatusIcon(results.dkim.status)}</span>
    </div>
    <p><strong>Valid Keys:</strong> ${results.dkim.validKeysCount}/${results.dkim.totalChecked} selectors checked</p>
    ${results.dkim.selectors.filter(s => s.status === 'pass' || s.status === 'warn').map(sel => `
      <div class="mx-record">
        <strong>Selector: ${sel.selector}</strong> ${getStatusIcon(sel.status)}<br>
        Key Length: ${sel.keyLength} bits<br>
        ${sel.issues ? sel.issues.map(i => `<div class="issue">${escapeHtml(i)}</div>`).join('') : ''}
      </div>
    `).join('')}
  </div>

  <div class="section">
    <div class="section-header">
      <h2>MX (Mail Exchange)</h2>
      <span class="status-${escapeHtml(results.mx.status)}" style="font-size: 24px;">${getStatusIcon(results.mx.status)}</span>
    </div>
    <p><strong>Records Found:</strong> ${escapeHtml(String(results.mx.count))}</p>
    ${results.mx.records.map(mx => `
      <div class="mx-record">
        <strong>${escapeHtml(mx.exchange)}</strong> (Priority: ${escapeHtml(String(mx.priority))})<br>
        ${mx.vendor ? `Vendor: ${escapeHtml(mx.vendor)}<br>` : ''}
        ${mx.ips.length > 0 ? `IPs: ${escapeHtml(mx.ips.join(', '))}` : ''}
      </div>
    `).join('')}
    ${results.mx.issues ? results.mx.issues.map(i => `<div class="issue">${escapeHtml(i)}</div>`).join('') : ''}
  </div>

  ${results.mtaSts.status !== 'not_configured' ? `
    <div class="section">
      <div class="section-header">
        <h2>MTA-STS</h2>
        <span class="status-${results.mtaSts.status}" style="font-size: 24px;">${getStatusIcon(results.mtaSts.status)}</span>
      </div>
      ${results.mtaSts.dnsRecord ? `<div class="record-box">${escapeHtml(results.mtaSts.dnsRecord)}</div>` : ''}
      ${results.mtaSts.issues ? results.mtaSts.issues.map(i => `<div class="issue">${escapeHtml(i)}</div>`).join('') : ''}
    </div>
  ` : ''}

  ${results.bimi.status !== 'not_configured' ? `
    <div class="section">
      <div class="section-header">
        <h2>BIMI</h2>
        <span class="status-${results.bimi.status}" style="font-size: 24px;">${getStatusIcon(results.bimi.status)}</span>
      </div>
      ${results.bimi.record ? `<div class="record-box">${escapeHtml(results.bimi.record)}</div>` : ''}
    </div>
  ` : ''}

  ${results.mxToolbox && !results.mxToolbox.error ? `
    <div class="section">
      <h2>MXToolbox Email Health</h2>
      <div class="summary-item" style="max-width: 200px;">
        <div class="summary-value" style="color: ${results.mxToolbox.emailHealthScore >= 80 ? '#16a34a' : results.mxToolbox.emailHealthScore >= 60 ? '#ea580c' : '#dc2626'}">
          ${results.mxToolbox.emailHealthScore}
        </div>
        <div class="summary-label">Health Score</div>
      </div>
      <p style="margin-top: 20px;"><a href="${results.mxToolbox.deepLink && results.mxToolbox.deepLink.startsWith('https://') ? escapeHtml(results.mxToolbox.deepLink) : '#'}" target="_blank" rel="noopener noreferrer">View Full Report in MXToolbox →</a></p>
    </div>
  ` : ''}

  <div class="footer">
    <p><strong>ThreatDefender Email Posture Check</strong></p>
    <p>eGroup Enabling Technologies | ThreatDefender MSSP/MXDR</p>
    <p style="font-size: 12px; color: #9ca3af;">Report generated on ${new Date().toLocaleString()}</p>
  </div>
</body>
</html>`;

    // Download
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-posture-${results.domain}-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`space-y-6 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
      {/* Header */}
      <div className={`p-6 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
        <h2 className="text-2xl font-bold mb-2">📧 Email Posture Check</h2>
        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
          Comprehensive email security analysis: SPF, DMARC, DKIM, MX, MTA-STS, and BIMI validation
        </p>
      </div>

      {/* Input Form */}
      <div className={`p-6 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
        <div className="space-y-4">
          <div>
            <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
              Domain to Analyze
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className={`w-full px-4 py-3 rounded-md border ${
                darkMode
                  ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
              } focus:outline-none focus:ring-2 focus:ring-blue-500`}
              onKeyPress={(e) => e.key === 'Enter' && runAnalysis()}
            />
          </div>

          <div>
            <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
              DKIM Selectors (optional, comma-separated)
            </label>
            <input
              type="text"
              value={dkimSelectors}
              onChange={(e) => setDkimSelectors(e.target.value)}
              placeholder="selector1, selector2, google"
              className={`w-full px-4 py-3 rounded-md border ${
                darkMode
                  ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
              } focus:outline-none focus:ring-2 focus:ring-blue-500`}
            />
            <p className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
              Leave empty to use common selectors (selector1, selector2, google, etc.)
            </p>
          </div>

          <button
            onClick={runAnalysis}
            disabled={loading}
            className={`w-full py-3 px-6 rounded-md font-semibold transition ${
              loading
                ? darkMode
                  ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                : darkMode
                  ? 'bg-blue-600 text-white hover:bg-blue-500'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            {loading ? '🔄 Analyzing...' : '🔍 Run Email Posture Check'}
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="p-4 rounded-lg bg-red-900 text-red-200 border border-red-700">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary */}
          <div className={`p-6 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
            <h3 className="text-xl font-bold mb-4">Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className={`text-3xl font-bold ${getStatusColor(results.summary.overallStatus)}`}>
                  {results.summary.overallStatus.toUpperCase()}
                </div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Overall</div>
              </div>
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className="text-3xl font-bold text-green-500">{results.summary.passCount}</div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Passed</div>
              </div>
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className="text-3xl font-bold text-yellow-500">{results.summary.warnCount}</div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Warnings</div>
              </div>
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className="text-3xl font-bold text-red-500">{results.summary.failCount}</div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Failed</div>
              </div>
            </div>

            {results.summary.issues.length > 0 && (
              <div className="mt-6">
                <h4 className="font-semibold mb-3">Issues Found:</h4>
                <div className="space-y-2">
                  {results.summary.issues.map((issue, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg ${
                        issue.severity === 'high'
                          ? 'bg-red-900 border-l-4 border-red-600'
                          : 'bg-yellow-900 border-l-4 border-yellow-600'
                      }`}
                    >
                      <span className="font-semibold">[{issue.category}]</span> {issue.message}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MXToolbox Health Score */}
            {results.mxToolbox && !results.mxToolbox.error && (
              <div className="mt-6 p-4 rounded-lg bg-gradient-to-r from-blue-900 to-purple-900">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-semibold">MXToolbox Email Health Score</h4>
                    <p className="text-sm text-gray-300">Enriched data from MXToolbox API</p>
                  </div>
                  <div className="text-4xl font-bold">{results.mxToolbox.emailHealthScore}/100</div>
                </div>
                <a
                  href={results.mxToolbox.deepLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-3 inline-block text-blue-300 hover:text-blue-200 text-sm"
                >
                  View in MXToolbox →
                </a>
              </div>
            )}

            {/* Export Buttons */}
            <div className="mt-6 flex gap-3">
              <button
                onClick={exportMarkdown}
                className={`flex-1 py-2 px-4 rounded-md font-semibold transition ${
                  darkMode
                    ? 'bg-green-700 text-white hover:bg-green-600'
                    : 'bg-green-600 text-white hover:bg-green-700'
                }`}
              >
                📄 Export as Markdown
              </button>
              <button
                onClick={exportHTML}
                className={`flex-1 py-2 px-4 rounded-md font-semibold transition ${
                  darkMode
                    ? 'bg-purple-700 text-white hover:bg-purple-600'
                    : 'bg-purple-600 text-white hover:bg-purple-700'
                }`}
              >
                🌐 Export as HTML
              </button>
            </div>
          </div>

          {/* Detailed Results */}
          <div className="space-y-4">
            {/* SPF */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('spf')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{getStatusIcon(results.spf.status)}</span>
                  <div>
                    <h3 className="text-lg font-bold">SPF (Sender Policy Framework)</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Status: {results.spf.status}
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.spf ? '▼' : '▶'}</span>
              </button>
              {expandedSections.spf && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  {results.spf.record ? (
                    <>
                      <div className={`p-3 rounded-md font-mono text-sm ${darkMode ? 'bg-gray-700' : 'bg-gray-100'} break-all`}>
                        {results.spf.record}
                      </div>
                      <div className="mt-4 grid grid-cols-2 gap-4">
                        <div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>DNS Lookups</p>
                          <p className="text-lg font-semibold">{results.spf.lookupCount}/10</p>
                        </div>
                        <div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Mechanism</p>
                          <p className="text-lg font-semibold">{results.spf.mechanism || 'N/A'}</p>
                        </div>
                      </div>
                      {results.spf.issues && (
                        <div className="mt-4 space-y-2">
                          {results.spf.issues.map((issue, idx) => (
                            <div key={idx} className="p-3 rounded-md bg-yellow-900 border-l-4 border-yellow-600">
                              {issue}
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>No SPF record found</p>
                  )}
                </div>
              )}
            </div>

            {/* DMARC */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('dmarc')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{getStatusIcon(results.dmarc.status)}</span>
                  <div>
                    <h3 className="text-lg font-bold">DMARC (Domain-based Message Authentication)</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Status: {results.dmarc.status} | Policy: {results.dmarc.policy || 'N/A'}
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.dmarc ? '▼' : '▶'}</span>
              </button>
              {expandedSections.dmarc && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  {results.dmarc.record ? (
                    <>
                      <div className={`p-3 rounded-md font-mono text-sm ${darkMode ? 'bg-gray-700' : 'bg-gray-100'} break-all`}>
                        {results.dmarc.record}
                      </div>
                      <div className="mt-4 grid grid-cols-2 gap-4">
                        <div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Policy</p>
                          <p className="text-lg font-semibold">{results.dmarc.policy}</p>
                        </div>
                        <div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Percentage</p>
                          <p className="text-lg font-semibold">{results.dmarc.percentage}%</p>
                        </div>
                      </div>
                      {results.dmarc.reporting.aggregate && (
                        <div className="mt-4">
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Aggregate Reporting</p>
                          <p className="text-sm font-mono">{results.dmarc.reporting.aggregate}</p>
                        </div>
                      )}
                      {results.dmarc.issues && (
                        <div className="mt-4 space-y-2">
                          {results.dmarc.issues.map((issue, idx) => (
                            <div key={idx} className="p-3 rounded-md bg-yellow-900 border-l-4 border-yellow-600">
                              {issue}
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>No DMARC record found</p>
                  )}
                </div>
              )}
            </div>

            {/* DKIM */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('dkim')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{getStatusIcon(results.dkim.status)}</span>
                  <div>
                    <h3 className="text-lg font-bold">DKIM (DomainKeys Identified Mail)</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Valid Keys: {results.dkim.validKeysCount}/{results.dkim.totalChecked}
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.dkim ? '▼' : '▶'}</span>
              </button>
              {expandedSections.dkim && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  <div className="space-y-3">
                    {results.dkim.selectors
                      .filter(s => s.status === 'pass' || s.status === 'warn')
                      .map((sel, idx) => (
                        <div key={idx} className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-semibold">Selector: {sel.selector}</span>
                            <span className="text-xl">{getStatusIcon(sel.status)}</span>
                          </div>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                            Key Length: {sel.keyLength} bits | Type: {sel.keyType}
                          </p>
                          {sel.issues && (
                            <div className="mt-3 space-y-2">
                              {sel.issues.map((issue, iidx) => (
                                <div key={iidx} className="p-2 rounded-md bg-yellow-900 border-l-4 border-yellow-600 text-sm">
                                  {issue}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    {results.dkim.validKeysCount === 0 && (
                      <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
                        No valid DKIM keys found for the selectors checked
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* MX */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('mx')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{getStatusIcon(results.mx.status)}</span>
                  <div>
                    <h3 className="text-lg font-bold">MX (Mail Exchange)</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Records: {results.mx.count}
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.mx ? '▼' : '▶'}</span>
              </button>
              {expandedSections.mx && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  <div className="space-y-3">
                    {results.mx.records.map((mx, idx) => (
                      <div key={idx} className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-semibold">{mx.exchange}</span>
                          <span className={`text-sm px-2 py-1 rounded ${darkMode ? 'bg-gray-600' : 'bg-gray-200'}`}>
                            Priority: {mx.priority}
                          </span>
                        </div>
                        {mx.vendor && (
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                            Vendor: {mx.vendor}
                          </p>
                        )}
                        {mx.ips.length > 0 && (
                          <p className={`text-xs mt-1 font-mono ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                            IPs: {mx.ips.join(', ')}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                  {results.mx.issues && (
                    <div className="mt-4 space-y-2">
                      {results.mx.issues.map((issue, idx) => (
                        <div key={idx} className="p-3 rounded-md bg-yellow-900 border-l-4 border-yellow-600">
                          {issue}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* MTA-STS (if configured) */}
            {results.mtaSts.status !== 'not_configured' && (
              <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
                <button
                  onClick={() => toggleSection('mtaSts')}
                  className={`w-full p-4 text-left flex items-center justify-between ${
                    darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                  } transition`}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{getStatusIcon(results.mtaSts.status)}</span>
                    <div>
                      <h3 className="text-lg font-bold">MTA-STS (SMTP MTA Strict Transport Security)</h3>
                      <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                        Status: {results.mtaSts.status}
                      </p>
                    </div>
                  </div>
                  <span className="text-2xl">{expandedSections.mtaSts ? '▼' : '▶'}</span>
                </button>
                {expandedSections.mtaSts && (
                  <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                    {results.mtaSts.dnsRecord && (
                      <div className={`p-3 rounded-md font-mono text-sm ${darkMode ? 'bg-gray-700' : 'bg-gray-100'} break-all`}>
                        {results.mtaSts.dnsRecord}
                      </div>
                    )}
                    {results.mtaSts.issues && (
                      <div className="mt-4 space-y-2">
                        {results.mtaSts.issues.map((issue, idx) => (
                          <div key={idx} className="p-3 rounded-md bg-yellow-900 border-l-4 border-yellow-600">
                            {issue}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* BIMI (if configured) */}
            {results.bimi.status !== 'not_configured' && (
              <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
                <button
                  onClick={() => toggleSection('bimi')}
                  className={`w-full p-4 text-left flex items-center justify-between ${
                    darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                  } transition`}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{getStatusIcon(results.bimi.status)}</span>
                    <div>
                      <h3 className="text-lg font-bold">BIMI (Brand Indicators for Message Identification)</h3>
                      <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                        Status: {results.bimi.status}
                      </p>
                    </div>
                  </div>
                  <span className="text-2xl">{expandedSections.bimi ? '▼' : '▶'}</span>
                </button>
                {expandedSections.bimi && (
                  <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                    {results.bimi.record && (
                      <>
                        <div className={`p-3 rounded-md font-mono text-sm ${darkMode ? 'bg-gray-700' : 'bg-gray-100'} break-all mb-4`}>
                          {results.bimi.record}
                        </div>
                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Logo URL: {results.bimi.logoUrl || 'Not specified'}
                        </p>
                      </>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
