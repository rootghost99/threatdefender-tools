import React, { useState } from 'react';

export default function EmailHeaderAnalyzer({ darkMode }) {
  const [rawHeaders, setRawHeaders] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedSections, setExpandedSections] = useState({
    keyHeaders: true,
    deliveryPath: true,
    authentication: false,
    securityFindings: true,
    allHeaders: false
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const runAnalysis = async () => {
    if (!rawHeaders.trim()) {
      setError('Please paste email headers to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await fetch('/api/EmailHeaderAnalyzer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headers: rawHeaders })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);

      // Auto-expand sections with issues
      const newExpanded = {
        keyHeaders: true,
        deliveryPath: data.deliveryPath?.issues?.length > 0,
        authentication: data.authentication?.overallStatus !== 'pass',
        securityFindings: data.securityAnalysis?.totalFindings > 0,
        allHeaders: false
      };
      setExpandedSections(newExpanded);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const clearAnalysis = () => {
    setRawHeaders('');
    setResults(null);
    setError(null);
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'high': return '🔴';
      case 'medium': return '🟠';
      case 'low': return '🟡';
      case 'info': return '🔵';
      default: return '⚪';
    }
  };

  const getRiskLevelColor = (level) => {
    switch (level) {
      case 'high': return darkMode ? 'text-red-400' : 'text-red-600';
      case 'medium': return darkMode ? 'text-orange-400' : 'text-orange-600';
      case 'low': return darkMode ? 'text-yellow-400' : 'text-yellow-600';
      case 'clean': return darkMode ? 'text-green-400' : 'text-green-600';
      default: return darkMode ? 'text-gray-400' : 'text-gray-600';
    }
  };

  const getAuthStatusIcon = (status) => {
    switch (status) {
      case 'pass': return '✅';
      case 'fail': return '❌';
      case 'partial': return '⚠️';
      case 'softfail': return '⚠️';
      case 'neutral': return '⚪';
      case 'none': return '⚪';
      default: return '❓';
    }
  };

  const getAuthStatusColor = (status) => {
    switch (status) {
      case 'pass': return darkMode ? 'text-green-400' : 'text-green-600';
      case 'fail': case 'hardfail': return darkMode ? 'text-red-400' : 'text-red-600';
      case 'partial': case 'softfail': return darkMode ? 'text-yellow-400' : 'text-yellow-600';
      default: return darkMode ? 'text-gray-400' : 'text-gray-600';
    }
  };

  const exportMarkdown = () => {
    if (!results) return;

    let markdown = `# Email Header Security Analysis Report\n\n`;
    markdown += `**Generated:** ${new Date(results.timestamp).toLocaleString()}\n\n`;

    // Summary
    markdown += `## Summary\n\n`;
    markdown += `- **Risk Level:** ${results.summary.riskLevel.toUpperCase()}\n`;
    markdown += `- **Risk Score:** ${results.summary.riskScore}/100\n`;
    markdown += `- **Authentication Status:** ${results.summary.authenticationStatus}\n`;
    markdown += `- **Total Hops:** ${results.summary.totalHops}\n`;
    if (results.summary.totalTransitTime) {
      markdown += `- **Total Transit Time:** ${results.summary.totalTransitTime}\n`;
    }
    markdown += `\n`;

    // Findings Summary
    markdown += `### Findings\n`;
    markdown += `- High: ${results.summary.findingsCount.high}\n`;
    markdown += `- Medium: ${results.summary.findingsCount.medium}\n`;
    markdown += `- Low: ${results.summary.findingsCount.low}\n`;
    markdown += `- Info: ${results.summary.findingsCount.info}\n\n`;

    // Key Headers
    markdown += `## Key Email Headers\n\n`;
    const kh = results.keyHeaders;
    if (kh.from) markdown += `- **From:** ${kh.from}\n`;
    if (kh.to) markdown += `- **To:** ${kh.to}\n`;
    if (kh.subject) markdown += `- **Subject:** ${kh.subject}\n`;
    if (kh.date) markdown += `- **Date:** ${kh.date}\n`;
    if (kh.returnPath) markdown += `- **Return-Path:** ${kh.returnPath}\n`;
    if (kh.replyTo) markdown += `- **Reply-To:** ${kh.replyTo}\n`;
    if (kh.messageId) markdown += `- **Message-ID:** ${kh.messageId}\n`;
    if (kh.xOriginatingIP) markdown += `- **X-Originating-IP:** ${kh.xOriginatingIP}\n`;
    markdown += `\n`;

    // Authentication Results
    markdown += `## Authentication Results\n\n`;
    markdown += `| Check | Status | Details |\n`;
    markdown += `|-------|--------|--------|\n`;
    markdown += `| SPF | ${results.authentication.spf.status} | ${results.authentication.spf.details || '-'} |\n`;
    markdown += `| DKIM | ${results.authentication.dkim.status} | ${results.authentication.dkim.details || '-'} |\n`;
    markdown += `| DMARC | ${results.authentication.dmarc.status} | ${results.authentication.dmarc.details || '-'} |\n`;
    if (results.authentication.arc.status !== 'unknown') {
      markdown += `| ARC | ${results.authentication.arc.status} | ${results.authentication.arc.seals} seal(s) |\n`;
    }
    markdown += `\n`;

    // Delivery Path
    markdown += `## Delivery Path\n\n`;
    if (results.deliveryPath.hops && results.deliveryPath.hops.length > 0) {
      markdown += `| Hop | Server | From IP | Time | Delay | TLS |\n`;
      markdown += `|-----|--------|---------|------|-------|-----|\n`;
      results.deliveryPath.hops.forEach(hop => {
        markdown += `| ${hop.hopNumber} | ${hop.by || '-'} | ${hop.fromIP || '-'} | ${hop.timestampRaw || '-'} | ${hop.delayFormatted || '-'} | ${hop.tls ? 'Yes' : 'No'} |\n`;
      });
    } else {
      markdown += `No delivery path information available.\n`;
    }
    markdown += `\n`;

    // Security Findings
    if (results.securityAnalysis.findings.length > 0) {
      markdown += `## Security Findings\n\n`;
      results.securityAnalysis.findings.forEach(finding => {
        markdown += `### ${finding.severity.toUpperCase()}: ${finding.title}\n`;
        markdown += `**Category:** ${finding.category}\n\n`;
        markdown += `${finding.description}\n\n`;
      });
    }

    // Recommendations
    if (results.summary.recommendations.length > 0) {
      markdown += `## Recommendations\n\n`;
      results.summary.recommendations.forEach(rec => {
        markdown += `- **[${rec.priority.toUpperCase()}]** ${rec.action}\n`;
      });
    }

    markdown += `\n---\n\n`;
    markdown += `*Report generated by ThreatDefender Email Header Analyzer*\n`;

    // Download
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-header-analysis-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportHTML = () => {
    if (!results) return;

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Email Header Security Analysis</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 40px auto; padding: 20px; line-height: 1.6; background: #f9fafb; }
    .header { background: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; }
    h1 { margin: 0; font-size: 28px; }
    .timestamp { opacity: 0.9; margin-top: 10px; font-size: 14px; }
    .summary { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 30px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
    .summary-item { text-align: center; padding: 15px; background: #f3f4f6; border-radius: 8px; }
    .summary-value { font-size: 28px; font-weight: bold; }
    .summary-label { font-size: 12px; color: #6b7280; margin-top: 5px; text-transform: uppercase; }
    .section { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
    .risk-high { color: #dc2626; }
    .risk-medium { color: #ea580c; }
    .risk-low { color: #eab308; }
    .risk-clean { color: #16a34a; }
    .auth-pass { color: #16a34a; }
    .auth-fail { color: #dc2626; }
    .auth-partial { color: #ea580c; }
    .finding { border-left: 4px solid #ddd; padding: 15px; margin: 10px 0; background: #f9fafb; border-radius: 4px; }
    .finding-high { border-left-color: #dc2626; background: #fef2f2; }
    .finding-medium { border-left-color: #ea580c; background: #fff7ed; }
    .finding-low { border-left-color: #eab308; background: #fefce8; }
    .finding-info { border-left-color: #3b82f6; background: #eff6ff; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { background: #7c3aed; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #e5e7eb; }
    .mono { font-family: monospace; font-size: 13px; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
    .footer { text-align: center; margin-top: 50px; padding-top: 30px; border-top: 2px solid #e5e7eb; color: #6b7280; }
    .recommendation { background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px; margin: 8px 0; border-radius: 4px; }
    .recommendation-critical { background: #fef2f2; border-left-color: #dc2626; }
    .recommendation-high { background: #fff7ed; border-left-color: #ea580c; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Email Header Security Analysis</h1>
    <div class="timestamp">Generated: ${new Date(results.timestamp).toLocaleString()}</div>
  </div>

  <div class="summary">
    <h2>Analysis Summary</h2>
    <div class="summary-grid">
      <div class="summary-item">
        <div class="summary-value risk-${results.summary.riskLevel}">${results.summary.riskLevel.toUpperCase()}</div>
        <div class="summary-label">Risk Level</div>
      </div>
      <div class="summary-item">
        <div class="summary-value" style="color: ${results.summary.riskScore > 50 ? '#dc2626' : results.summary.riskScore > 20 ? '#ea580c' : '#16a34a'}">${results.summary.riskScore}</div>
        <div class="summary-label">Risk Score</div>
      </div>
      <div class="summary-item">
        <div class="summary-value auth-${results.summary.authenticationStatus === 'pass' ? 'pass' : results.summary.authenticationStatus === 'fail' ? 'fail' : 'partial'}">${results.summary.authenticationStatus.toUpperCase()}</div>
        <div class="summary-label">Auth Status</div>
      </div>
      <div class="summary-item">
        <div class="summary-value">${results.summary.totalHops}</div>
        <div class="summary-label">Total Hops</div>
      </div>
    </div>
    ${results.summary.totalTransitTime ? `<p style="margin-top: 15px; text-align: center; color: #6b7280;">Total Transit Time: ${results.summary.totalTransitTime}</p>` : ''}
  </div>

  <div class="section">
    <h2>Key Email Headers</h2>
    <table>
      <tr><th>Header</th><th>Value</th></tr>
      ${results.keyHeaders.from ? `<tr><td><strong>From</strong></td><td>${escapeHtml(results.keyHeaders.from)}</td></tr>` : ''}
      ${results.keyHeaders.to ? `<tr><td><strong>To</strong></td><td>${escapeHtml(results.keyHeaders.to)}</td></tr>` : ''}
      ${results.keyHeaders.subject ? `<tr><td><strong>Subject</strong></td><td>${escapeHtml(results.keyHeaders.subject)}</td></tr>` : ''}
      ${results.keyHeaders.date ? `<tr><td><strong>Date</strong></td><td>${escapeHtml(results.keyHeaders.date)}</td></tr>` : ''}
      ${results.keyHeaders.returnPath ? `<tr><td><strong>Return-Path</strong></td><td class="mono">${escapeHtml(results.keyHeaders.returnPath)}</td></tr>` : ''}
      ${results.keyHeaders.replyTo ? `<tr><td><strong>Reply-To</strong></td><td class="mono">${escapeHtml(results.keyHeaders.replyTo)}</td></tr>` : ''}
      ${results.keyHeaders.messageId ? `<tr><td><strong>Message-ID</strong></td><td class="mono" style="word-break: break-all;">${escapeHtml(results.keyHeaders.messageId)}</td></tr>` : ''}
      ${results.keyHeaders.xOriginatingIP ? `<tr><td><strong>X-Originating-IP</strong></td><td class="mono">${escapeHtml(results.keyHeaders.xOriginatingIP)}</td></tr>` : ''}
      ${results.keyHeaders.xMailer ? `<tr><td><strong>X-Mailer</strong></td><td>${escapeHtml(results.keyHeaders.xMailer)}</td></tr>` : ''}
    </table>
  </div>

  <div class="section">
    <h2>Authentication Results</h2>
    <table>
      <tr><th>Check</th><th>Status</th><th>Details</th></tr>
      <tr>
        <td><strong>SPF</strong></td>
        <td class="auth-${results.authentication.spf.status === 'pass' ? 'pass' : results.authentication.spf.status === 'fail' ? 'fail' : 'partial'}">${results.authentication.spf.status.toUpperCase()}</td>
        <td>${escapeHtml(results.authentication.spf.details || '-')}</td>
      </tr>
      <tr>
        <td><strong>DKIM</strong></td>
        <td class="auth-${results.authentication.dkim.status === 'pass' ? 'pass' : results.authentication.dkim.status === 'fail' ? 'fail' : 'partial'}">${results.authentication.dkim.status.toUpperCase()}</td>
        <td>${escapeHtml(results.authentication.dkim.details || '-')}</td>
      </tr>
      <tr>
        <td><strong>DMARC</strong></td>
        <td class="auth-${results.authentication.dmarc.status === 'pass' ? 'pass' : results.authentication.dmarc.status === 'fail' ? 'fail' : 'partial'}">${results.authentication.dmarc.status.toUpperCase()}</td>
        <td>${escapeHtml(results.authentication.dmarc.details || '-')}</td>
      </tr>
      ${results.authentication.arc.status !== 'unknown' ? `
      <tr>
        <td><strong>ARC</strong></td>
        <td class="auth-${results.authentication.arc.status === 'pass' ? 'pass' : 'partial'}">${results.authentication.arc.status.toUpperCase()}</td>
        <td>${results.authentication.arc.seals || 0} seal(s)</td>
      </tr>
      ` : ''}
    </table>
  </div>

  <div class="section">
    <h2>Delivery Path (${results.deliveryPath.totalHops} hops)</h2>
    ${results.deliveryPath.hops && results.deliveryPath.hops.length > 0 ? `
    <table>
      <tr><th>Hop</th><th>Server</th><th>From IP</th><th>Delay</th><th>TLS</th></tr>
      ${results.deliveryPath.hops.map(hop => `
      <tr>
        <td>${hop.hopNumber}</td>
        <td>${escapeHtml(hop.by || '-')}</td>
        <td class="mono">${escapeHtml(hop.fromIP || '-')}</td>
        <td>${hop.delayFormatted || '-'}</td>
        <td>${hop.tls ? '<span style="color:#16a34a">Yes</span>' : '<span style="color:#dc2626">No</span>'}</td>
      </tr>
      `).join('')}
    </table>
    ` : '<p>No delivery path information available.</p>'}
    ${results.deliveryPath.issues && results.deliveryPath.issues.length > 0 ? `
    <h4>Delivery Issues</h4>
    ${results.deliveryPath.issues.map(issue => `
    <div class="finding finding-${issue.severity}">${issue.message}</div>
    `).join('')}
    ` : ''}
  </div>

  ${results.securityAnalysis.findings.length > 0 ? `
  <div class="section">
    <h2>Security Findings (${results.securityAnalysis.totalFindings})</h2>
    ${results.securityAnalysis.findings.map(finding => `
    <div class="finding finding-${finding.severity}">
      <h4 style="margin: 0 0 8px 0;">${finding.severity.toUpperCase()}: ${escapeHtml(finding.title)}</h4>
      <p style="margin: 0; color: #6b7280; font-size: 12px;">Category: ${finding.category}</p>
      <p style="margin: 10px 0 0 0;">${escapeHtml(finding.description)}</p>
    </div>
    `).join('')}
  </div>
  ` : ''}

  ${results.summary.recommendations.length > 0 ? `
  <div class="section">
    <h2>Recommendations</h2>
    ${results.summary.recommendations.map(rec => `
    <div class="recommendation recommendation-${rec.priority}">
      <strong>[${rec.priority.toUpperCase()}]</strong> ${escapeHtml(rec.action)}
    </div>
    `).join('')}
  </div>
  ` : ''}

  <div class="footer">
    <p><strong>ThreatDefender Email Header Analyzer</strong></p>
    <p>eGroup Enabling Technologies | ThreatDefender MSSP/MXDR</p>
    <p style="font-size: 12px; color: #9ca3af;">Report generated on ${new Date().toLocaleString()}</p>
  </div>
</body>
</html>`;

    function escapeHtml(text) {
      if (!text) return '';
      return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Download
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `email-header-analysis-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`space-y-6 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
      {/* Header */}
      <div className={`p-6 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
        <h2 className="text-2xl font-bold mb-2">Email Header Security Analyzer</h2>
        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
          Analyze email headers for security issues, authentication results, delivery path, and potential threats.
          Paste raw email headers below to begin analysis.
        </p>
      </div>

      {/* Input Form */}
      <div className={`p-6 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
        <div className="space-y-4">
          <div>
            <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
              Raw Email Headers
            </label>
            <textarea
              value={rawHeaders}
              onChange={(e) => setRawHeaders(e.target.value)}
              placeholder={`Paste email headers here...

Example:
Received: from mail.example.com (mail.example.com [192.0.2.1])
    by mx.recipient.com with ESMTPS; Thu, 8 Jan 2026 10:30:00 -0500
From: sender@example.com
To: recipient@example.org
Subject: Test Email
Date: Thu, 8 Jan 2026 10:29:55 -0500
Message-ID: <unique-id@example.com>
Authentication-Results: mx.recipient.com; spf=pass; dkim=pass; dmarc=pass`}
              className={`w-full px-4 py-3 rounded-md border font-mono text-sm ${
                darkMode
                  ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
              } focus:outline-none focus:ring-2 focus:ring-purple-500`}
              rows={12}
            />
            <p className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
              Tip: In most email clients, you can view headers via "View Original" or "Show Original" option.
              In Outlook, use File &gt; Properties. In Gmail, click the three dots &gt; Show original.
            </p>
          </div>

          <div className="flex gap-3">
            <button
              onClick={runAnalysis}
              disabled={loading}
              className={`flex-1 py-3 px-6 rounded-md font-semibold transition ${
                loading
                  ? darkMode
                    ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                    : 'bg-gray-300 text-gray-500 cursor-not-allowed'
                  : darkMode
                    ? 'bg-purple-600 text-white hover:bg-purple-500'
                    : 'bg-purple-600 text-white hover:bg-purple-700'
              }`}
            >
              {loading ? 'Analyzing...' : 'Analyze Headers'}
            </button>
            {(rawHeaders || results) && (
              <button
                onClick={clearAnalysis}
                className={`py-3 px-6 rounded-md font-semibold transition ${
                  darkMode
                    ? 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                Clear
              </button>
            )}
          </div>
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
            <h3 className="text-xl font-bold mb-4">Analysis Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className={`text-2xl font-bold ${getRiskLevelColor(results.summary.riskLevel)}`}>
                  {results.summary.riskLevel.toUpperCase()}
                </div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Risk Level</div>
              </div>
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className={`text-2xl font-bold ${results.summary.riskScore > 50 ? 'text-red-500' : results.summary.riskScore > 20 ? 'text-orange-500' : 'text-green-500'}`}>
                  {results.summary.riskScore}
                </div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Risk Score</div>
              </div>
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className={`text-2xl font-bold ${getAuthStatusColor(results.summary.authenticationStatus)}`}>
                  {results.summary.authenticationStatus.toUpperCase()}
                </div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Auth Status</div>
              </div>
              <div className={`p-4 rounded-lg text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                <div className="text-2xl font-bold text-blue-500">{results.summary.totalHops}</div>
                <div className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Total Hops</div>
              </div>
            </div>

            {results.summary.totalTransitTime && (
              <p className={`text-center mt-4 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                Total Transit Time: <span className="font-semibold">{results.summary.totalTransitTime}</span>
              </p>
            )}

            {/* Findings count */}
            {results.securityAnalysis.totalFindings > 0 && (
              <div className="mt-4 flex justify-center gap-4">
                {results.summary.findingsCount.high > 0 && (
                  <span className="px-3 py-1 rounded-full bg-red-900 text-red-200 text-sm">
                    {results.summary.findingsCount.high} High
                  </span>
                )}
                {results.summary.findingsCount.medium > 0 && (
                  <span className="px-3 py-1 rounded-full bg-orange-900 text-orange-200 text-sm">
                    {results.summary.findingsCount.medium} Medium
                  </span>
                )}
                {results.summary.findingsCount.low > 0 && (
                  <span className="px-3 py-1 rounded-full bg-yellow-900 text-yellow-200 text-sm">
                    {results.summary.findingsCount.low} Low
                  </span>
                )}
                {results.summary.findingsCount.info > 0 && (
                  <span className="px-3 py-1 rounded-full bg-blue-900 text-blue-200 text-sm">
                    {results.summary.findingsCount.info} Info
                  </span>
                )}
              </div>
            )}

            {/* Recommendations */}
            {results.summary.recommendations.length > 0 && (
              <div className="mt-6">
                <h4 className="font-semibold mb-3">Recommendations:</h4>
                <div className="space-y-2">
                  {results.summary.recommendations.map((rec, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg border-l-4 ${
                        rec.priority === 'critical'
                          ? 'bg-red-900 border-red-600'
                          : rec.priority === 'high'
                            ? 'bg-orange-900 border-orange-600'
                            : rec.priority === 'medium'
                              ? 'bg-yellow-900 border-yellow-600'
                              : 'bg-blue-900 border-blue-600'
                      }`}
                    >
                      <span className="font-semibold">[{rec.priority.toUpperCase()}]</span> {rec.action}
                    </div>
                  ))}
                </div>
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
                Export as Markdown
              </button>
              <button
                onClick={exportHTML}
                className={`flex-1 py-2 px-4 rounded-md font-semibold transition ${
                  darkMode
                    ? 'bg-purple-700 text-white hover:bg-purple-600'
                    : 'bg-purple-600 text-white hover:bg-purple-700'
                }`}
              >
                Export as HTML
              </button>
            </div>
          </div>

          {/* Detailed Results */}
          <div className="space-y-4">
            {/* Key Headers */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('keyHeaders')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">&#x1F4E7;</span>
                  <div>
                    <h3 className="text-lg font-bold">Key Email Headers</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Important header values
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.keyHeaders ? '\u25BC' : '\u25B6'}</span>
              </button>
              {expandedSections.keyHeaders && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  <div className="space-y-3">
                    {Object.entries(results.keyHeaders).filter(([_, v]) => v).map(([key, value]) => (
                      <div key={key} className={`p-3 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                        <span className={`text-sm font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase())}:
                        </span>
                        <p className="font-mono text-sm break-all mt-1">{value}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Authentication Results */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('authentication')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{getAuthStatusIcon(results.authentication.overallStatus)}</span>
                  <div>
                    <h3 className="text-lg font-bold">Authentication Results</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      SPF: {results.authentication.spf.status} | DKIM: {results.authentication.dkim.status} | DMARC: {results.authentication.dmarc.status}
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.authentication ? '\u25BC' : '\u25B6'}</span>
              </button>
              {expandedSections.authentication && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  <div className="grid gap-4">
                    {/* SPF */}
                    <div className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xl">{getAuthStatusIcon(results.authentication.spf.status)}</span>
                        <span className="font-semibold">SPF (Sender Policy Framework)</span>
                        <span className={`ml-auto ${getAuthStatusColor(results.authentication.spf.status)}`}>
                          {results.authentication.spf.status.toUpperCase()}
                        </span>
                      </div>
                      {results.authentication.spf.details && (
                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {results.authentication.spf.details}
                        </p>
                      )}
                    </div>

                    {/* DKIM */}
                    <div className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xl">{getAuthStatusIcon(results.authentication.dkim.status)}</span>
                        <span className="font-semibold">DKIM (DomainKeys Identified Mail)</span>
                        <span className={`ml-auto ${getAuthStatusColor(results.authentication.dkim.status)}`}>
                          {results.authentication.dkim.status.toUpperCase()}
                        </span>
                      </div>
                      {results.authentication.dkim.details && (
                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {results.authentication.dkim.details}
                        </p>
                      )}
                      {results.authentication.dkim.signatures.length > 0 && (
                        <div className="mt-3 space-y-2">
                          <p className={`text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                            DKIM Signatures ({results.authentication.dkim.signatures.length}):
                          </p>
                          {results.authentication.dkim.signatures.map((sig, idx) => (
                            <div key={idx} className={`text-xs p-2 rounded ${darkMode ? 'bg-gray-600' : 'bg-gray-200'}`}>
                              <span>Domain: <strong>{sig.domain}</strong></span>
                              {sig.selector && <span className="ml-3">Selector: <strong>{sig.selector}</strong></span>}
                              {sig.algorithm && <span className="ml-3">Algorithm: <strong>{sig.algorithm}</strong></span>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* DMARC */}
                    <div className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xl">{getAuthStatusIcon(results.authentication.dmarc.status)}</span>
                        <span className="font-semibold">DMARC (Domain-based Message Authentication)</span>
                        <span className={`ml-auto ${getAuthStatusColor(results.authentication.dmarc.status)}`}>
                          {results.authentication.dmarc.status.toUpperCase()}
                        </span>
                      </div>
                      {results.authentication.dmarc.details && (
                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {results.authentication.dmarc.details}
                        </p>
                      )}
                    </div>

                    {/* ARC (if present) */}
                    {results.authentication.arc.status !== 'unknown' && (
                      <div className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-xl">{getAuthStatusIcon(results.authentication.arc.status)}</span>
                          <span className="font-semibold">ARC (Authenticated Received Chain)</span>
                          <span className={`ml-auto ${getAuthStatusColor(results.authentication.arc.status)}`}>
                            {results.authentication.arc.status.toUpperCase()}
                          </span>
                        </div>
                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {results.authentication.arc.seals} seal(s), {results.authentication.arc.signatures} signature(s)
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Raw Authentication-Results */}
                  {results.authentication.authenticationResultsRaw && (
                    <div className="mt-4">
                      <p className={`text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        Raw Authentication-Results Header:
                      </p>
                      <div className={`p-3 rounded-md font-mono text-xs ${darkMode ? 'bg-gray-700' : 'bg-gray-100'} break-all`}>
                        {results.authentication.authenticationResultsRaw}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Delivery Path */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('deliveryPath')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">&#x1F4E8;</span>
                  <div>
                    <h3 className="text-lg font-bold">Delivery Path</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      {results.deliveryPath.totalHops} hop(s) | Transit: {results.deliveryPath.totalTransitFormatted || 'Unknown'}
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.deliveryPath ? '\u25BC' : '\u25B6'}</span>
              </button>
              {expandedSections.deliveryPath && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  {results.deliveryPath.hops && results.deliveryPath.hops.length > 0 ? (
                    <div className="space-y-3">
                      {results.deliveryPath.hops.map((hop, idx) => (
                        <div key={idx} className={`p-4 rounded-md ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-semibold">Hop {hop.hopNumber}</span>
                            <div className="flex items-center gap-2">
                              {hop.delayFormatted && (
                                <span className={`text-xs px-2 py-1 rounded ${
                                  hop.delayFromPrevious > 300000
                                    ? 'bg-red-900 text-red-200'
                                    : darkMode ? 'bg-gray-600' : 'bg-gray-200'
                                }`}>
                                  +{hop.delayFormatted}
                                </span>
                              )}
                              <span className={`text-xs px-2 py-1 rounded ${
                                hop.tls
                                  ? 'bg-green-900 text-green-200'
                                  : 'bg-red-900 text-red-200'
                              }`}>
                                {hop.tls ? 'TLS' : 'No TLS'}
                              </span>
                            </div>
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                            {hop.from && (
                              <div>
                                <span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>From: </span>
                                <span className="font-mono">{hop.from}</span>
                              </div>
                            )}
                            {hop.fromIP && (
                              <div>
                                <span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>IP: </span>
                                <span className="font-mono">{hop.fromIP}</span>
                              </div>
                            )}
                            {hop.by && (
                              <div>
                                <span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>By: </span>
                                <span className="font-mono">{hop.by}</span>
                              </div>
                            )}
                            {hop.with && (
                              <div>
                                <span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>Protocol: </span>
                                <span>{hop.with}</span>
                              </div>
                            )}
                          </div>
                          {hop.timestampRaw && (
                            <p className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                              {hop.timestampRaw}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
                      No delivery path information available.
                    </p>
                  )}

                  {/* Delivery Issues */}
                  {results.deliveryPath.issues && results.deliveryPath.issues.length > 0 && (
                    <div className="mt-4">
                      <h4 className="font-semibold mb-2">Delivery Issues:</h4>
                      <div className="space-y-2">
                        {results.deliveryPath.issues.map((issue, idx) => (
                          <div
                            key={idx}
                            className={`p-3 rounded-lg border-l-4 ${
                              issue.severity === 'high'
                                ? 'bg-red-900 border-red-600'
                                : issue.severity === 'medium'
                                  ? 'bg-orange-900 border-orange-600'
                                  : 'bg-yellow-900 border-yellow-600'
                            }`}
                          >
                            {issue.message}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Security Findings */}
            {results.securityAnalysis.totalFindings > 0 && (
              <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
                <button
                  onClick={() => toggleSection('securityFindings')}
                  className={`w-full p-4 text-left flex items-center justify-between ${
                    darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                  } transition`}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">&#x26A0;&#xFE0F;</span>
                    <div>
                      <h3 className="text-lg font-bold">Security Findings</h3>
                      <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                        {results.securityAnalysis.totalFindings} finding(s) detected
                      </p>
                    </div>
                  </div>
                  <span className="text-2xl">{expandedSections.securityFindings ? '\u25BC' : '\u25B6'}</span>
                </button>
                {expandedSections.securityFindings && (
                  <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                    <div className="space-y-3">
                      {results.securityAnalysis.findings.map((finding, idx) => (
                        <div
                          key={idx}
                          className={`p-4 rounded-lg border-l-4 ${
                            finding.severity === 'high'
                              ? 'bg-red-900 border-red-500'
                              : finding.severity === 'medium'
                                ? 'bg-orange-900 border-orange-500'
                                : finding.severity === 'low'
                                  ? 'bg-yellow-900 border-yellow-500'
                                  : 'bg-blue-900 border-blue-500'
                          }`}
                        >
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-lg">{getSeverityIcon(finding.severity)}</span>
                            <span className="font-bold">{finding.title}</span>
                            <span className={`ml-auto text-xs px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                              {finding.category}
                            </span>
                          </div>
                          <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-200'}`}>
                            {finding.description}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* All Headers */}
            <div className={`rounded-lg overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-md`}>
              <button
                onClick={() => toggleSection('allHeaders')}
                className={`w-full p-4 text-left flex items-center justify-between ${
                  darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                } transition`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">&#x1F4CB;</span>
                  <div>
                    <h3 className="text-lg font-bold">All Parsed Headers</h3>
                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      {Object.keys(results.allHeaders).length} unique headers
                    </p>
                  </div>
                </div>
                <span className="text-2xl">{expandedSections.allHeaders ? '\u25BC' : '\u25B6'}</span>
              </button>
              {expandedSections.allHeaders && (
                <div className={`p-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  <div className="space-y-2">
                    {Object.entries(results.allHeaders)
                      .filter(([key]) => !['received', 'dkim-signature', 'arc-seal', 'arc-message-signature', 'arc-authentication-results'].includes(key))
                      .map(([key, value]) => (
                        <div key={key} className={`p-2 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                          <span className={`text-sm font-semibold ${darkMode ? 'text-purple-400' : 'text-purple-600'}`}>
                            {key}:
                          </span>
                          <span className="ml-2 text-sm font-mono break-all">
                            {typeof value === 'string' ? value : JSON.stringify(value)}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
