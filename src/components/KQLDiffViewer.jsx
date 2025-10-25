import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';

export default function KQLDiffViewer({ darkMode }) {
  const [originalQuery, setOriginalQuery] = useState('');
  const [updatedQuery, setUpdatedQuery] = useState('');
  const [showDiff, setShowDiff] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [syntaxErrors, setSyntaxErrors] = useState({ original: [], updated: [] });
  const [fpAnalysis, setFpAnalysis] = useState(null);
  const [isFpAnalyzing, setIsFpAnalyzing] = useState(false);

  // KQL Syntax Validator
  const validateKQLSyntax = (query) => {
    const errors = [];
    const lines = query.split('\n');
    
    // Check for common syntax issues
    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();
      
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('//')) return;
      
      // Check for unmatched parentheses
      const openParens = (line.match(/\(/g) || []).length;
      const closeParens = (line.match(/\)/g) || []).length;
      if (openParens !== closeParens) {
        errors.push({ line: lineNum, message: 'Unmatched parentheses', severity: 'error' });
      }
      
      // Check for missing pipe before operators
      if (trimmed.match(/^(where|project|extend|summarize|join|union|order|top|take|limit)/i) && idx > 0) {
        const prevLine = lines[idx - 1].trim();
        if (prevLine && !prevLine.endsWith('|') && !prevLine.startsWith('//')) {
          errors.push({ line: lineNum, message: 'Missing pipe (|) before operator', severity: 'error' });
        }
      }
      
      // Check for common typos
      if (trimmed.match(/\bwheer\b|\bprojetc\b|\bsummariz\b/i)) {
        errors.push({ line: lineNum, message: 'Possible typo in operator', severity: 'warning' });
      }
      
      // Check for ago() without time unit
      if (trimmed.match(/ago\(\s*\d+\s*\)/)) {
        errors.push({ line: lineNum, message: 'ago() missing time unit (d, h, m, s)', severity: 'error' });
      }
      
      // Check for unquoted strings after ==
      if (trimmed.match(/==\s*[a-zA-Z][a-zA-Z0-9]*\s*($|[^\w])/)) {
        errors.push({ line: lineNum, message: 'String values should be quoted', severity: 'warning' });
      }
      
      // Check for expensive operations
      if (trimmed.match(/\bjoin\b|\bunion\b/i)) {
        errors.push({ line: lineNum, message: 'Expensive operation detected (join/union)', severity: 'info' });
      }
    });
    
    // Check overall structure
    if (!query.trim()) {
      errors.push({ line: 0, message: 'Query is empty', severity: 'error' });
    }
    
    if (!query.match(/^\w+/)) {
      errors.push({ line: 1, message: 'Query should start with a table name', severity: 'warning' });
    }
    
    return errors;
  };

  // Character-level diff for modified lines
  const getCharDiff = (str1, str2) => {
    const result1 = [];
    const result2 = [];
    let i = 0;
    let j = 0;
    
    while (i < str1.length || j < str2.length) {
      if (i < str1.length && j < str2.length && str1[i] === str2[j]) {
        result1.push({ char: str1[i], changed: false });
        result2.push({ char: str2[j], changed: false });
        i++;
        j++;
      } else {
        let found = false;
        
        // Look ahead to find matching sequence
        for (let k = 1; k <= Math.min(20, str1.length - i, str2.length - j); k++) {
          if (str1.substring(i, i + k) === str2.substring(j, j + k)) {
            // Mark differences before the match
            while (i < str1.length && str1[i] !== str2[j]) {
              result1.push({ char: str1[i], changed: true });
              i++;
            }
            while (j < str2.length && str2[j] !== str1[i - (i > 0 ? 1 : 0)]) {
              result2.push({ char: str2[j], changed: true });
              j++;
            }
            found = true;
            break;
          }
        }
        
        if (!found) {
          if (i < str1.length) {
            result1.push({ char: str1[i], changed: true });
            i++;
          }
          if (j < str2.length) {
            result2.push({ char: str2[j], changed: true });
            j++;
          }
        }
      }
    }
    
    return { original: result1, updated: result2 };
  };

  // Simple line-based diff algorithm
  const computeDiff = (original, updated) => {
    const originalLines = original.split('\n');
    const updatedLines = updated.split('\n');
    const maxLength = Math.max(originalLines.length, updatedLines.length);
    
    const diff = [];
    for (let i = 0; i < maxLength; i++) {
      const origLine = originalLines[i] || '';
      const updLine = updatedLines[i] || '';
      
      if (origLine === updLine) {
        diff.push({ type: 'unchanged', original: origLine, updated: updLine, lineNum: i + 1 });
      } else if (!origLine && updLine) {
        diff.push({ type: 'added', original: '', updated: updLine, lineNum: i + 1 });
      } else if (origLine && !updLine) {
        diff.push({ type: 'removed', original: origLine, updated: '', lineNum: i + 1 });
      } else {
        const charDiff = getCharDiff(origLine, updLine);
        diff.push({ 
          type: 'modified', 
          original: origLine, 
          updated: updLine, 
          lineNum: i + 1,
          charDiff 
        });
      }
    }
    return diff;
  };

  // Parse AI response into structured sections
  const parseAIResponse = (text) => {
    const sections = [];
    const lines = text.split('\n');
    let currentSection = null;
    
    for (const line of lines) {
      // Detect section headers
      if (line.match(/^#{1,3}\s+(.+)/)) {
        if (currentSection) sections.push(currentSection);
        const title = line.replace(/^#{1,3}\s+/, '').trim();
        const type = detectSectionType(title);
        currentSection = { title, content: '', type };
      } else if (line.match(/^\d+\.\s+(.+)/) || line.match(/^[-*]\s+(.+)/)) {
        // Numbered or bullet list item
        if (!currentSection) {
          currentSection = { title: 'Overview', content: '', type: 'info' };
        }
        currentSection.content += line + '\n';
      } else if (line.trim()) {
        if (!currentSection) {
          currentSection = { title: 'Overview', content: '', type: 'info' };
        }
        currentSection.content += line + '\n';
      }
    }
    
    if (currentSection) sections.push(currentSection);
    return sections.length > 0 ? sections : [{ title: 'Analysis', content: text, type: 'info' }];
  };

  const detectSectionType = (title) => {
    const lower = title.toLowerCase();
    if (lower.includes('issue') || lower.includes('risk') || lower.includes('concern') || lower.includes('problem')) {
      return 'warning';
    }
    if (lower.includes('improvement') || lower.includes('benefit') || lower.includes('positive') || lower.includes('enhancement')) {
      return 'success';
    }
    if (lower.includes('impact') || lower.includes('change') || lower.includes('overview')) {
      return 'info';
    }
    return 'neutral';
  };

  const getSectionStyle = (type) => {
    const base = darkMode ? 'bg-gray-800' : '';
    switch (type) {
      case 'warning':
        return darkMode 
          ? 'bg-yellow-900 bg-opacity-30 border-yellow-500 border-l-4' 
          : 'bg-yellow-50 border-yellow-300 border-l-4';
      case 'success':
        return darkMode 
          ? 'bg-green-900 bg-opacity-30 border-green-500 border-l-4' 
          : 'bg-green-50 border-green-300 border-l-4';
      case 'info':
        return darkMode 
          ? 'bg-blue-900 bg-opacity-30 border-blue-500 border-l-4' 
          : 'bg-blue-50 border-blue-300 border-l-4';
      default:
        return darkMode 
          ? 'bg-gray-800 border-gray-600 border-l-4' 
          : 'bg-gray-50 border-gray-300 border-l-4';
    }
  };

  const getSectionIcon = (type) => {
    switch (type) {
      case 'warning':
        return '⚠️';
      case 'success':
        return '✅';
      case 'info':
        return 'ℹ️';
      default:
        return '📝';
    }
  };

  const generateAIAnalysis = async () => {
    setIsAnalyzing(true);
    setAiAnalysis(null);
    
    try {
      const functionUrl = 'https://threatdefender-functions-befyasdqduhsa8at.eastus-01.azurewebsites.net/api/kqlanalyzer';
      
      const response = await fetch(functionUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          originalQuery,
          updatedQuery
        })
      });

      if (!response.ok) {
        throw new Error(`Worker request failed: ${response.status}`);
      }

      const data = await response.json();
      const analysis = data.content[0].text;
      const parsedSections = parseAIResponse(analysis);
      setAiAnalysis(parsedSections);
    } catch (error) {
      console.error("Error generating AI analysis:", error);
      setAiAnalysis([{ title: 'Error', content: 'Failed to generate analysis. Please try again.', type: 'warning' }]);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const generateFPAnalysis = async () => {
    setIsFpAnalyzing(true);
    setFpAnalysis(null);
    
    try {
      const functionUrl = 'https://threatdefender-functions-befyasdqduhsa8at.eastus-01.azurewebsites.net/api/kqlanalyzer';
      
      const response = await fetch(functionUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          originalQuery,
          updatedQuery
        })
      });

      if (!response.ok) {
        throw new Error(`Worker request failed: ${response.status}`);
      }

      const data = await response.json();
      
      // Second call for FP analysis
      const fpResponse = await fetch(functionUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          originalQuery: `Analyze this KQL query change for false positive risk:\n\nORIGINAL:\n${originalQuery}\n\nUPDATED:\n${updatedQuery}\n\nProvide:\n1. False Positive Risk Level (Low/Medium/High)\n2. Specific conditions that might trigger false positives\n3. Recommendations to reduce false positives\n4. Test cases to validate the changes`,
          updatedQuery: "Analysis request"
        })
      });

      const fpData = await fpResponse.json();
      const fpText = fpData.content[0].text;
      setFpAnalysis(fpText);
    } catch (error) {
      console.error("Error generating FP analysis:", error);
      setFpAnalysis("Failed to generate false positive analysis. Please try again.");
    } finally {
      setIsFpAnalyzing(false);
    }
  };

  const exportReport = () => {
    const diffSummary = diff.reduce((acc, line) => {
      if (line.type === 'added') acc.added++;
      if (line.type === 'removed') acc.removed++;
      if (line.type === 'modified') acc.modified++;
      return acc;
    }, { added: 0, removed: 0, modified: 0 });

    let reportContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>KQL Query Comparison Report</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 40px auto; padding: 20px; }
    h1 { color: #1e40af; border-bottom: 3px solid #1e40af; padding-bottom: 10px; }
    h2 { color: #374151; margin-top: 30px; }
    .metadata { background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0; }
    .summary { display: flex; gap: 20px; margin: 20px 0; }
    .summary-item { background: white; border: 2px solid #e5e7eb; padding: 15px; border-radius: 8px; flex: 1; text-align: center; }
    .summary-item.added { border-color: #10b981; }
    .summary-item.removed { border-color: #ef4444; }
    .summary-item.modified { border-color: #f59e0b; }
    .query-section { margin: 20px 0; }
    .query-box { background: #1f2937; color: #f9fafb; padding: 20px; border-radius: 8px; overflow-x: auto; }
    pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; }
    .analysis-section { background: #eff6ff; border-left: 4px solid #3b82f6; padding: 20px; margin: 20px 0; border-radius: 4px; }
    .fp-section { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 20px; margin: 20px 0; border-radius: 4px; }
    .error-section { background: #fee2e2; border-left: 4px solid #ef4444; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .error-list { margin: 10px 0; }
    .error-item { margin: 5px 0; padding: 5px; background: white; border-radius: 4px; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; color: #6b7280; font-size: 14px; }
  </style>
</head>
<body>
  <h1>🛡️ ThreatDefender - KQL Query Comparison Report</h1>
  
  <div class="metadata">
    <p><strong>Report Generated:</strong> ${new Date().toLocaleString()}</p>
    <p><strong>Analyst:</strong> ${navigator.userAgent.includes('Windows') ? 'ThreatHunter Team' : 'Security Analyst'}</p>
  </div>

  <h2>Change Summary</h2>
  <div class="summary">
    <div class="summary-item added">
      <h3 style="margin: 0; color: #10b981;">${diffSummary.added}</h3>
      <p style="margin: 5px 0 0 0;">Lines Added</p>
    </div>
    <div class="summary-item removed">
      <h3 style="margin: 0; color: #ef4444;">${diffSummary.removed}</h3>
      <p style="margin: 5px 0 0 0;">Lines Removed</p>
    </div>
    <div class="summary-item modified">
      <h3 style="margin: 0; color: #f59e0b;">${diffSummary.modified}</h3>
      <p style="margin: 5px 0 0 0;">Lines Modified</p>
    </div>
  </div>`;

    // Add syntax validation results
    if (syntaxErrors.original.length > 0 || syntaxErrors.updated.length > 0) {
      reportContent += `<h2>Syntax Validation</h2>`;
      
      if (syntaxErrors.original.length > 0) {
        reportContent += `<div class="error-section">
          <h3>Original Query Issues (${syntaxErrors.original.length})</h3>
          <div class="error-list">`;
        syntaxErrors.original.forEach(err => {
          reportContent += `<div class="error-item">Line ${err.line}: ${err.message} [${err.severity}]</div>`;
        });
        reportContent += `</div></div>`;
      }
      
      if (syntaxErrors.updated.length > 0) {
        reportContent += `<div class="error-section">
          <h3>Updated Query Issues (${syntaxErrors.updated.length})</h3>
          <div class="error-list">`;
        syntaxErrors.updated.forEach(err => {
          reportContent += `<div class="error-item">Line ${err.line}: ${err.message} [${err.severity}]</div>`;
        });
        reportContent += `</div></div>`;
      }
    }

    // Add AI Analysis
    if (aiAnalysis) {
      reportContent += `<h2>AI Analysis</h2>`;
      aiAnalysis.forEach(section => {
        reportContent += `<div class="analysis-section">
          <h3>${section.title}</h3>
          <div>${section.content.replace(/\n/g, '<br>')}</div>
        </div>`;
      });
    }

    // Add FP Analysis
    if (fpAnalysis) {
      reportContent += `<h2>False Positive Analysis</h2>
      <div class="fp-section">
        <div>${fpAnalysis.replace(/\n/g, '<br>')}</div>
      </div>`;
    }

    // Add queries
    reportContent += `
  <h2>Original Query</h2>
  <div class="query-section">
    <div class="query-box">
      <pre>${originalQuery}</pre>
    </div>
  </div>

  <h2>Updated Query</h2>
  <div class="query-section">
    <div class="query-box">
      <pre>${updatedQuery}</pre>
    </div>
  </div>

  <div class="footer">
    <p>Generated by ThreatDefender KQL Diff App | eGroup Enabling Technologies</p>
  </div>
</body>
</html>`;

    // Create and download
    const blob = new Blob([reportContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kql-comparison-report-${Date.now()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCompare = () => {
    if (originalQuery.trim() && updatedQuery.trim()) {
      // Run syntax validation
      const originalErrors = validateKQLSyntax(originalQuery);
      const updatedErrors = validateKQLSyntax(updatedQuery);
      setSyntaxErrors({ original: originalErrors, updated: updatedErrors });
      
      setShowDiff(true);
      setAiAnalysis(null);
      setFpAnalysis(null);
    }
  };

  const handleReset = () => {
    setOriginalQuery('');
    setUpdatedQuery('');
    setShowDiff(false);
    setAiAnalysis(null);
    setFpAnalysis(null);
    setSyntaxErrors({ original: [], updated: [] });
  };

  const diff = showDiff ? computeDiff(originalQuery, updatedQuery) : [];

  const getLineStyle = (type) => {
    if (darkMode) {
      switch (type) {
        case 'added':
          return 'bg-green-900 bg-opacity-30 border-l-4 border-green-500';
        case 'removed':
          return 'bg-red-900 bg-opacity-30 border-l-4 border-red-500';
        case 'modified':
          return 'bg-yellow-900 bg-opacity-30 border-l-4 border-yellow-500';
        default:
          return 'bg-gray-800';
      }
    } else {
      switch (type) {
        case 'added':
          return 'bg-green-100 border-l-4 border-green-500';
        case 'removed':
          return 'bg-red-100 border-l-4 border-red-500';
        case 'modified':
          return 'bg-yellow-100 border-l-4 border-yellow-500';
        default:
          return 'bg-white';
      }
    }
  };

  return (
    <div className={`min-h-screen p-6 ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              ThreatDefender - KQL Diff App
            </h1>
            <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
              Compare Sentinel Analytic Rule changes
            </p>
          </div>
        </div>

        {!showDiff ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
              <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                Original KQL Query
              </label>
              <textarea
                value={originalQuery}
                onChange={(e) => setOriginalQuery(e.target.value)}
                className={`w-full h-96 p-3 border rounded-md font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  darkMode 
                    ? 'bg-gray-900 border-gray-700 text-gray-300' 
                    : 'bg-white border-gray-300 text-gray-900'
                }`}
                placeholder="Paste your original Sentinel Analytic Rule query here..."
              />
            </div>

            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
              <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                Updated KQL Query
              </label>
              <textarea
                value={updatedQuery}
                onChange={(e) => setUpdatedQuery(e.target.value)}
                className={`w-full h-96 p-3 border rounded-md font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  darkMode 
                    ? 'bg-gray-900 border-gray-700 text-gray-300' 
                    : 'bg-white border-gray-300 text-gray-900'
                }`}
                placeholder="Paste your updated query here..."
              />
            </div>
          </div>
        ) : (
          <>
            {(syntaxErrors.original.length > 0 || syntaxErrors.updated.length > 0) && (
              <div className="mb-6">
                <h2 className={`text-2xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  Syntax Validation
                </h2>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {syntaxErrors.original.length > 0 && (
                    <div className={`rounded-lg p-4 ${darkMode ? 'bg-red-900 bg-opacity-30 border-red-500' : 'bg-red-50 border-red-300'} border-l-4`}>
                      <h3 className={`font-semibold mb-2 ${darkMode ? 'text-red-300' : 'text-red-800'}`}>
                        Original Query Issues ({syntaxErrors.original.length})
                      </h3>
                      <div className="space-y-2">
                        {syntaxErrors.original.map((err, idx) => (
                          <div key={idx} className={`text-sm ${darkMode ? 'text-red-200' : 'text-red-700'}`}>
                            <span className="font-mono">Line {err.line}:</span> {err.message}
                            <span className={`ml-2 px-2 py-1 rounded text-xs ${
                              err.severity === 'error' ? 'bg-red-600 text-white' :
                              err.severity === 'warning' ? 'bg-yellow-600 text-white' :
                              'bg-blue-600 text-white'
                            }`}>
                              {err.severity}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {syntaxErrors.updated.length > 0 && (
                    <div className={`rounded-lg p-4 ${darkMode ? 'bg-red-900 bg-opacity-30 border-red-500' : 'bg-red-50 border-red-300'} border-l-4`}>
                      <h3 className={`font-semibold mb-2 ${darkMode ? 'text-red-300' : 'text-red-800'}`}>
                        Updated Query Issues ({syntaxErrors.updated.length})
                      </h3>
                      <div className="space-y-2">
                        {syntaxErrors.updated.map((err, idx) => (
                          <div key={idx} className={`text-sm ${darkMode ? 'text-red-200' : 'text-red-700'}`}>
                            <span className="font-mono">Line {err.line}:</span> {err.message}
                            <span className={`ml-2 px-2 py-1 rounded text-xs ${
                              err.severity === 'error' ? 'bg-red-600 text-white' :
                              err.severity === 'warning' ? 'bg-yellow-600 text-white' :
                              'bg-blue-600 text-white'
                            }`}>
                              {err.severity}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {aiAnalysis && (
              <div className="mb-6 space-y-4">
                <h2 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  AI Analysis
                </h2>
                {aiAnalysis.map((section, idx) => (
                  <div key={idx} className={`rounded-lg p-6 ${getSectionStyle(section.type)}`}>
                    <h3 className={`text-lg font-semibold mb-3 flex items-center gap-2 ${
                      darkMode ? 'text-gray-100' : 'text-gray-900'
                    }`}>
                      <span>{getSectionIcon(section.type)}</span>
                      {section.title}
                    </h3>
                    <div className={`prose prose-sm max-w-none ${
                      darkMode ? 'text-gray-300 prose-invert' : 'text-gray-800'
                    }`}>
                      <ReactMarkdown>{section.content}</ReactMarkdown>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {fpAnalysis && (
              <div className="mb-6">
                <h2 className={`text-2xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  False Positive Analysis
                </h2>
                <div className={`rounded-lg p-6 ${
                  darkMode ? 'bg-yellow-900 bg-opacity-30 border-yellow-500' : 'bg-yellow-50 border-yellow-300'
                } border-l-4`}>
                  <div className={`prose prose-sm max-w-none ${
                    darkMode ? 'text-gray-300 prose-invert' : 'text-gray-800'
                  }`}>
                    <ReactMarkdown>{fpAnalysis}</ReactMarkdown>
                  </div>
                </div>
              </div>
            )}

            <div className={`rounded-lg shadow overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
              <div className={`p-4 border-b ${
                darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-100 border-gray-200'
              }`}>
                <div className="flex items-center gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-green-100 border-l-4 border-green-500"></div>
                    <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Added</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-red-100 border-l-4 border-red-500"></div>
                    <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Removed</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-yellow-100 border-l-4 border-yellow-500"></div>
                    <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Modified</span>
                  </div>
                </div>
              </div>

              <div className={`grid grid-cols-2 divide-x ${
                darkMode ? 'divide-gray-700' : 'divide-gray-200'
              }`}>
                <div className="p-4">
                  <h3 className={`text-sm font-semibold mb-3 ${
                    darkMode ? 'text-gray-300' : 'text-gray-700'
                  }`}>Original</h3>
                  <div className="space-y-1">
                    {diff.map((line, idx) => (
                      <div
                        key={idx}
                        className={`p-2 ${getLineStyle(line.type)} font-mono text-xs whitespace-pre-wrap break-all ${
                          darkMode ? 'text-gray-300' : 'text-gray-900'
                        }`}
                      >
                        <span className={`mr-3 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                          {line.lineNum}
                        </span>
                        {line.type === 'modified' && line.charDiff ? (
                          <span>
                            {line.charDiff.original.map((item, i) => (
                              <span
                                key={i}
                                className={item.changed ? (darkMode ? 'bg-red-500' : 'bg-red-300') : ''}
                              >
                                {item.char}
                              </span>
                            ))}
                          </span>
                        ) : (
                          <span>{line.original || ' '}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4">
                  <h3 className={`text-sm font-semibold mb-3 ${
                    darkMode ? 'text-gray-300' : 'text-gray-700'
                  }`}>Updated</h3>
                  <div className="space-y-1">
                    {diff.map((line, idx) => (
                      <div
                        key={idx}
                        className={`p-2 ${getLineStyle(line.type)} font-mono text-xs whitespace-pre-wrap break-all ${
                          darkMode ? 'text-gray-300' : 'text-gray-900'
                        }`}
                      >
                        <span className={`mr-3 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                          {line.lineNum}
                        </span>
                        {line.type === 'modified' && line.charDiff ? (
                          <span>
                            {line.charDiff.updated.map((item, i) => (
                              <span
                                key={i}
                                className={item.changed ? (darkMode ? 'bg-green-500' : 'bg-green-300') : ''}
                              >
                                {item.char}
                              </span>
                            ))}
                          </span>
                        ) : (
                          <span>{line.updated || ' '}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        <div className="mt-6 flex gap-4 flex-wrap">
          {!showDiff ? (
            <button
              onClick={handleCompare}
              disabled={!originalQuery.trim() || !updatedQuery.trim()}
              className="px-6 py-3 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition"
            >
              Compare Queries
            </button>
          ) : (
            <>
              <button
                onClick={() => setShowDiff(false)}
                className="px-6 py-3 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 transition"
              >
                Back to Edit
              </button>
              <button
                onClick={handleReset}
                className="px-6 py-3 bg-gray-600 text-white rounded-md font-semibold hover:bg-gray-700 transition"
              >
                Start Over
              </button>
              {!aiAnalysis && (
                <button
                  onClick={generateAIAnalysis}
                  disabled={isAnalyzing}
                  className="px-6 py-3 bg-purple-600 text-white rounded-md font-semibold hover:bg-purple-700 disabled:bg-purple-300 transition"
                >
                  {isAnalyzing ? 'Analyzing...' : 'Generate AI Summary'}
                </button>
              )}
              {!fpAnalysis && (
                <button
                  onClick={generateFPAnalysis}
                  disabled={isFpAnalyzing}
                  className="px-6 py-3 bg-yellow-600 text-white rounded-md font-semibold hover:bg-yellow-700 disabled:bg-yellow-300 transition"
                >
                  {isFpAnalyzing ? 'Analyzing...' : '🎯 False Positive Check'}
                </button>
              )}
              <button
                onClick={exportReport}
                className="px-6 py-3 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 transition"
              >
                📄 Export Report
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
