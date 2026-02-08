import React, { useState, useEffect, useRef, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import Editor from '@monaco-editor/react';
import { DiffEditor } from '@monaco-editor/react';

export default function KQLDiffViewer({ darkMode }) {
  const [originalQuery, setOriginalQuery] = useState('');
  const [updatedQuery, setUpdatedQuery] = useState('');
  const [showDiff, setShowDiff] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [syntaxErrors, setSyntaxErrors] = useState({ original: [], updated: [] });
  const [fpAnalysis, setFpAnalysis] = useState(null);
  const [isFpAnalyzing, setIsFpAnalyzing] = useState(false);

  // Phase 1 & 2: New state for advanced features
  const [ignoreWhitespace, setIgnoreWhitespace] = useState(false);
  const [ignoreCase, setIgnoreCase] = useState(false);
  const [viewMode, setViewMode] = useState('side-by-side'); // 'side-by-side' or 'inline'
  const [shareUrl, setShareUrl] = useState('');

  // Monaco editor refs for diagnostics
  const originalEditorRef = useRef(null);
  const updatedEditorRef = useRef(null);
  const diffEditorRef = useRef(null);

  // Debounce timer
  const debounceTimerRef = useRef(null);

  // Phase 1: Load from URL parameters on mount (shareable state)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has('original') && params.has('updated')) {
      try {
        const original = decodeURIComponent(params.get('original'));
        const updated = decodeURIComponent(params.get('updated'));
        setOriginalQuery(original);
        setUpdatedQuery(updated);

        // Auto-load settings from URL
        if (params.has('whitespace')) setIgnoreWhitespace(params.get('whitespace') === 'true');
        if (params.has('case')) setIgnoreCase(params.get('case') === 'true');
        if (params.has('view')) setViewMode(params.get('view'));
      } catch (error) {
        console.error('Error parsing URL parameters:', error);
      }
    }

    // Load preferences from localStorage
    const savedPrefs = localStorage.getItem('kql-diff-preferences');
    if (savedPrefs) {
      try {
        const prefs = JSON.parse(savedPrefs);
        if (prefs.ignoreWhitespace !== undefined) setIgnoreWhitespace(prefs.ignoreWhitespace);
        if (prefs.ignoreCase !== undefined) setIgnoreCase(prefs.ignoreCase);
        if (prefs.viewMode) setViewMode(prefs.viewMode);
      } catch (error) {
        console.error('Error loading preferences:', error);
      }
    }
  }, []);

  // Phase 2: Save preferences to localStorage when they change
  useEffect(() => {
    const prefs = { ignoreWhitespace, ignoreCase, viewMode };
    localStorage.setItem('kql-diff-preferences', JSON.stringify(prefs));
  }, [ignoreWhitespace, ignoreCase, viewMode]);

  // Phase 2: Global keyboard shortcuts
  useEffect(() => {
    const handleKeyboard = (e) => {
      // Ctrl+Enter or Cmd+Enter: Compare queries
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !showDiff) {
        e.preventDefault();
        if (originalQuery.trim() && updatedQuery.trim()) {
          handleCompare();
        }
      }
      // Escape: Back to edit
      if (e.key === 'Escape' && showDiff) {
        e.preventDefault();
        setShowDiff(false);
      }
    };

    window.addEventListener('keydown', handleKeyboard);
    return () => window.removeEventListener('keydown', handleKeyboard);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showDiff, originalQuery, updatedQuery]);

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

  // Phase 1: Apply syntax errors as Monaco markers (inline diagnostics)
  const applyMonacoMarkers = useCallback((editor, errors, monaco) => {
    if (!editor || !monaco) return;

    const model = editor.getModel();
    if (!model) return;

    const markers = errors.map(err => ({
      severity: err.severity === 'error' ? monaco.MarkerSeverity.Error :
                err.severity === 'warning' ? monaco.MarkerSeverity.Warning :
                monaco.MarkerSeverity.Info,
      message: err.message,
      startLineNumber: err.line || 1,
      startColumn: 1,
      endLineNumber: err.line || 1,
      endColumn: model.getLineMaxColumn(err.line || 1)
    }));

    monaco.editor.setModelMarkers(model, 'kql-validator', markers);
  }, []);

  // Phase 1: Generate shareable URL
  const generateShareUrl = useCallback(() => {
    const params = new URLSearchParams();
    params.set('original', encodeURIComponent(originalQuery));
    params.set('updated', encodeURIComponent(updatedQuery));
    params.set('whitespace', ignoreWhitespace.toString());
    params.set('case', ignoreCase.toString());
    params.set('view', viewMode);

    const url = `${window.location.origin}${window.location.pathname}?${params.toString()}`;
    setShareUrl(url);

    // Copy to clipboard
    navigator.clipboard.writeText(url).then(() => {
      alert('Share link copied to clipboard! 🔗');
    }).catch(() => {
      // Fallback: show URL in prompt
      prompt('Copy this shareable link:', url);
    });
  }, [originalQuery, updatedQuery, ignoreWhitespace, ignoreCase, viewMode]);

  // Phase 2: Markdown export function - moved after diff computation
  const exportMarkdownFn = (diffData) => {
    const diffSummary = diffData.reduce((acc, line) => {
      if (line.type === 'added') acc.added++;
      if (line.type === 'removed') acc.removed++;
      if (line.type === 'modified') acc.modified++;
      return acc;
    }, { added: 0, removed: 0, modified: 0 });

    let markdown = `# KQL Query Comparison Report\n\n`;
    markdown += `**Generated:** ${new Date().toLocaleString()}\n\n`;
    markdown += `---\n\n`;

    // Summary
    markdown += `## Change Summary\n\n`;
    markdown += `- ✅ **Added Lines:** ${diffSummary.added}\n`;
    markdown += `- ❌ **Removed Lines:** ${diffSummary.removed}\n`;
    markdown += `- 🔄 **Modified Lines:** ${diffSummary.modified}\n\n`;

    // Syntax errors
    if (syntaxErrors.original.length > 0 || syntaxErrors.updated.length > 0) {
      markdown += `## Syntax Validation\n\n`;
      if (syntaxErrors.original.length > 0) {
        markdown += `### Original Query Issues (${syntaxErrors.original.length})\n\n`;
        syntaxErrors.original.forEach(err => {
          markdown += `- **Line ${err.line}:** ${err.message} \`[${err.severity}]\`\n`;
        });
        markdown += `\n`;
      }
      if (syntaxErrors.updated.length > 0) {
        markdown += `### Updated Query Issues (${syntaxErrors.updated.length})\n\n`;
        syntaxErrors.updated.forEach(err => {
          markdown += `- **Line ${err.line}:** ${err.message} \`[${err.severity}]\`\n`;
        });
        markdown += `\n`;
      }
    }

    // AI Analysis
    if (aiAnalysis) {
      markdown += `## AI Analysis\n\n`;
      aiAnalysis.forEach(section => {
        markdown += `### ${section.title}\n\n${section.content}\n\n`;
      });
    }

    // FP Analysis
    if (fpAnalysis) {
      markdown += `## False Positive Analysis\n\n${fpAnalysis}\n\n`;
    }

    // Queries
    markdown += `## Original Query\n\n\`\`\`kql\n${originalQuery}\n\`\`\`\n\n`;
    markdown += `## Updated Query\n\n\`\`\`kql\n${updatedQuery}\n\`\`\`\n\n`;
    markdown += `---\n\n`;
    markdown += `*Generated by ThreatDefender KQL Diff App | eGroup Enabling Technologies*\n`;

    // Download
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kql-comparison-${Date.now()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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

  // Phase 2: Debounced AI analysis to prevent spammy API calls
  const generateAIAnalysis = useCallback(async (debounce = false) => {
    if (debounce) {
      // Clear existing timer
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }

      // Set new timer for 500ms debounce
      debounceTimerRef.current = setTimeout(() => {
        generateAIAnalysis(false);
      }, 500);
      return;
    }

    setIsAnalyzing(true);
    setAiAnalysis(null);

    try {
      // Use relative URL for Azure Static Web Apps - works with custom domains
const functionUrl = '/api/kqlanalyzer';

console.log('🔍 Sending AI analysis request:', { originalLength: originalQuery.length, updatedLength: updatedQuery.length, url: functionUrl });

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

      console.log('📡 Response status:', response.status, response.statusText);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        console.error('❌ API Error Response:', errorData);
        throw new Error(`API Error (${response.status}): ${errorData.error || errorData.details || response.statusText}`);
      }

      const data = await response.json();
      console.log('✅ Received data:', { hasContent: !!data.content, contentLength: data.content?.length });

      if (!data.content || !data.content[0] || !data.content[0].text) {
        console.error('❌ Invalid response format:', data);
        throw new Error('Invalid response format from API');
      }

      const analysis = data.content[0].text;
      const parsedSections = parseAIResponse(analysis);
      console.log('✅ Parsed sections:', parsedSections.length);
      setAiAnalysis(parsedSections);
    } catch (error) {
      console.error("❌ Error generating AI analysis:", error);
      const errorMessage = error.message || 'Unknown error occurred';
      setAiAnalysis([{
        title: 'Error',
        content: `Failed to generate analysis: ${errorMessage}\n\nPlease check:\n- Azure Function is running\n- Azure OpenAI credentials are configured\n- Network connectivity`,
        type: 'warning'
      }]);
    } finally {
      setIsAnalyzing(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [originalQuery, updatedQuery]);

  const generateFPAnalysis = async () => {
    setIsFpAnalyzing(true);
    setFpAnalysis(null);

    try {
      // Use relative URL for Azure Static Web Apps - works with custom domains
const functionUrl = '/api/kqlanalyzer';

console.log('🔍 Sending FP analysis request:', { url: functionUrl });

      // FP-specific analysis call
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

      console.log('📡 FP Response status:', fpResponse.status, fpResponse.statusText);

      if (!fpResponse.ok) {
        const errorData = await fpResponse.json().catch(() => ({ error: 'Unknown error' }));
        console.error('❌ FP API Error Response:', errorData);
        throw new Error(`API Error (${fpResponse.status}): ${errorData.error || errorData.details || fpResponse.statusText}`);
      }

      const fpData = await fpResponse.json();
      console.log('✅ Received FP data:', { hasContent: !!fpData.content });

      if (!fpData.content || !fpData.content[0] || !fpData.content[0].text) {
        console.error('❌ Invalid FP response format:', fpData);
        throw new Error('Invalid response format from API');
      }

      const fpText = fpData.content[0].text;
      console.log('✅ FP Analysis received:', fpText.substring(0, 100) + '...');
      setFpAnalysis(fpText);
    } catch (error) {
      console.error("❌ Error generating FP analysis:", error);
      const errorMessage = error.message || 'Unknown error occurred';
      setFpAnalysis(`Failed to generate false positive analysis: ${errorMessage}\n\nPlease check:\n- Azure Function is running\n- Azure OpenAI credentials are configured\n- Network connectivity`);
    } finally {
      setIsFpAnalyzing(false);
    }
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
          reportContent += `<div class="error-item">Line ${escapeHtml(String(err.line))}: ${escapeHtml(err.message)} [${escapeHtml(err.severity)}]</div>`;
        });
        reportContent += `</div></div>`;
      }

      if (syntaxErrors.updated.length > 0) {
        reportContent += `<div class="error-section">
          <h3>Updated Query Issues (${syntaxErrors.updated.length})</h3>
          <div class="error-list">`;
        syntaxErrors.updated.forEach(err => {
          reportContent += `<div class="error-item">Line ${escapeHtml(String(err.line))}: ${escapeHtml(err.message)} [${escapeHtml(err.severity)}]</div>`;
        });
        reportContent += `</div></div>`;
      }
    }

    // Add AI Analysis
    if (aiAnalysis) {
      reportContent += `<h2>AI Analysis</h2>`;
      aiAnalysis.forEach(section => {
        reportContent += `<div class="analysis-section">
          <h3>${escapeHtml(section.title)}</h3>
          <div>${escapeHtml(section.content).replace(/\n/g, '<br>')}</div>
        </div>`;
      });
    }

    // Add FP Analysis
    if (fpAnalysis) {
      reportContent += `<h2>False Positive Analysis</h2>
      <div class="fp-section">
        <div>${escapeHtml(fpAnalysis).replace(/\n/g, '<br>')}</div>
      </div>`;
    }

    // Add queries
    reportContent += `
  <h2>Original Query</h2>
  <div class="query-section">
    <div class="query-box">
      <pre>${escapeHtml(originalQuery)}</pre>
    </div>
  </div>

  <h2>Updated Query</h2>
  <div class="query-section">
    <div class="query-box">
      <pre>${escapeHtml(updatedQuery)}</pre>
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
    setShareUrl('');
  };

  // Phase 2: Memoize diff computation with new dependencies
  const diff = React.useMemo(() => {
    if (!showDiff) return [];

    const originalLines = originalQuery.split('\n');
    const updatedLines = updatedQuery.split('\n');
    const maxLength = Math.max(originalLines.length, updatedLines.length);

    const normalizeLine = (line) => {
      let normalized = line;
      if (ignoreWhitespace) {
        normalized = normalized.replace(/\s+/g, ' ').trim();
      }
      if (ignoreCase) {
        normalized = normalized.toLowerCase();
      }
      return normalized;
    };

    const result = [];
    for (let i = 0; i < maxLength; i++) {
      const origLine = originalLines[i] || '';
      const updLine = updatedLines[i] || '';

      const normalizedOrig = normalizeLine(origLine);
      const normalizedUpd = normalizeLine(updLine);

      if (normalizedOrig === normalizedUpd) {
        result.push({ type: 'unchanged', original: origLine, updated: updLine, lineNum: i + 1 });
      } else if (!origLine && updLine) {
        result.push({ type: 'added', original: '', updated: updLine, lineNum: i + 1 });
      } else if (origLine && !updLine) {
        result.push({ type: 'removed', original: origLine, updated: '', lineNum: i + 1 });
      } else {
        result.push({
          type: 'modified',
          original: origLine,
          updated: updLine,
          lineNum: i + 1
        });
      }
    }
    return result;
  }, [showDiff, originalQuery, updatedQuery, ignoreWhitespace, ignoreCase]);

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
            {/* Phase 1: Monaco Editor for Original Query */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                Original KQL Query
              </label>
              <div className="border rounded-md overflow-hidden" style={{ height: '400px' }}>
                <Editor
                  height="400px"
                  defaultLanguage="kusto"
                  language="kusto"
                  value={originalQuery}
                  onChange={(value) => setOriginalQuery(value || '')}
                  theme={darkMode ? 'vs-dark' : 'vs'}
                  options={{
                    minimap: { enabled: true },
                    fontSize: 14,
                    wordWrap: 'on',
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    tabSize: 2
                  }}
                  onMount={(editor, monaco) => {
                    originalEditorRef.current = editor;

                    // Apply initial validation
                    const errors = validateKQLSyntax(originalQuery);
                    applyMonacoMarkers(editor, errors, monaco);

                    // Listen for changes and revalidate
                    editor.onDidChangeModelContent(() => {
                      const content = editor.getValue();
                      const newErrors = validateKQLSyntax(content);
                      applyMonacoMarkers(editor, newErrors, monaco);
                      setSyntaxErrors(prev => ({ ...prev, original: newErrors }));
                    });
                  }}
                />
              </div>
            </div>

            {/* Phase 1: Monaco Editor for Updated Query */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                Updated KQL Query
              </label>
              <div className="border rounded-md overflow-hidden" style={{ height: '400px' }}>
                <Editor
                  height="400px"
                  defaultLanguage="kusto"
                  language="kusto"
                  value={updatedQuery}
                  onChange={(value) => setUpdatedQuery(value || '')}
                  theme={darkMode ? 'vs-dark' : 'vs'}
                  options={{
                    minimap: { enabled: true },
                    fontSize: 14,
                    wordWrap: 'on',
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    tabSize: 2
                  }}
                  onMount={(editor, monaco) => {
                    updatedEditorRef.current = editor;

                    // Apply initial validation
                    const errors = validateKQLSyntax(updatedQuery);
                    applyMonacoMarkers(editor, errors, monaco);

                    // Listen for changes and revalidate
                    editor.onDidChangeModelContent(() => {
                      const content = editor.getValue();
                      const newErrors = validateKQLSyntax(content);
                      applyMonacoMarkers(editor, newErrors, monaco);
                      setSyntaxErrors(prev => ({ ...prev, updated: newErrors }));
                    });
                  }}
                />
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* Phase 2: Noise-Control Toggles */}
            <div className={`rounded-lg shadow p-4 mb-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <div className="flex flex-wrap items-center gap-6">
                <h3 className={`text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                  Diff Options:
                </h3>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ignoreWhitespace}
                    onChange={(e) => setIgnoreWhitespace(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
                  />
                  <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Ignore Whitespace
                  </span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ignoreCase}
                    onChange={(e) => setIgnoreCase(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
                  />
                  <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Ignore Case
                  </span>
                </label>

                <div className="flex items-center gap-2">
                  <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>View:</span>
                  <button
                    onClick={() => setViewMode('side-by-side')}
                    className={`px-3 py-1 rounded text-sm ${
                      viewMode === 'side-by-side'
                        ? 'bg-blue-600 text-white'
                        : darkMode
                        ? 'bg-gray-700 text-gray-300'
                        : 'bg-gray-200 text-gray-700'
                    }`}
                  >
                    Side-by-Side
                  </button>
                  <button
                    onClick={() => setViewMode('inline')}
                    className={`px-3 py-1 rounded text-sm ${
                      viewMode === 'inline'
                        ? 'bg-blue-600 text-white'
                        : darkMode
                        ? 'bg-gray-700 text-gray-300'
                        : 'bg-gray-200 text-gray-700'
                    }`}
                  >
                    Inline
                  </button>
                </div>

                <div className="ml-auto">
                  <button
                    onClick={generateShareUrl}
                    className="px-4 py-2 bg-indigo-600 text-white rounded-md font-semibold hover:bg-indigo-700 transition text-sm"
                  >
                    🔗 Share Link
                  </button>
                </div>
              </div>

              {shareUrl && (
                <div className={`mt-3 p-2 rounded text-xs ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-700'}`}>
                  Link copied! Share: <span className="font-mono break-all">{shareUrl}</span>
                </div>
              )}
            </div>

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

            {/* Phase 1: Monaco DiffEditor - Professional side-by-side or inline diff view */}
            <div className={`rounded-lg shadow overflow-hidden ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <div className={`p-4 border-b ${
                darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-100 border-gray-200'
              }`}>
                <h2 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  Query Comparison
                </h2>
              </div>

              <div style={{ height: '600px' }}>
                <DiffEditor
                  height="600px"
                  language="kusto"
                  original={originalQuery}
                  modified={updatedQuery}
                  theme={darkMode ? 'vs-dark' : 'vs'}
                  options={{
                    renderSideBySide: viewMode === 'side-by-side',
                    readOnly: true,
                    minimap: { enabled: true },
                    fontSize: 14,
                    wordWrap: 'on',
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    ignoreTrimWhitespace: ignoreWhitespace,
                    originalEditable: false,
                    enableSplitViewResizing: true,
                    renderOverviewRuler: true
                  }}
                  onMount={(editor, monaco) => {
                    diffEditorRef.current = editor;
                  }}
                />
              </div>

              {/* Diff Statistics */}
              <div className={`p-4 border-t ${
                darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-100 border-gray-200'
              }`}>
                <div className="flex items-center gap-6 text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-green-500 rounded"></div>
                    <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>
                      Added: {diff.filter(l => l.type === 'added').length}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-red-500 rounded"></div>
                    <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>
                      Removed: {diff.filter(l => l.type === 'removed').length}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-yellow-500 rounded"></div>
                    <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>
                      Modified: {diff.filter(l => l.type === 'modified').length}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        <div className="mt-6 space-y-4">
          <div className="flex gap-4 flex-wrap">
            {!showDiff ? (
              <>
                <button
                  onClick={handleCompare}
                  disabled={!originalQuery.trim() || !updatedQuery.trim()}
                  className="px-6 py-3 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition"
                >
                  Compare Queries
                </button>
                <span className={`text-sm self-center ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  (Ctrl+Enter)
                </span>
              </>
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
                    onClick={() => generateAIAnalysis(false)}
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
                    {isFpAnalyzing ? 'Analyzing...' : 'False Positive Check'}
                  </button>
                )}

                {/* Phase 2: Export buttons with both HTML and Markdown */}
                <div className="flex gap-2">
                  <button
                    onClick={exportReport}
                    className="px-6 py-3 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 transition"
                  >
                    Export HTML
                  </button>
                  <button
                    onClick={() => exportMarkdownFn(diff)}
                    className="px-6 py-3 bg-teal-600 text-white rounded-md font-semibold hover:bg-teal-700 transition"
                  >
                    Export Markdown
                  </button>
                </div>

                <span className={`text-sm self-center ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  (ESC to go back)
                </span>
              </>
            )}
          </div>

          {/* Phase 2: Keyboard shortcuts help */}
          {!showDiff && (
            <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
              <strong>Keyboard Shortcuts:</strong> Ctrl+Enter to compare | ESC to go back
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
