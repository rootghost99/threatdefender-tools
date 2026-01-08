// /src/components/PromptDetail.jsx
import React, { useState, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import { useAuth } from '../contexts/AuthContext';

// IOC extraction patterns
const IOC_PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|ru|cn|jp|au|ca|info|biz|xyz|top|online|site|club|work|live|store|tech|app|dev|me|tv|cc|ws|pw|tk|ml|ga|cf|gq|email|link|click|download|zip|mov|support|help|cloud|host|world)\b/gi,
  url: /https?:\/\/[^\s<>"')\]]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  cve: /CVE-\d{4}-\d{4,}/gi
};

// Defang patterns for common obfuscation
const DEFANG_PATTERNS = [
  { pattern: /\[\.?\]/g, replacement: '.' },
  { pattern: /hxxp/gi, replacement: 'http' },
  { pattern: /\[@\]/g, replacement: '@' }
];

// Refang text (convert defanged IOCs back to original)
function refangText(text) {
  let result = text;
  DEFANG_PATTERNS.forEach(({ pattern, replacement }) => {
    result = result.replace(pattern, replacement);
  });
  return result;
}

// Check if IP is private/internal
function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    parts[0] === 0 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
}

// Extract IOCs from text
function extractIOCs(text) {
  if (!text) return { ips: [], domains: [], urls: [], md5s: [], sha1s: [], sha256s: [], emails: [], cves: [] };

  const refangedText = refangText(text);
  const result = {
    ips: [],
    domains: [],
    urls: [],
    md5s: [],
    sha1s: [],
    sha256s: [],
    emails: [],
    cves: []
  };

  // Extract SHA-256 first (longest hash)
  const sha256Matches = refangedText.match(IOC_PATTERNS.sha256) || [];
  result.sha256s = [...new Set(sha256Matches.map(h => h.toLowerCase()))];

  // Extract SHA-1 (exclude if part of SHA-256)
  const sha1Matches = refangedText.match(IOC_PATTERNS.sha1) || [];
  result.sha1s = [...new Set(sha1Matches.map(h => h.toLowerCase()))]
    .filter(h => !result.sha256s.some(s256 => s256.includes(h)));

  // Extract MD5 (exclude if part of longer hash)
  const md5Matches = refangedText.match(IOC_PATTERNS.md5) || [];
  result.md5s = [...new Set(md5Matches.map(h => h.toLowerCase()))]
    .filter(h => !result.sha1s.some(s1 => s1.includes(h)) && !result.sha256s.some(s256 => s256.includes(h)));

  // Extract IPs (exclude private)
  const ipMatches = refangedText.match(IOC_PATTERNS.ipv4) || [];
  result.ips = [...new Set(ipMatches)].filter(ip => !isPrivateIP(ip));

  // Extract URLs
  const urlMatches = refangedText.match(IOC_PATTERNS.url) || [];
  result.urls = [...new Set(urlMatches)];

  // Extract domains (exclude those already in URLs)
  const domainMatches = refangedText.match(IOC_PATTERNS.domain) || [];
  const urlDomains = result.urls.map(u => {
    try { return new URL(u).hostname; } catch { return ''; }
  });
  result.domains = [...new Set(domainMatches.map(d => d.toLowerCase()))]
    .filter(d => !urlDomains.includes(d));

  // Extract emails
  const emailMatches = refangedText.match(IOC_PATTERNS.email) || [];
  result.emails = [...new Set(emailMatches.map(e => e.toLowerCase()))];

  // Extract CVEs
  const cveMatches = refangedText.match(IOC_PATTERNS.cve) || [];
  result.cves = [...new Set(cveMatches.map(c => c.toUpperCase()))];

  return result;
}

// Get total IOC count
function getIOCCount(iocs) {
  return iocs.ips.length + iocs.domains.length + iocs.urls.length +
    iocs.md5s.length + iocs.sha1s.length + iocs.sha256s.length +
    iocs.emails.length + iocs.cves.length;
}

export default function PromptDetail({ darkMode, promptId, onBack, onEdit }) {
  const { isAuthenticated, getSentinelWorkspaces, getSentinelIncident, getIncidentLogs } = useAuth();

  const [prompt, setPrompt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Form state
  const [context, setContext] = useState('');
  const [variables, setVariables] = useState({});
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState(null);
  const [runError, setRunError] = useState(null);
  const [usage, setUsage] = useState(null);

  // Sentinel incident loader state
  const [workspaces, setWorkspaces] = useState([]);
  const [workspacesLoading, setWorkspacesLoading] = useState(false);
  const [workspacesError, setWorkspacesError] = useState(null);
  const [selectedWorkspace, setSelectedWorkspace] = useState('');
  const [incidentNumber, setIncidentNumber] = useState('');
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [incidentError, setIncidentError] = useState(null);
  const [showSentinelLoader, setShowSentinelLoader] = useState(false);

  // IOC extraction and enrichment state
  const [extractedIOCs, setExtractedIOCs] = useState(null);
  const [enrichmentResults, setEnrichmentResults] = useState({});
  const [enriching, setEnriching] = useState(false);
  const [enrichmentProgress, setEnrichmentProgress] = useState({ current: 0, total: 0 });
  const [showIOCPanel, setShowIOCPanel] = useState(false);

  // Fetch prompt details
  useEffect(() => {
    fetchPrompt();
  }, [promptId]);

  const fetchPrompt = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/prompts/${promptId}`);
      if (!response.ok) throw new Error('Failed to fetch prompt');
      const data = await response.json();
      setPrompt(data);

      // Initialize variables
      const initialVars = {};
      if (data.variables) {
        data.variables.forEach(v => {
          initialVars[v.name] = v.defaultValue || '';
        });
      }
      setVariables(initialVars);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Load Sentinel workspaces when the loader is shown
  useEffect(() => {
    async function loadWorkspaces() {
      if (!showSentinelLoader || !isAuthenticated || workspaces.length > 0) return;

      setWorkspacesLoading(true);
      setWorkspacesError(null);
      try {
        const ws = await getSentinelWorkspaces((progressWorkspaces) => {
          setWorkspaces(progressWorkspaces);
        });
        setWorkspaces(ws);
        // Auto-select first workspace if only one
        if (ws.length === 1) {
          setSelectedWorkspace(ws[0].id);
        }
      } catch (err) {
        console.error('Failed to load workspaces:', err);
        setWorkspacesError(err.message || 'Failed to load workspaces');
      } finally {
        setWorkspacesLoading(false);
      }
    }

    loadWorkspaces();
  }, [showSentinelLoader, isAuthenticated, getSentinelWorkspaces, workspaces.length]);

  // Fetch incident from Sentinel
  const fetchIncident = useCallback(async () => {
    if (!selectedWorkspace || !incidentNumber.trim()) {
      setIncidentError('Please select a workspace and enter an incident number');
      return;
    }

    setIncidentLoading(true);
    setIncidentError(null);

    try {
      // Get incident details, alerts, and entities
      const { incident, alerts, entities } = await getSentinelIncident(selectedWorkspace, incidentNumber.trim());

      // Get workspace customerId for Log Analytics queries
      const workspace = workspaces.find(w => w.id === selectedWorkspace);

      // Try to get additional logs from Log Analytics
      let logs = null;
      if (workspace?.customerId && getIncidentLogs) {
        try {
          logs = await getIncidentLogs(workspace.customerId, incidentNumber.trim());
        } catch (logErr) {
          console.warn('Could not fetch Log Analytics data:', logErr);
        }
      }

      // Format the incident data as JSON for the context
      const incidentData = {
        incident: {
          id: incident.name,
          title: incident.properties?.title,
          description: incident.properties?.description,
          severity: incident.properties?.severity,
          status: incident.properties?.status,
          classification: incident.properties?.classification,
          classificationComment: incident.properties?.classificationComment,
          owner: incident.properties?.owner,
          labels: incident.properties?.labels,
          tactics: incident.properties?.additionalData?.tactics,
          techniques: incident.properties?.additionalData?.techniques,
          alertsCount: incident.properties?.additionalData?.alertsCount,
          createdTimeUtc: incident.properties?.createdTimeUtc,
          lastModifiedTimeUtc: incident.properties?.lastModifiedTimeUtc,
        },
        alerts: alerts.map(alert => ({
          id: alert.properties?.systemAlertId,
          name: alert.properties?.alertDisplayName,
          description: alert.properties?.description,
          severity: alert.properties?.severity,
          status: alert.properties?.status,
          providerName: alert.properties?.providerAlertId,
          tactics: alert.properties?.tactics,
          techniques: alert.properties?.techniques,
          timeGenerated: alert.properties?.timeGenerated,
          entities: alert.properties?.entities,
        })),
        entities: entities.map(entity => ({
          type: entity.kind,
          ...entity.properties,
        })),
        logAnalyticsData: logs,
      };

      // Set the context with formatted JSON
      setContext(JSON.stringify(incidentData, null, 2));

      // Auto-populate severity variable if it exists
      if (incident.properties?.severity) {
        const severityMap = {
          'Informational': 'Low',
          'Low': 'Low',
          'Medium': 'Medium',
          'High': 'High',
          'Critical': 'Critical'
        };
        const mappedSeverity = severityMap[incident.properties.severity] || incident.properties.severity;
        setVariables(prev => ({
          ...prev,
          severity: mappedSeverity
        }));
      }

      // Close the Sentinel loader panel
      setShowSentinelLoader(false);

    } catch (err) {
      console.error('Failed to fetch incident:', err);
      setIncidentError(`Failed to fetch incident: ${err.message}`);
    } finally {
      setIncidentLoading(false);
    }
  }, [selectedWorkspace, incidentNumber, workspaces, getSentinelIncident, getIncidentLogs]);

  // Extract IOCs when context changes
  useEffect(() => {
    if (context) {
      const iocs = extractIOCs(context);
      setExtractedIOCs(iocs);
      // Clear enrichment when context changes
      setEnrichmentResults({});
    } else {
      setExtractedIOCs(null);
      setEnrichmentResults({});
    }
  }, [context]);

  // Enrich IOCs via ThreatIntelLookup API
  const enrichIOCs = useCallback(async () => {
    if (!extractedIOCs) return;

    // Collect all indicators to enrich
    const allIndicators = [
      ...extractedIOCs.ips.map(v => ({ value: v, type: 'IP' })),
      ...extractedIOCs.domains.map(v => ({ value: v, type: 'Domain' })),
      ...extractedIOCs.urls.slice(0, 10).map(v => ({ value: v, type: 'URL' })), // Limit URLs
      ...extractedIOCs.sha256s.map(v => ({ value: v, type: 'SHA256' })),
      ...extractedIOCs.sha1s.map(v => ({ value: v, type: 'SHA1' })),
      ...extractedIOCs.md5s.map(v => ({ value: v, type: 'MD5' }))
    ];

    if (allIndicators.length === 0) {
      return;
    }

    setEnriching(true);
    setEnrichmentProgress({ current: 0, total: allIndicators.length });

    const results = {};
    const batchSize = 3;

    try {
      for (let i = 0; i < allIndicators.length; i += batchSize) {
        const batch = allIndicators.slice(i, i + batchSize);

        const batchResults = await Promise.all(
          batch.map(async ({ value, type }) => {
            try {
              const resp = await fetch('/api/ThreatIntelLookup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ indicator: value })
              });

              if (!resp.ok) {
                return { indicator: value, type, error: 'Lookup failed' };
              }

              const data = await resp.json();
              return { indicator: value, type, ...data };
            } catch (err) {
              return { indicator: value, type, error: err.message };
            }
          })
        );

        batchResults.forEach(result => {
          results[result.indicator] = result;
        });

        setEnrichmentProgress({ current: Math.min(i + batchSize, allIndicators.length), total: allIndicators.length });

        // Small delay between batches to avoid rate limiting
        if (i + batchSize < allIndicators.length) {
          await new Promise(r => setTimeout(r, 500));
        }
      }

      setEnrichmentResults(results);
    } catch (err) {
      console.error('Enrichment error:', err);
    } finally {
      setEnriching(false);
    }
  }, [extractedIOCs]);

  // Summarize enrichment for prompt context
  const getEnrichmentSummary = useCallback(() => {
    if (Object.keys(enrichmentResults).length === 0) return null;

    const summary = {
      highRiskIOCs: [],
      maliciousIndicators: [],
      suspiciousIndicators: [],
      cleanIndicators: [],
      enrichmentDetails: {}
    };

    Object.entries(enrichmentResults).forEach(([indicator, data]) => {
      if (data.error) return;

      const vtMalicious = data.virusTotal?.malicious || 0;
      const vtSuspicious = data.virusTotal?.suspicious || 0;
      const abuseScore = data.abuseIPDB?.abuseScore || 0;
      const otxPulses = data.alienVault?.pulseCount || 0;

      // Classify risk level
      if (vtMalicious > 5 || abuseScore > 50) {
        summary.highRiskIOCs.push(indicator);
        summary.maliciousIndicators.push({
          indicator,
          type: data.type,
          detections: vtMalicious,
          abuseScore
        });
      } else if (vtMalicious > 0 || vtSuspicious > 0 || abuseScore > 20 || otxPulses > 0) {
        summary.suspiciousIndicators.push({
          indicator,
          type: data.type,
          detections: vtMalicious + vtSuspicious,
          pulses: otxPulses
        });
      } else if (vtMalicious === 0 && !data.error) {
        summary.cleanIndicators.push(indicator);
      }

      // Store detailed enrichment
      summary.enrichmentDetails[indicator] = {
        type: data.type,
        virusTotal: data.virusTotal ? {
          malicious: data.virusTotal.malicious,
          suspicious: data.virusTotal.suspicious,
          harmless: data.virusTotal.harmless
        } : null,
        abuseIPDB: data.abuseIPDB ? {
          score: data.abuseIPDB.abuseScore,
          reports: data.abuseIPDB.totalReports,
          country: data.abuseIPDB.countryCode
        } : null,
        greyNoise: data.greyNoise ? {
          classification: data.greyNoise.classification,
          noise: data.greyNoise.noise
        } : null,
        alienVault: data.alienVault ? {
          pulses: data.alienVault.pulseCount
        } : null,
        shodan: data.shodan ? {
          ports: data.shodan.openPortsCount,
          vulns: data.shodan.vulnCount
        } : null
      };
    });

    return summary;
  }, [enrichmentResults]);

  // Get risk badge for an indicator
  const getIndicatorRisk = (indicator) => {
    const data = enrichmentResults[indicator];
    if (!data || data.error) return 'unknown';

    const vtMalicious = data.virusTotal?.malicious || 0;
    const abuseScore = data.abuseIPDB?.abuseScore || 0;

    if (vtMalicious > 5 || abuseScore > 50) return 'high';
    if (vtMalicious > 0 || abuseScore > 20) return 'medium';
    if (data.virusTotal && vtMalicious === 0) return 'clean';
    return 'unknown';
  };

  // Run prompt
  const handleRun = async () => {
    setRunning(true);
    setRunError(null);
    setOutput(null);
    setUsage(null);

    try {
      // Build enhanced context with IOC and enrichment data
      let enhancedContext = context;

      // Add extracted IOCs summary if present
      if (extractedIOCs && getIOCCount(extractedIOCs) > 0) {
        const iocSummary = `\n\n---\n## Extracted IOCs\n` +
          (extractedIOCs.ips.length > 0 ? `- **IPs**: ${extractedIOCs.ips.join(', ')}\n` : '') +
          (extractedIOCs.domains.length > 0 ? `- **Domains**: ${extractedIOCs.domains.join(', ')}\n` : '') +
          (extractedIOCs.urls.length > 0 ? `- **URLs**: ${extractedIOCs.urls.slice(0, 5).join(', ')}${extractedIOCs.urls.length > 5 ? ` (+${extractedIOCs.urls.length - 5} more)` : ''}\n` : '') +
          (extractedIOCs.sha256s.length > 0 ? `- **SHA256 Hashes**: ${extractedIOCs.sha256s.join(', ')}\n` : '') +
          (extractedIOCs.sha1s.length > 0 ? `- **SHA1 Hashes**: ${extractedIOCs.sha1s.join(', ')}\n` : '') +
          (extractedIOCs.md5s.length > 0 ? `- **MD5 Hashes**: ${extractedIOCs.md5s.join(', ')}\n` : '') +
          (extractedIOCs.emails.length > 0 ? `- **Emails**: ${extractedIOCs.emails.join(', ')}\n` : '') +
          (extractedIOCs.cves.length > 0 ? `- **CVEs**: ${extractedIOCs.cves.join(', ')}\n` : '');

        enhancedContext += iocSummary;
      }

      // Add enrichment summary if present
      const enrichmentSummary = getEnrichmentSummary();
      if (enrichmentSummary) {
        let enrichmentSection = '\n## Threat Intelligence Enrichment\n';

        if (enrichmentSummary.highRiskIOCs.length > 0) {
          enrichmentSection += `\n### High Risk Indicators (${enrichmentSummary.highRiskIOCs.length})\n`;
          enrichmentSummary.maliciousIndicators.forEach(ind => {
            enrichmentSection += `- **${ind.indicator}** (${ind.type}): ${ind.detections} VT detections`;
            if (ind.abuseScore) enrichmentSection += `, ${ind.abuseScore}% AbuseIPDB score`;
            enrichmentSection += '\n';
          });
        }

        if (enrichmentSummary.suspiciousIndicators.length > 0) {
          enrichmentSection += `\n### Suspicious Indicators (${enrichmentSummary.suspiciousIndicators.length})\n`;
          enrichmentSummary.suspiciousIndicators.forEach(ind => {
            enrichmentSection += `- **${ind.indicator}** (${ind.type}): ${ind.detections} detections`;
            if (ind.pulses) enrichmentSection += `, ${ind.pulses} OTX pulses`;
            enrichmentSection += '\n';
          });
        }

        if (enrichmentSummary.cleanIndicators.length > 0) {
          enrichmentSection += `\n### Clean/Benign Indicators (${enrichmentSummary.cleanIndicators.length})\n`;
          enrichmentSection += enrichmentSummary.cleanIndicators.join(', ') + '\n';
        }

        // Add detailed enrichment as JSON for AI analysis
        enrichmentSection += '\n### Detailed Enrichment Data\n```json\n' +
          JSON.stringify(enrichmentSummary.enrichmentDetails, null, 2) + '\n```\n';

        enhancedContext += enrichmentSection;
      }

      const response = await fetch(`/api/prompts/${promptId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context: enhancedContext, variables })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to run prompt');
      }

      const data = await response.json();
      setOutput(data.output);
      setUsage(data.usage);
    } catch (err) {
      setRunError(err.message);
    } finally {
      setRunning(false);
    }
  };

  // Copy output to clipboard
  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  // Copy specific section to clipboard
  const copySection = (sectionTitle) => {
    if (!output) return;

    // Find section by looking for headers (## or ###)
    const lines = output.split('\n');
    let inSection = false;
    let sectionContent = [];

    for (const line of lines) {
      // Check if this is the target section header
      if (line.match(/^#{2,3}\s/) && line.toLowerCase().includes(sectionTitle.toLowerCase())) {
        inSection = true;
        sectionContent.push(line);
        continue;
      }
      // Check if we've hit the next section
      if (inSection && line.match(/^#{2,3}\s/)) {
        break;
      }
      if (inSection) {
        sectionContent.push(line);
      }
    }

    if (sectionContent.length > 0) {
      navigator.clipboard.writeText(sectionContent.join('\n').trim());
    }
  };

  // Check if output contains dual sections (client + internal)
  const hasDualOutput = output &&
    (output.toLowerCase().includes('client-facing') || output.toLowerCase().includes('client facing')) &&
    (output.toLowerCase().includes('internal') || output.toLowerCase().includes('ticket notes'));

  // Delete prompt
  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this prompt? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`/api/prompts/${promptId}`, {
        method: 'DELETE'
      });

      if (!response.ok) throw new Error('Failed to delete prompt');

      alert('Prompt deleted successfully');
      onBack();
    } catch (err) {
      alert(`Error deleting prompt: ${err.message}`);
    }
  };

  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900';
  const buttonPrimary = darkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600';
  const buttonSecondary = darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300';
  const buttonDanger = darkMode ? 'bg-red-700 hover:bg-red-800' : 'bg-red-500 hover:bg-red-600';

  if (loading) {
    return (
      <div className={`text-center py-12 ${textMuted}`}>
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <p className="mt-4">Loading prompt...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <button onClick={onBack} className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}>
          ← Back to Gallery
        </button>
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {error}
        </div>
      </div>
    );
  }

  if (!prompt) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <div className="flex items-center justify-between mb-4">
          <button onClick={onBack} className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}>
            ← Back to Gallery
          </button>
          <div className="flex gap-2">
            <button
              onClick={() => onEdit(promptId)}
              className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
            >
              ✏️ Edit
            </button>
            <button
              onClick={handleDelete}
              className={`px-4 py-2 rounded font-semibold text-white ${buttonDanger}`}
            >
              🗑️ Delete
            </button>
          </div>
        </div>

        <h2 className={`text-2xl font-bold mb-2 ${textPrimary}`}>
          {prompt.title}
        </h2>
        <p className={`${textSecondary} mb-4`}>
          {prompt.description}
        </p>

        {/* Metadata */}
        <div className="flex flex-wrap gap-2 mb-4">
          <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-blue-900/50 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
            {prompt.category}
          </span>
          {prompt.collection && (
            <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-purple-900/50 text-purple-300' : 'bg-purple-100 text-purple-700'}`}>
              {prompt.collection}
            </span>
          )}
          {prompt.tags && prompt.tags.map((tag, idx) => (
            <span key={idx} className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'}`}>
              #{tag}
            </span>
          ))}
        </div>

        <div className={`text-xs ${textMuted}`}>
          Created by {prompt.createdBy} on {new Date(prompt.createdAt).toLocaleDateString()}
          {prompt.updatedBy && ` • Updated by ${prompt.updatedBy} on ${new Date(prompt.updatedAt).toLocaleDateString()}`}
        </div>
      </div>

      {/* Prompt Template Preview */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
          📝 Prompt Instructions
        </h3>
        <div className={`prose prose-sm max-w-none ${darkMode ? 'prose-invert' : ''}`}>
          <ReactMarkdown>{prompt.userInstructions}</ReactMarkdown>
        </div>
      </div>

      {/* Context Input */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <div className="flex items-center justify-between mb-2">
          <h3 className={`text-lg font-bold ${textPrimary}`}>
            📋 Incident Context (Optional)
          </h3>
          {isAuthenticated && (
            <button
              onClick={() => setShowSentinelLoader(!showSentinelLoader)}
              className={`px-3 py-1.5 rounded font-semibold text-sm ${showSentinelLoader
                ? (darkMode ? 'bg-blue-600 text-white' : 'bg-blue-500 text-white')
                : (darkMode ? 'bg-blue-900/50 text-blue-300 hover:bg-blue-800' : 'bg-blue-100 text-blue-700 hover:bg-blue-200')
              }`}
            >
              🔷 {showSentinelLoader ? 'Hide Sentinel Loader' : 'Load from Sentinel'}
            </button>
          )}
        </div>

        {/* Sentinel Incident Loader */}
        {showSentinelLoader && isAuthenticated && (
          <div className={`mb-4 p-4 rounded-lg border ${darkMode ? 'bg-blue-900/20 border-blue-800' : 'bg-blue-50 border-blue-200'}`}>
            <p className={`text-sm mb-3 ${textSecondary}`}>
              Load incident data directly from Microsoft Sentinel. Select a workspace and enter the incident number.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
              {/* Workspace Selector */}
              <div className="md:col-span-1">
                <label className={`block text-xs font-medium mb-1 ${textMuted}`}>
                  Sentinel Workspace
                </label>
                <select
                  value={selectedWorkspace}
                  onChange={(e) => setSelectedWorkspace(e.target.value)}
                  disabled={workspacesLoading || workspaces.length === 0}
                  className={`w-full px-3 py-2 rounded border text-sm ${inputBg} ${workspacesLoading ? 'opacity-50' : ''}`}
                >
                  <option value="">
                    {workspacesLoading ? 'Loading workspaces...' : workspaces.length === 0 ? 'No workspaces found' : 'Select workspace...'}
                  </option>
                  {workspaces.map((ws) => (
                    <option key={ws.id} value={ws.id}>
                      {ws.name} ({ws.subscriptionName})
                    </option>
                  ))}
                </select>
              </div>

              {/* Incident Number */}
              <div className="md:col-span-1">
                <label className={`block text-xs font-medium mb-1 ${textMuted}`}>
                  Incident Number
                </label>
                <input
                  type="text"
                  value={incidentNumber}
                  onChange={(e) => setIncidentNumber(e.target.value)}
                  placeholder="e.g., 12345"
                  className={`w-full px-3 py-2 rounded border text-sm ${inputBg}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && selectedWorkspace && incidentNumber.trim()) {
                      fetchIncident();
                    }
                  }}
                />
              </div>

              {/* Load Button */}
              <div className="md:col-span-1 flex items-end">
                <button
                  onClick={fetchIncident}
                  disabled={incidentLoading || !selectedWorkspace || !incidentNumber.trim()}
                  className={`w-full px-4 py-2 rounded font-semibold text-sm text-white ${
                    incidentLoading || !selectedWorkspace || !incidentNumber.trim()
                      ? 'bg-gray-500 cursor-not-allowed'
                      : 'bg-blue-600 hover:bg-blue-700'
                  }`}
                >
                  {incidentLoading ? '⏳ Loading...' : '📥 Load Incident'}
                </button>
              </div>
            </div>

            {/* Workspace Error */}
            {workspacesError && (
              <div className="p-2 rounded text-sm bg-red-500/10 border border-red-500/50 text-red-400 mb-2">
                {workspacesError}
              </div>
            )}

            {/* Incident Error */}
            {incidentError && (
              <div className="p-2 rounded text-sm bg-red-500/10 border border-red-500/50 text-red-400">
                {incidentError}
              </div>
            )}
          </div>
        )}

        {/* Not authenticated message */}
        {!isAuthenticated && (
          <p className={`text-sm mb-4 ${textMuted}`}>
            Paste relevant incident data, logs, or context here. <span className={darkMode ? 'text-blue-400' : 'text-blue-600'}>Sign in to load incidents directly from Sentinel.</span>
          </p>
        )}

        {isAuthenticated && !showSentinelLoader && (
          <p className={`text-sm mb-4 ${textMuted}`}>
            Paste relevant incident data, or use the "Load from Sentinel" button above to pull incident data directly.
          </p>
        )}

        {showSentinelLoader && (
          <p className={`text-sm mb-4 ${textMuted}`}>
            Or paste incident data manually below:
          </p>
        )}

        <textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Paste incident details, Sentinel logs, IP addresses, user information, etc..."
          rows={8}
          className={`w-full px-4 py-2 rounded border font-mono text-sm ${inputBg}`}
        />
        <div className={`flex justify-between text-xs mt-2 ${textMuted}`}>
          <span>
            {context.length} characters {context.length > 5000 && '(Consider summarizing for better results)'}
          </span>
          {context && (
            <button
              onClick={() => setContext('')}
              className="text-red-400 hover:text-red-300"
            >
              Clear context
            </button>
          )}
        </div>

        {/* IOC Extraction Panel */}
        {extractedIOCs && getIOCCount(extractedIOCs) > 0 && (
          <div className={`mt-4 p-4 rounded-lg border ${darkMode ? 'bg-gray-900/50 border-gray-700' : 'bg-gray-50 border-gray-300'}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className={`font-bold ${textPrimary}`}>🔍 Extracted IOCs</span>
                <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-blue-900/50 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
                  {getIOCCount(extractedIOCs)} found
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowIOCPanel(!showIOCPanel)}
                  className={`px-3 py-1 rounded text-xs font-semibold ${buttonSecondary} ${textPrimary}`}
                >
                  {showIOCPanel ? 'Hide Details' : 'Show Details'}
                </button>
                <button
                  onClick={enrichIOCs}
                  disabled={enriching}
                  className={`px-3 py-1 rounded text-xs font-semibold text-white ${
                    enriching ? 'bg-gray-500 cursor-not-allowed' : 'bg-orange-600 hover:bg-orange-700'
                  }`}
                >
                  {enriching
                    ? `⏳ Enriching ${enrichmentProgress.current}/${enrichmentProgress.total}`
                    : Object.keys(enrichmentResults).length > 0
                      ? '🔄 Re-enrich'
                      : '🔎 Enrich IOCs'
                  }
                </button>
              </div>
            </div>

            {/* Quick Summary */}
            <div className="flex flex-wrap gap-2 text-xs">
              {extractedIOCs.ips.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.ips.length} IPs
                </span>
              )}
              {extractedIOCs.domains.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.domains.length} Domains
                </span>
              )}
              {extractedIOCs.urls.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.urls.length} URLs
                </span>
              )}
              {extractedIOCs.sha256s.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.sha256s.length} SHA256
                </span>
              )}
              {extractedIOCs.sha1s.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.sha1s.length} SHA1
                </span>
              )}
              {extractedIOCs.md5s.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.md5s.length} MD5
                </span>
              )}
              {extractedIOCs.emails.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.emails.length} Emails
                </span>
              )}
              {extractedIOCs.cves.length > 0 && (
                <span className={`px-2 py-1 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  {extractedIOCs.cves.length} CVEs
                </span>
              )}
            </div>

            {/* Enrichment Summary */}
            {Object.keys(enrichmentResults).length > 0 && (
              <div className={`mt-3 pt-3 border-t ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                <div className="flex flex-wrap gap-2 text-xs">
                  {(() => {
                    const summary = getEnrichmentSummary();
                    if (!summary) return null;
                    return (
                      <>
                        {summary.highRiskIOCs.length > 0 && (
                          <span className="px-2 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/50">
                            🚨 {summary.highRiskIOCs.length} High Risk
                          </span>
                        )}
                        {summary.suspiciousIndicators.length > 0 && (
                          <span className="px-2 py-1 rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/50">
                            ⚠️ {summary.suspiciousIndicators.length} Suspicious
                          </span>
                        )}
                        {summary.cleanIndicators.length > 0 && (
                          <span className="px-2 py-1 rounded bg-green-500/20 text-green-400 border border-green-500/50">
                            ✅ {summary.cleanIndicators.length} Clean
                          </span>
                        )}
                      </>
                    );
                  })()}
                </div>
              </div>
            )}

            {/* Detailed IOC List */}
            {showIOCPanel && (
              <div className={`mt-3 pt-3 border-t ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                <div className="space-y-3 text-sm">
                  {/* IPs */}
                  {extractedIOCs.ips.length > 0 && (
                    <div>
                      <div className={`font-semibold mb-1 ${textSecondary}`}>IP Addresses</div>
                      <div className="flex flex-wrap gap-1">
                        {extractedIOCs.ips.map((ip, i) => {
                          const risk = getIndicatorRisk(ip);
                          const riskColors = {
                            high: 'bg-red-500/20 text-red-400 border-red-500/50',
                            medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
                            clean: 'bg-green-500/20 text-green-400 border-green-500/50',
                            unknown: darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'
                          };
                          return (
                            <span key={i} className={`px-2 py-0.5 rounded text-xs font-mono border ${riskColors[risk]}`}>
                              {ip}
                              {enrichmentResults[ip]?.virusTotal && (
                                <span className="ml-1 opacity-75">
                                  ({enrichmentResults[ip].virusTotal.malicious}/{enrichmentResults[ip].virusTotal.malicious + enrichmentResults[ip].virusTotal.suspicious + (enrichmentResults[ip].virusTotal.harmless || 0)})
                                </span>
                              )}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Domains */}
                  {extractedIOCs.domains.length > 0 && (
                    <div>
                      <div className={`font-semibold mb-1 ${textSecondary}`}>Domains</div>
                      <div className="flex flex-wrap gap-1">
                        {extractedIOCs.domains.map((domain, i) => {
                          const risk = getIndicatorRisk(domain);
                          const riskColors = {
                            high: 'bg-red-500/20 text-red-400 border-red-500/50',
                            medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
                            clean: 'bg-green-500/20 text-green-400 border-green-500/50',
                            unknown: darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'
                          };
                          return (
                            <span key={i} className={`px-2 py-0.5 rounded text-xs font-mono border ${riskColors[risk]}`}>
                              {domain}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Hashes */}
                  {(extractedIOCs.sha256s.length > 0 || extractedIOCs.sha1s.length > 0 || extractedIOCs.md5s.length > 0) && (
                    <div>
                      <div className={`font-semibold mb-1 ${textSecondary}`}>File Hashes</div>
                      <div className="space-y-1">
                        {extractedIOCs.sha256s.map((hash, i) => {
                          const risk = getIndicatorRisk(hash);
                          const riskColors = {
                            high: 'bg-red-500/20 text-red-400 border-red-500/50',
                            medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
                            clean: 'bg-green-500/20 text-green-400 border-green-500/50',
                            unknown: darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'
                          };
                          return (
                            <div key={i} className={`px-2 py-1 rounded text-xs font-mono border ${riskColors[risk]} break-all`}>
                              <span className="opacity-50">SHA256:</span> {hash}
                              {enrichmentResults[hash]?.virusTotal && (
                                <span className="ml-2">
                                  ({enrichmentResults[hash].virusTotal.malicious} detections)
                                </span>
                              )}
                            </div>
                          );
                        })}
                        {extractedIOCs.sha1s.map((hash, i) => (
                          <div key={i} className={`px-2 py-1 rounded text-xs font-mono ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} break-all`}>
                            <span className="opacity-50">SHA1:</span> {hash}
                          </div>
                        ))}
                        {extractedIOCs.md5s.map((hash, i) => (
                          <div key={i} className={`px-2 py-1 rounded text-xs font-mono ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} break-all`}>
                            <span className="opacity-50">MD5:</span> {hash}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* URLs */}
                  {extractedIOCs.urls.length > 0 && (
                    <div>
                      <div className={`font-semibold mb-1 ${textSecondary}`}>URLs</div>
                      <div className="space-y-1">
                        {extractedIOCs.urls.slice(0, 10).map((url, i) => (
                          <div key={i} className={`px-2 py-1 rounded text-xs font-mono ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} break-all`}>
                            {url}
                          </div>
                        ))}
                        {extractedIOCs.urls.length > 10 && (
                          <div className={`text-xs ${textMuted}`}>
                            +{extractedIOCs.urls.length - 10} more URLs
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Emails */}
                  {extractedIOCs.emails.length > 0 && (
                    <div>
                      <div className={`font-semibold mb-1 ${textSecondary}`}>Email Addresses</div>
                      <div className="flex flex-wrap gap-1">
                        {extractedIOCs.emails.map((email, i) => (
                          <span key={i} className={`px-2 py-0.5 rounded text-xs font-mono ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                            {email}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* CVEs */}
                  {extractedIOCs.cves.length > 0 && (
                    <div>
                      <div className={`font-semibold mb-1 ${textSecondary}`}>CVE References</div>
                      <div className="flex flex-wrap gap-1">
                        {extractedIOCs.cves.map((cve, i) => (
                          <span key={i} className={`px-2 py-0.5 rounded text-xs font-mono ${darkMode ? 'bg-purple-900/50 text-purple-300' : 'bg-purple-100 text-purple-700'}`}>
                            {cve}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Variables */}
      {prompt.variables && prompt.variables.length > 0 && (
        <div className={`p-6 rounded-lg border ${cardBg}`}>
          <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
            🔧 Variables
          </h3>
          <div className="space-y-4">
            {prompt.variables.map((varDef, idx) => (
              <div key={idx}>
                <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
                  {varDef.label || varDef.name}
                  {varDef.required && <span className="text-red-500 ml-1">*</span>}
                </label>
                {varDef.description && (
                  <p className={`text-xs mb-2 ${textMuted}`}>{varDef.description}</p>
                )}
                {varDef.type === 'boolean' ? (
                  <input
                    type="checkbox"
                    checked={variables[varDef.name] || false}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.checked })}
                    className="w-4 h-4"
                  />
                ) : varDef.type === 'enum' && varDef.options ? (
                  <select
                    value={variables[varDef.name] || ''}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.value })}
                    className={`w-full px-4 py-2 rounded border ${inputBg}`}
                  >
                    <option value="">Select...</option>
                    {varDef.options.map((opt, i) => (
                      <option key={i} value={opt}>{opt}</option>
                    ))}
                  </select>
                ) : varDef.type === 'text' ? (
                  <textarea
                    value={variables[varDef.name] || ''}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.value })}
                    rows={3}
                    className={`w-full px-4 py-2 rounded border ${inputBg}`}
                  />
                ) : (
                  <input
                    type={varDef.type === 'number' ? 'number' : 'text'}
                    value={variables[varDef.name] || ''}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.value })}
                    className={`w-full px-4 py-2 rounded border ${inputBg}`}
                  />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Run Button */}
      <div className="flex justify-end">
        <button
          onClick={handleRun}
          disabled={running}
          className={`px-6 py-3 rounded font-bold text-white ${running ? 'bg-gray-500 cursor-not-allowed' : buttonPrimary}`}
        >
          {running ? '⏳ Running...' : '▶️ Run Prompt'}
        </button>
      </div>

      {/* Run Error */}
      {runError && (
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {runError}
        </div>
      )}

      {/* Output */}
      {output && (
        <div className={`p-6 rounded-lg border ${cardBg}`}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className={`text-lg font-bold ${textPrimary}`}>
                ✨ Output
              </h3>
              {usage && (
                <p className={`text-xs mt-1 ${textMuted}`}>
                  Tokens: {usage.promptTokens} prompt + {usage.completionTokens} completion = {usage.totalTokens} total
                </p>
              )}
            </div>
            <div className="flex gap-2 flex-wrap justify-end">
              {hasDualOutput && (
                <>
                  <button
                    onClick={() => copySection('client-facing')}
                    className={`px-3 py-2 rounded font-semibold text-sm ${darkMode ? 'bg-green-700 hover:bg-green-600 text-white' : 'bg-green-100 hover:bg-green-200 text-green-800'}`}
                    title="Copy client-facing notes only"
                  >
                    📤 Copy Client Notes
                  </button>
                  <button
                    onClick={() => copySection('internal')}
                    className={`px-3 py-2 rounded font-semibold text-sm ${darkMode ? 'bg-yellow-700 hover:bg-yellow-600 text-white' : 'bg-yellow-100 hover:bg-yellow-200 text-yellow-800'}`}
                    title="Copy internal ticket notes only"
                  >
                    📝 Copy Internal Notes
                  </button>
                </>
              )}
              <button
                onClick={copyOutput}
                className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
              >
                📋 Copy All
              </button>
            </div>
          </div>
          {hasDualOutput && (
            <div className={`mb-4 p-3 rounded text-sm ${darkMode ? 'bg-blue-900/30 text-blue-300 border border-blue-700' : 'bg-blue-50 text-blue-700 border border-blue-200'}`}>
              💡 <strong>Tip:</strong> This output contains separate sections for client-facing and internal notes. Use the buttons above to copy each section individually.
            </div>
          )}
          <div className={`prose prose-sm max-w-none ${darkMode ? 'prose-invert [&_*]:text-gray-100 [&_code]:bg-gray-700 [&_code]:text-gray-100 [&_pre]:bg-gray-900 [&_pre]:text-gray-100' : ''}`}>
            <ReactMarkdown>{output}</ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
}
