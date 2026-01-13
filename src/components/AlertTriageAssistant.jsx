// Alert Triage Assistant - AI-powered alert classification and IOC enrichment
import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';

// IOC extraction patterns
const IOC_PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  // IPv6 pattern: matches full, compressed (::), and IPv4-mapped forms
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  // GUID/UUID pattern: matches Azure AD user IDs, object IDs, etc.
  guid: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|ru|cn|jp|au|ca|info|biz|xyz|top|online|site|club|work|live|store|tech|app|dev|me|tv|cc|ws|pw|tk|ml|ga|cf|gq|email|link|click|download|zip|mov|support|help|cloud|host|world)\b/gi,
  url: /https?:\/\/[^\s<>"')\]]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  cve: /CVE-\d{4}-\d{4,}/gi
};

// Defang patterns for normalization
const DEFANG_PATTERNS = [
  { pattern: /\[\.?\]/g, replacement: '.' },
  { pattern: /hxxp/gi, replacement: 'http' },
  { pattern: /\[@\]/g, replacement: '@' },
  { pattern: /\[\.\]/g, replacement: '.' }
];

// Helper to refang IOCs
function refangIOC(ioc) {
  let refanged = ioc;
  DEFANG_PATTERNS.forEach(({ pattern, replacement }) => {
    refanged = refanged.replace(pattern, replacement);
  });
  return refanged;
}

// Extract IOCs from text
function extractIOCs(text) {
  const refangedText = refangIOC(text);
  const extracted = {
    ips: [],
    ipv6s: [],
    guids: [],
    domains: [],
    urls: [],
    md5s: [],
    sha1s: [],
    sha256s: [],
    emails: [],
    cves: []
  };

  // Extract IPv4 addresses
  const ipMatches = refangedText.match(IOC_PATTERNS.ipv4) || [];
  extracted.ips = [...new Set(ipMatches)].filter(ip => {
    // Filter out common private/local IPs
    return !ip.startsWith('10.') &&
           !ip.startsWith('192.168.') &&
           !ip.startsWith('172.16.') &&
           !ip.startsWith('127.') &&
           !ip.startsWith('0.');
  });

  // Extract IPv6 addresses
  const ipv6Matches = refangedText.match(IOC_PATTERNS.ipv6) || [];
  extracted.ipv6s = [...new Set(ipv6Matches)].filter(ip => {
    const lower = ip.toLowerCase();
    // Filter out loopback (::1), link-local (fe80::), and private (fc00::/7, fd00::/8)
    return lower !== '::1' &&
           !lower.startsWith('fe80:') &&
           !lower.startsWith('fc') &&
           !lower.startsWith('fd');
  });

  // Extract GUIDs/UUIDs (Azure AD user IDs, object IDs, etc.)
  const guidMatches = refangedText.match(IOC_PATTERNS.guid) || [];
  extracted.guids = [...new Set(guidMatches.map(g => g.toLowerCase()))];

  const urlMatches = refangedText.match(IOC_PATTERNS.url) || [];
  extracted.urls = [...new Set(urlMatches)];

  // Extract domains (exclude those already in URLs)
  const domainMatches = refangedText.match(IOC_PATTERNS.domain) || [];
  const urlDomains = extracted.urls.map(url => {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }).filter(Boolean);
  extracted.domains = [...new Set(domainMatches)]
    .filter(d => !urlDomains.includes(d.toLowerCase()))
    .filter(d => !d.match(/^\d+\.\d+\.\d+\.\d+$/)); // Filter out IPs

  // Hashes - ensure they're not substrings of longer hashes
  const sha256Matches = refangedText.match(IOC_PATTERNS.sha256) || [];
  extracted.sha256s = [...new Set(sha256Matches)];

  const sha1Matches = refangedText.match(IOC_PATTERNS.sha1) || [];
  extracted.sha1s = [...new Set(sha1Matches)]
    .filter(h => !extracted.sha256s.some(s => s.includes(h)));

  const md5Matches = refangedText.match(IOC_PATTERNS.md5) || [];
  extracted.md5s = [...new Set(md5Matches)]
    .filter(h => !extracted.sha1s.some(s => s.includes(h)) &&
                 !extracted.sha256s.some(s => s.includes(h)));

  const emailMatches = refangedText.match(IOC_PATTERNS.email) || [];
  extracted.emails = [...new Set(emailMatches)];

  const cveMatches = refangedText.match(IOC_PATTERNS.cve) || [];
  extracted.cves = [...new Set(cveMatches.map(c => c.toUpperCase()))];

  return extracted;
}

// Severity color helpers
const getSeverityColor = (severity, darkMode) => {
  const colors = {
    Critical: { bg: 'bg-red-600', text: 'text-white', border: 'border-red-500' },
    High: { bg: 'bg-orange-600', text: 'text-white', border: 'border-orange-500' },
    Medium: { bg: 'bg-yellow-500', text: 'text-gray-900', border: 'border-yellow-400' },
    Low: { bg: 'bg-blue-600', text: 'text-white', border: 'border-blue-500' },
    Informational: { bg: darkMode ? 'bg-gray-600' : 'bg-gray-500', text: 'text-white', border: 'border-gray-400' }
  };
  return colors[severity] || colors.Informational;
};

const getRiskColor = (risk, darkMode) => {
  const colors = {
    Critical: darkMode ? 'text-red-400' : 'text-red-600',
    High: darkMode ? 'text-orange-400' : 'text-orange-600',
    Medium: darkMode ? 'text-yellow-400' : 'text-yellow-600',
    Low: darkMode ? 'text-blue-400' : 'text-blue-600'
  };
  return colors[risk] || (darkMode ? 'text-gray-400' : 'text-gray-600');
};

// Section Card Component
function SectionCard({ title, icon, children, darkMode, defaultExpanded = true, copyContent = null }) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (copyContent) {
      navigator.clipboard.writeText(copyContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className={`rounded-lg border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} overflow-hidden`}>
      <div
        className={`flex items-center justify-between px-4 py-3 cursor-pointer ${darkMode ? 'hover:bg-gray-750' : 'hover:bg-gray-50'}`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          <span>{icon}</span>
          <h3 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
        </div>
        <div className="flex items-center gap-2">
          {copyContent && (
            <button
              onClick={(e) => { e.stopPropagation(); handleCopy(); }}
              className={`px-2 py-1 text-xs rounded ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          )}
          <motion.span
            animate={{ rotate: expanded ? 180 : 0 }}
            transition={{ duration: 0.2 }}
            className={darkMode ? 'text-gray-400' : 'text-gray-600'}
          >
            ▼
          </motion.span>
        </div>
      </div>
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className={`px-4 pb-4 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// IOC Badge Component
function IOCBadge({ type, count, icon, darkMode }) {
  if (count === 0) return null;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-700'}`}>
      <span>{icon}</span>
      <span>{type}: {count}</span>
    </span>
  );
}

// Splash Screen Component
function SplashScreen({ onComplete, darkMode }) {
  useEffect(() => {
    const timer = setTimeout(onComplete, 3000);
    return () => clearTimeout(timer);
  }, [onComplete]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ backgroundColor: darkMode ? 'rgba(17, 24, 39, 0.95)' : 'rgba(255, 255, 255, 0.95)' }}
    >
      <div className="text-center p-8">
        <motion.div
          initial={{ scale: 0.5 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', damping: 10 }}
          className="text-6xl mb-6"
        >
          🚨
        </motion.div>
        <h1 className={`text-3xl font-bold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
          Alert Triage Assistant
        </h1>
        <p className={`text-lg mb-6 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
          Paste. Extract. Enrich. Classify.
        </p>
        <div className={`text-sm ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
          Powered by AI + Multi-Source Threat Intelligence
        </div>
      </div>
    </motion.div>
  );
}

// Main Component
export default function AlertTriageAssistant({ darkMode }) {
  const { isAuthenticated, isMsalAvailable, login, getSentinelWorkspaces, getSentinelIncident, getIncidentLogs, isLoading: authLoading } = useAuth();
  const [showSplash, setShowSplash] = useState(true);
  const [loginError, setLoginError] = useState(null);

  // Sentinel workspace/incident state
  const [workspaces, setWorkspaces] = useState([]);
  const [selectedWorkspace, setSelectedWorkspace] = useState('');
  const [incidentNumber, setIncidentNumber] = useState('');
  const [workspacesLoading, setWorkspacesLoading] = useState(false);
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [workspacesError, setWorkspacesError] = useState(null);

  // Form state
  const [rawInput, setRawInput] = useState('');
  const [inputFormat, setInputFormat] = useState('auto');

  // Extracted IOCs state
  const [extractedIOCs, setExtractedIOCs] = useState(null);
  const [selectedIOCs, setSelectedIOCs] = useState({});

  // Enrichment state
  const [enrichmentResults, setEnrichmentResults] = useState(null);
  const [enrichmentProgress, setEnrichmentProgress] = useState({ current: 0, total: 0 });

  // Classification state
  const [classification, setClassification] = useState(null);

  // Loading/error states
  const [loading, setLoading] = useState({ extract: false, enrich: false, classify: false });
  const [error, setError] = useState(null);

  // Load Sentinel workspaces on mount
  useEffect(() => {
    async function loadWorkspaces() {
      if (!isAuthenticated) return;

      setWorkspacesLoading(true);
      setWorkspacesError(null);
      try {
        // Use progress callback to show workspaces as they're discovered
        const ws = await getSentinelWorkspaces((progressWorkspaces) => {
          // Sort alphabetically by name as they load
          const sorted = [...progressWorkspaces].sort((a, b) =>
            (a.name || '').localeCompare(b.name || '')
          );
          setWorkspaces(sorted);
        });
        // Sort final results alphabetically by name
        const sortedWorkspaces = [...ws].sort((a, b) =>
          (a.name || '').localeCompare(b.name || '')
        );
        setWorkspaces(sortedWorkspaces);
        // Auto-select first workspace if only one
        if (sortedWorkspaces.length === 1) {
          setSelectedWorkspace(sortedWorkspaces[0].id);
        }
      } catch (err) {
        console.error('Failed to load workspaces:', err);
        setWorkspacesError(err.message || 'Failed to load workspaces');
      } finally {
        setWorkspacesLoading(false);
      }
    }

    loadWorkspaces();
  }, [isAuthenticated, getSentinelWorkspaces]);

  // Fetch incident from Sentinel
  const fetchIncident = useCallback(async () => {
    if (!selectedWorkspace || !incidentNumber.trim()) {
      setError('Please select a workspace and enter an incident number');
      return;
    }

    setIncidentLoading(true);
    setError(null);

    try {
      // Get incident details, alerts, and entities
      const { incident, alerts, entities } = await getSentinelIncident(selectedWorkspace, incidentNumber.trim());

      // Get workspace customerId for Log Analytics queries
      const workspace = workspaces.find(w => w.id === selectedWorkspace);

      // Try to get additional logs from Log Analytics
      let logs = null;
      if (workspace?.customerId) {
        try {
          logs = await getIncidentLogs(workspace.customerId, incidentNumber.trim());
        } catch (logErr) {
          console.warn('Could not fetch Log Analytics data:', logErr);
        }
      }

      // Format the incident data as JSON for the raw input
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

      // Set the raw input with formatted JSON
      setRawInput(JSON.stringify(incidentData, null, 2));
      setInputFormat('json');

    } catch (err) {
      console.error('Failed to fetch incident:', err);
      setError(`Failed to fetch incident: ${err.message}`);
    } finally {
      setIncidentLoading(false);
    }
  }, [selectedWorkspace, incidentNumber, workspaces, getSentinelIncident, getIncidentLogs]);

  // Styling helpers
  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900';
  const subText = darkMode ? 'text-gray-400' : 'text-gray-600';

  // Extract IOCs from input
  const handleExtract = useCallback(() => {
    setLoading(prev => ({ ...prev, extract: true }));
    setError(null);
    setEnrichmentResults(null);
    setClassification(null);

    try {
      const iocs = extractIOCs(rawInput);
      setExtractedIOCs(iocs);
      setSelectedIOCs(iocs); // Select all by default

      const totalCount = Object.values(iocs).flat().length;
      if (totalCount === 0) {
        setError('No IOCs detected in the provided content. Try pasting an alert with IPs, domains, URLs, hashes, or email addresses.');
      }
    } catch (err) {
      setError(`Extraction failed: ${err.message}`);
    } finally {
      setLoading(prev => ({ ...prev, extract: false }));
    }
  }, [rawInput]);

  // Toggle individual IOC selection
  const toggleIOC = (type, value) => {
    setSelectedIOCs(prev => ({
      ...prev,
      [type]: prev[type]?.includes(value)
        ? prev[type].filter(v => v !== value)
        : [...(prev[type] || []), value]
    }));
  };

  // Bulk enrich IOCs
  const handleEnrich = useCallback(async () => {
    const allIndicators = [
      ...(selectedIOCs.ips || []).map(v => ({ value: v, type: 'ip' })),
      ...(selectedIOCs.ipv6s || []).map(v => ({ value: v, type: 'ipv6' })),
      ...(selectedIOCs.domains || []).map(v => ({ value: v, type: 'domain' })),
      ...(selectedIOCs.urls || []).map(v => ({ value: v, type: 'url' })),
      ...(selectedIOCs.sha256s || []).map(v => ({ value: v, type: 'sha256' })),
      ...(selectedIOCs.sha1s || []).map(v => ({ value: v, type: 'sha1' })),
      ...(selectedIOCs.md5s || []).map(v => ({ value: v, type: 'md5' }))
    ];

    if (allIndicators.length === 0) {
      setError('No IOCs selected for enrichment.');
      return;
    }

    setLoading(prev => ({ ...prev, enrich: true }));
    setError(null);
    setEnrichmentProgress({ current: 0, total: allIndicators.length });

    try {
      const results = [];
      // Process in batches of 3 to avoid rate limiting
      const batchSize = 3;
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
              const data = await resp.json();
              return { indicator: value, type, ...data };
            } catch (err) {
              return { indicator: value, type, error: err.message };
            }
          })
        );
        results.push(...batchResults);
        setEnrichmentProgress({ current: results.length, total: allIndicators.length });

        // Small delay between batches
        if (i + batchSize < allIndicators.length) {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      }

      setEnrichmentResults(results);
    } catch (err) {
      setError(`Enrichment failed: ${err.message}`);
    } finally {
      setLoading(prev => ({ ...prev, enrich: false }));
    }
  }, [selectedIOCs]);

  // Summarize enrichment for classification
  const summarizeEnrichment = useCallback(() => {
    if (!enrichmentResults) return {};

    const summary = {
      highRiskIOCs: [],
      maliciousIndicators: [],
      suspiciousIndicators: [],
      cleanIndicators: [],
      enrichmentDetails: {}
    };

    enrichmentResults.forEach(result => {
      const { indicator, type, virusTotal, abuseIPDB, greyNoise, alienVault } = result;
      let risk = 'unknown';

      // Assess risk based on available data
      if (virusTotal) {
        if (virusTotal.malicious > 5) {
          risk = 'malicious';
          summary.maliciousIndicators.push({ indicator, detections: virusTotal.malicious });
        } else if (virusTotal.malicious > 0 || virusTotal.suspicious > 0) {
          risk = 'suspicious';
          summary.suspiciousIndicators.push({ indicator, detections: virusTotal.malicious + virusTotal.suspicious });
        }
      }

      if (abuseIPDB && abuseIPDB.abuseScore > 50) {
        risk = 'malicious';
        if (!summary.maliciousIndicators.find(i => i.indicator === indicator)) {
          summary.maliciousIndicators.push({ indicator, abuseScore: abuseIPDB.abuseScore });
        }
      }

      if (alienVault && alienVault.pulseCount > 0) {
        if (risk === 'unknown') risk = 'suspicious';
        summary.suspiciousIndicators.push({ indicator, pulses: alienVault.pulseCount });
      }

      if (risk === 'unknown' && virusTotal && virusTotal.malicious === 0) {
        risk = 'clean';
        summary.cleanIndicators.push(indicator);
      }

      if (risk === 'malicious' || risk === 'suspicious') {
        summary.highRiskIOCs.push(indicator);
      }

      summary.enrichmentDetails[indicator] = {
        type,
        virusTotal: virusTotal ? { malicious: virusTotal.malicious, suspicious: virusTotal.suspicious } : null,
        abuseIPDB: abuseIPDB ? { score: abuseIPDB.abuseScore, reports: abuseIPDB.totalReports } : null,
        greyNoise: greyNoise ? { classification: greyNoise.classification, noise: greyNoise.noise } : null,
        alienVault: alienVault ? { pulses: alienVault.pulseCount } : null
      };
    });

    return summary;
  }, [enrichmentResults]);

  // Classify alert with AI
  const handleClassify = useCallback(async () => {
    setLoading(prev => ({ ...prev, classify: true }));
    setError(null);

    try {
      const enrichmentSummary = summarizeEnrichment();

      const resp = await fetch('/api/AlertTriage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alertContent: rawInput,
          extractedIOCs: selectedIOCs,
          enrichmentSummary,
          temperature: 0.2
        })
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.error || `Classification failed: ${resp.status}`);
      }

      const data = await resp.json();
      setClassification(data.triage);
    } catch (err) {
      setError(`Classification failed: ${err.message}`);
    } finally {
      setLoading(prev => ({ ...prev, classify: false }));
    }
  }, [rawInput, selectedIOCs, summarizeEnrichment]);

  // Reset all state
  const handleReset = () => {
    setRawInput('');
    setExtractedIOCs(null);
    setSelectedIOCs({});
    setEnrichmentResults(null);
    setClassification(null);
    setError(null);
  };

  // IOC type configurations
  const iocTypes = [
    { key: 'ips', label: 'IPv4 Addresses', icon: '🌐' },
    { key: 'ipv6s', label: 'IPv6 Addresses', icon: '🌍' },
    { key: 'guids', label: 'GUIDs/User IDs', icon: '🆔' },
    { key: 'domains', label: 'Domains', icon: '🔗' },
    { key: 'urls', label: 'URLs', icon: '🔍' },
    { key: 'sha256s', label: 'SHA-256', icon: '🔐' },
    { key: 'sha1s', label: 'SHA-1', icon: '🔑' },
    { key: 'md5s', label: 'MD5', icon: '#' },
    { key: 'emails', label: 'Emails', icon: '📧' },
    { key: 'cves', label: 'CVEs', icon: '🛡️' }
  ];

  const totalSelectedIOCs = Object.values(selectedIOCs).flat().length;

  // Splash screen
  if (showSplash) {
    return <SplashScreen onComplete={() => setShowSplash(false)} darkMode={darkMode} />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className={`rounded-lg border ${cardBg} p-6`}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className={`text-xl font-bold flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              <span>🚨</span> Alert Triage Assistant
            </h2>
            <p className={`text-sm ${subText}`}>
              Paste raw alerts for automatic IOC extraction, enrichment, and AI classification
            </p>
          </div>
          {(extractedIOCs || classification) && (
            <button
              onClick={handleReset}
              className={`px-4 py-2 rounded-lg text-sm font-medium ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
            >
              Start Over
            </button>
          )}
        </div>

        {/* Error Display */}
        {error && (
          <div className="mb-4 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500">
            {error}
          </div>
        )}

        {/* Step 1: Input */}
        {!classification && (
          <div className="space-y-4">
            {/* Sentinel Workspace & Incident Lookup */}
            {isMsalAvailable && (
              <div className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-750 border-gray-600' : 'bg-blue-50 border-blue-200'}`}>
                <h4 className={`font-semibold mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  <span>🔗</span> Fetch from Microsoft Sentinel
                </h4>

                {/* Show login prompt if not authenticated */}
                {!isAuthenticated ? (
                  <div className="text-center py-4">
                    {loginError && (
                      <div className="mb-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-sm">
                        {loginError}
                      </div>
                    )}
                    <p className={`mb-4 text-sm ${subText}`}>
                      Sign in with your Microsoft account to fetch incidents directly from Sentinel workspaces.
                    </p>
                    <button
                      onClick={async () => {
                        setLoginError(null);
                        try {
                          await login();
                        } catch (err) {
                          setLoginError(err.message || 'Login failed. Please try again.');
                        }
                      }}
                      disabled={authLoading}
                      className={`px-6 py-2 rounded-lg font-medium transition-colors ${
                        authLoading
                          ? darkMode ? 'bg-gray-700 text-gray-500' : 'bg-gray-200 text-gray-400'
                          : 'bg-blue-600 hover:bg-blue-700 text-white'
                      }`}
                    >
                      {authLoading ? (
                        <span className="flex items-center gap-2">
                          <span className="animate-spin">⏳</span> Signing in...
                        </span>
                      ) : (
                        '🔐 Sign in with Microsoft'
                      )}
                    </button>
                  </div>
                ) : (
                  <>
                    {workspacesError && (
                      <div className="mb-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-sm">
                        {workspacesError}
                      </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      {/* Workspace Dropdown */}
                      <div className="md:col-span-1">
                        <label className={`block text-xs font-medium mb-1 ${subText}`}>
                          Sentinel Workspace
                        </label>
                        <select
                          value={selectedWorkspace}
                          onChange={(e) => setSelectedWorkspace(e.target.value)}
                          disabled={workspacesLoading || workspaces.length === 0}
                          className={`w-full px-3 py-2 rounded-lg border text-sm ${inputBg} ${workspacesLoading ? 'opacity-50' : ''}`}
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

                      {/* Incident Number Input */}
                      <div className="md:col-span-1">
                        <label className={`block text-xs font-medium mb-1 ${subText}`}>
                          Incident Number
                        </label>
                        <input
                          type="text"
                          value={incidentNumber}
                          onChange={(e) => setIncidentNumber(e.target.value)}
                          placeholder="e.g., 12345"
                          className={`w-full px-3 py-2 rounded-lg border text-sm ${inputBg}`}
                        />
                      </div>

                      {/* Fetch Button */}
                      <div className="md:col-span-1 flex items-end">
                        <button
                          onClick={fetchIncident}
                          disabled={!selectedWorkspace || !incidentNumber.trim() || incidentLoading || authLoading}
                          className={`w-full py-2 px-4 rounded-lg font-medium text-sm transition-colors ${
                            selectedWorkspace && incidentNumber.trim() && !incidentLoading && !authLoading
                              ? 'bg-blue-600 hover:bg-blue-700 text-white'
                              : darkMode
                              ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                              : 'bg-gray-200 text-gray-400 cursor-not-allowed'
                          }`}
                        >
                          {incidentLoading ? (
                            <span className="flex items-center justify-center gap-2">
                              <span className="animate-spin">⏳</span> Fetching...
                            </span>
                          ) : (
                            '📥 Fetch Incident'
                          )}
                        </button>
                      </div>
                    </div>

                    <p className={`mt-2 text-xs ${subText}`}>
                      Select a workspace and enter an incident number to automatically fetch alert details, entities, and related logs.
                    </p>
                  </>
                )}
              </div>
            )}

            {/* Divider */}
            {isMsalAvailable && (
              <div className="flex items-center gap-4">
                <div className={`flex-1 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}></div>
                <span className={`text-sm ${subText}`}>or paste manually</span>
                <div className={`flex-1 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}></div>
              </div>
            )}

            <div>
              <label className={`block text-sm font-semibold mb-2 ${subText}`}>
                Alert Source Format
              </label>
              <select
                value={inputFormat}
                onChange={(e) => setInputFormat(e.target.value)}
                className={`w-full md:w-auto px-3 py-2 rounded-lg border ${inputBg}`}
              >
                <option value="auto">Auto-Detect</option>
                <option value="json">JSON (Sentinel/Defender)</option>
                <option value="email">Email Forward</option>
                <option value="siem">SIEM Export</option>
                <option value="plaintext">Plain Text</option>
              </select>
            </div>

            <div>
              <label className={`block text-sm font-semibold mb-2 ${subText}`}>
                Paste Raw Alert
              </label>
              <textarea
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                rows={10}
                placeholder="Paste the raw alert content here (JSON, email body, SIEM export, etc.)...

Use Link to LA to grab all alert details and paste them here.

Examples of what to paste:
- Microsoft Sentinel alert JSON
- Defender for Endpoint alert details
- Forwarded phishing email headers + body
- Any text containing IPs, domains, URLs, or file hashes"
                className={`w-full px-4 py-3 rounded-lg border font-mono text-sm ${inputBg} placeholder-gray-500`}
              />
            </div>

            <button
              onClick={handleExtract}
              disabled={!rawInput.trim() || loading.extract}
              className={`w-full py-3 px-6 rounded-lg font-semibold transition-colors ${
                rawInput.trim() && !loading.extract
                  ? 'bg-blue-600 hover:bg-blue-700 text-white'
                  : darkMode
                  ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                  : 'bg-gray-200 text-gray-400 cursor-not-allowed'
              }`}
            >
              {loading.extract ? 'Extracting...' : '🔎 Extract IOCs'}
            </button>
          </div>
        )}
      </div>

      {/* Step 2: Extracted IOCs */}
      {extractedIOCs && !classification && (
        <div className={`rounded-lg border ${cardBg} p-6`}>
          <h3 className={`text-lg font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            📋 Extracted IOCs
          </h3>

          {/* IOC Summary Badges */}
          <div className="flex flex-wrap gap-2 mb-4">
            {iocTypes.map(({ key, label, icon }) => (
              <IOCBadge
                key={key}
                type={label}
                count={extractedIOCs[key]?.length || 0}
                icon={icon}
                darkMode={darkMode}
              />
            ))}
          </div>

          {/* IOC Selection Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
            {iocTypes.map(({ key, label, icon }) => {
              const iocs = extractedIOCs[key] || [];
              if (iocs.length === 0) return null;

              return (
                <div
                  key={key}
                  className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-750 border-gray-600' : 'bg-gray-50 border-gray-200'}`}
                >
                  <h4 className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                    <span>{icon}</span> {label} ({iocs.length})
                  </h4>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {iocs.map((value, idx) => (
                      <label
                        key={idx}
                        className={`flex items-center gap-2 text-sm cursor-pointer ${darkMode ? 'text-gray-300 hover:text-white' : 'text-gray-700 hover:text-gray-900'}`}
                      >
                        <input
                          type="checkbox"
                          checked={selectedIOCs[key]?.includes(value) || false}
                          onChange={() => toggleIOC(key, value)}
                          className="rounded"
                        />
                        <span className="font-mono truncate" title={value}>
                          {value.length > 40 ? value.substring(0, 40) + '...' : value}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Enrichment Progress */}
          {loading.enrich && (
            <div className="mb-4">
              <div className={`text-sm mb-2 ${subText}`}>
                Enriching IOCs... {enrichmentProgress.current}/{enrichmentProgress.total}
              </div>
              <div className={`w-full h-2 rounded-full ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                <div
                  className="h-full rounded-full bg-blue-600 transition-all"
                  style={{ width: `${(enrichmentProgress.current / enrichmentProgress.total) * 100}%` }}
                />
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={handleEnrich}
              disabled={totalSelectedIOCs === 0 || loading.enrich}
              className={`flex-1 py-3 px-6 rounded-lg font-semibold transition-colors ${
                totalSelectedIOCs > 0 && !loading.enrich
                  ? 'bg-green-600 hover:bg-green-700 text-white'
                  : darkMode
                  ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                  : 'bg-gray-200 text-gray-400 cursor-not-allowed'
              }`}
            >
              {loading.enrich ? 'Enriching...' : `🔍 Enrich ${totalSelectedIOCs} IOCs`}
            </button>

            {enrichmentResults && (
              <button
                onClick={handleClassify}
                disabled={loading.classify}
                className={`flex-1 py-3 px-6 rounded-lg font-semibold transition-colors ${
                  !loading.classify
                    ? 'bg-purple-600 hover:bg-purple-700 text-white'
                    : darkMode
                    ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
                    : 'bg-gray-200 text-gray-400 cursor-not-allowed'
                }`}
              >
                {loading.classify ? 'Classifying...' : '🤖 AI Classification'}
              </button>
            )}
          </div>
        </div>
      )}

      {/* Step 3: Enrichment Results Summary */}
      {enrichmentResults && !classification && (
        <div className={`rounded-lg border ${cardBg} p-6`}>
          <h3 className={`text-lg font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            🔬 Enrichment Results
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {enrichmentResults.map((result, idx) => {
              const { indicator, type, virusTotal, abuseIPDB, greyNoise, alienVault, error: resultError } = result;
              const isMalicious = (virusTotal?.malicious > 5) || (abuseIPDB?.abuseScore > 50);
              const isSuspicious = (virusTotal?.malicious > 0) || (virusTotal?.suspicious > 0) || (alienVault?.pulseCount > 0);

              return (
                <div
                  key={idx}
                  className={`p-4 rounded-lg border ${
                    isMalicious
                      ? darkMode ? 'bg-red-900/30 border-red-500/50' : 'bg-red-50 border-red-200'
                      : isSuspicious
                      ? darkMode ? 'bg-yellow-900/30 border-yellow-500/50' : 'bg-yellow-50 border-yellow-200'
                      : darkMode ? 'bg-gray-750 border-gray-600' : 'bg-gray-50 border-gray-200'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className={`font-mono text-sm break-all ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                      {indicator}
                    </span>
                    <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'}`}>
                      {type}
                    </span>
                  </div>

                  {resultError ? (
                    <p className="text-red-500 text-sm">{resultError}</p>
                  ) : (
                    <div className={`text-xs space-y-1 ${subText}`}>
                      {virusTotal && (
                        <div className={virusTotal.malicious > 0 ? 'text-red-500' : ''}>
                          VT: {virusTotal.malicious} malicious, {virusTotal.suspicious} suspicious
                        </div>
                      )}
                      {abuseIPDB && (
                        <div className={abuseIPDB.abuseScore > 50 ? 'text-red-500' : ''}>
                          AbuseIPDB: {abuseIPDB.abuseScore}% abuse score ({abuseIPDB.totalReports} reports)
                        </div>
                      )}
                      {greyNoise && !greyNoise.error && (
                        <div>GreyNoise: {greyNoise.classification || 'unknown'}</div>
                      )}
                      {alienVault && alienVault.pulseCount > 0 && (
                        <div className="text-yellow-500">AlienVault: {alienVault.pulseCount} pulses</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Step 4: AI Classification Results */}
      {classification && (
        <div className="space-y-4">
          {/* Severity & Category Header */}
          <div className={`rounded-lg border ${cardBg} p-6`}>
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
              <div>
                <h3 className={`text-lg font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  🤖 AI Classification Results
                </h3>
                <p className={`text-sm ${subText}`}>
                  Based on alert content and {Object.values(selectedIOCs).flat().length} enriched IOCs
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span
                  className={`px-4 py-2 rounded-full font-bold ${getSeverityColor(classification.severity, darkMode).bg} ${getSeverityColor(classification.severity, darkMode).text}`}
                >
                  {classification.severity}
                </span>
                <span className={`text-sm ${subText}`}>
                  {classification.confidence}% confidence
                </span>
              </div>
            </div>

            {/* Category & MITRE */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <div className={`p-4 rounded-lg ${darkMode ? 'bg-gray-750' : 'bg-gray-50'}`}>
                <h4 className={`font-semibold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  📁 Category
                </h4>
                <p className="text-lg font-bold text-blue-500">{classification.category}</p>
              </div>
              <div className={`p-4 rounded-lg ${darkMode ? 'bg-gray-750' : 'bg-gray-50'}`}>
                <h4 className={`font-semibold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  🎯 MITRE ATT&CK
                </h4>
                <div className="flex flex-wrap gap-1">
                  {classification.mitreTactics?.length > 0 ? (
                    classification.mitreTactics.map((tactic, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 bg-purple-600 text-white rounded text-xs font-medium"
                        title={tactic.techniques?.join(', ')}
                      >
                        {tactic.id}: {tactic.name}
                      </span>
                    ))
                  ) : (
                    <span className={subText}>No tactics identified</span>
                  )}
                </div>
              </div>
            </div>

            {/* Summary */}
            <div className={`p-4 rounded-lg mb-6 ${darkMode ? 'bg-gray-750' : 'bg-gray-50'}`}>
              <h4 className={`font-semibold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                📝 Summary
              </h4>
              <p className={darkMode ? 'text-gray-300' : 'text-gray-700'}>{classification.summary}</p>
            </div>
          </div>

          {/* Investigation Steps */}
          <SectionCard
            title="Investigation Steps"
            icon="🔍"
            darkMode={darkMode}
            copyContent={classification.investigationSteps?.join('\n')}
          >
            <ol className="list-decimal list-inside space-y-2">
              {classification.investigationSteps?.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ol>
          </SectionCard>

          {/* KQL Queries */}
          {classification.kqlQueries?.length > 0 && (
            <SectionCard title="KQL Queries" icon="💻" darkMode={darkMode}>
              <div className="space-y-4">
                {classification.kqlQueries.map((kql, idx) => (
                  <div key={idx}>
                    <h5 className={`font-medium mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                      {kql.purpose}
                    </h5>
                    <pre className={`p-3 rounded-lg text-sm overflow-x-auto ${darkMode ? 'bg-gray-900 text-green-400' : 'bg-gray-100 text-gray-800'}`}>
                      {kql.query}
                    </pre>
                  </div>
                ))}
              </div>
            </SectionCard>
          )}

          {/* Containment Recommendations */}
          {classification.containmentRecommendations?.length > 0 && (
            <SectionCard
              title="Containment Recommendations"
              icon="🛑"
              darkMode={darkMode}
              copyContent={classification.containmentRecommendations?.join('\n')}
            >
              <ul className="list-disc list-inside space-y-1">
                {classification.containmentRecommendations.map((rec, idx) => (
                  <li key={idx}>{rec}</li>
                ))}
              </ul>
            </SectionCard>
          )}

          {/* IOC Risk Assessment */}
          {classification.iocRiskAssessment?.length > 0 && (
            <SectionCard title="IOC Risk Assessment" icon="⚠️" darkMode={darkMode}>
              <div className="space-y-2">
                {classification.iocRiskAssessment.map((ioc, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg ${darkMode ? 'bg-gray-750' : 'bg-gray-50'}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-mono text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                        {ioc.indicator}
                      </span>
                      <span className={`font-bold ${getRiskColor(ioc.risk, darkMode)}`}>
                        {ioc.risk}
                      </span>
                    </div>
                    <p className={`text-sm ${subText}`}>{ioc.reason}</p>
                  </div>
                ))}
              </div>
            </SectionCard>
          )}

          {/* False Positive Indicators */}
          {classification.falsePositiveIndicators?.length > 0 && (
            <SectionCard title="Potential False Positive Indicators" icon="✅" darkMode={darkMode} defaultExpanded={false}>
              <ul className="list-disc list-inside space-y-1">
                {classification.falsePositiveIndicators.map((indicator, idx) => (
                  <li key={idx}>{indicator}</li>
                ))}
              </ul>
            </SectionCard>
          )}
        </div>
      )}
    </div>
  );
}
