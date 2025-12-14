const axios = require('axios');

/**
 * Main function to query Hybrid Analysis
 */
async function queryHybridAnalysis(indicator) {
  const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;

  if (!apiKey) {
    return {
      indicator,
      type: detectIndicatorType(indicator),
      hybridAnalysis: { error: 'Hybrid Analysis API key not configured' }
    };
  }

  const indicatorType = detectIndicatorType(indicator);

  const results = {
    indicator,
    type: indicatorType,
    hybridAnalysis: null
  };

  try {
    if (indicatorType === 'SHA1' || indicatorType === 'SHA256' || indicatorType === 'MD5') {
      results.hybridAnalysis = await queryHybridAnalysisHash(indicator, apiKey);
    } else if (indicatorType === 'URL') {
      results.hybridAnalysis = await queryHybridAnalysisUrl(indicator, apiKey);
    } else {
      results.hybridAnalysis = {
        found: false,
        error: `Unsupported indicator type: ${indicatorType}. Hybrid Analysis supports hashes (MD5, SHA1, SHA256) and URLs.`
      };
    }
  } catch (error) {
    results.hybridAnalysis = {
      found: false,
      error: error.message || 'Query failed',
      errorType: error.constructor?.name
    };

    if (error.response) {
      results.hybridAnalysis.apiStatus = error.response.status;
      results.hybridAnalysis.apiStatusText = error.response.statusText;
      results.hybridAnalysis.apiError = error.response.data;
    }
  }

  return results;
}

/**
 * Detect indicator type
 */
function detectIndicatorType(indicator) {
  const md5Regex = /^[a-fA-F0-9]{32}$/;
  const sha1Regex = /^[a-fA-F0-9]{40}$/;
  const sha256Regex = /^[a-fA-F0-9]{64}$/;
  const urlRegex = /^https?:\/\//;

  if (md5Regex.test(indicator)) return 'MD5';
  if (sha1Regex.test(indicator)) return 'SHA1';
  if (sha256Regex.test(indicator)) return 'SHA256';
  if (urlRegex.test(indicator)) return 'URL';
  return 'Unknown';
}

/**
 * Query Hybrid Analysis for hash lookups
 */
async function queryHybridAnalysisHash(hash, apiKey) {
  const url = `https://hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(hash)}`;

  const response = await axios.get(url, {
    headers: {
      'api-key': apiKey,
      'User-Agent': 'Falcon Sandbox'
    },
    timeout: 15000
  });

  const data = response.data;

  if (!data || !data.reports || !Array.isArray(data.reports) || data.reports.length === 0) {
    return {
      found: false,
      message: 'No analysis reports found for this hash'
    };
  }

  // Get the first report's ID to fetch full details
  const reportSummary = data.reports[0];
  const reportId = reportSummary.id;

  // Fetch full report details
  const reportResponse = await axios.get(
    `https://hybrid-analysis.com/api/v2/report/${reportId}/summary`,
    {
      headers: {
        'api-key': apiKey,
        'User-Agent': 'Falcon Sandbox'
      },
      timeout: 15000
    }
  );

  const latestReport = reportResponse.data;

  // Extract key information
  const verdict = latestReport.verdict || 'unknown';
  const threatScore = latestReport.threat_score || 0;
  const vxFamily = latestReport.vx_family || 'Unknown';
  const malwareFamily = latestReport.av_detect || 0;
  const environmentDescription = latestReport.environment_description || 'N/A';
  const submitName = latestReport.submit_name || 'N/A';
  const analysisStartTime = latestReport.analysis_start_time || 'N/A';
  const sha256 = latestReport.sha256 || hash;
  const jobId = latestReport.job_id || 'N/A';

  // Extract MITRE ATT&CK techniques
  const mitreTechniques = Array.isArray(latestReport.mitre_attcks) ? latestReport.mitre_attcks : [];

  // Extract network indicators
  const domains = Array.isArray(latestReport.domains) ? latestReport.domains : [];
  const compromisedHosts = Array.isArray(latestReport.compromised_hosts) ? latestReport.compromised_hosts : [];
  const contactedHosts = Array.isArray(latestReport.contacted_hosts) ? latestReport.contacted_hosts : [];

  // Extract processes
  const processes = Array.isArray(latestReport.processes) ? latestReport.processes : [];

  // Extract extracted files
  const extractedFiles = Array.isArray(latestReport.extracted_files) ? latestReport.extracted_files : [];

  return {
    found: true,
    verdict: verdict,
    threatScore: threatScore,
    confidenceScore: latestReport.threat_level || 0,
    detectedFamily: vxFamily,
    avDetect: malwareFamily,
    submitName: submitName,
    analysisDate: analysisStartTime,
    environment: environmentDescription,
    sha256: sha256,
    jobId: jobId,
    reportUrl: `https://www.hybrid-analysis.com/sample/${sha256}`,
    mitreTechniques: mitreTechniques.map(m => ({
      attackId: m.attck_id || 'N/A',
      tactic: m.tactic || 'N/A',
      technique: m.technique || 'N/A',
      maliciousIdentifiers: m.malicious_identifiers || []
    })),
    domains: domains,
    compromisedHosts: compromisedHosts,
    contactedHosts: contactedHosts,
    processes: processes.map(p => ({
      name: p.name || 'Unknown',
      pid: p.pid || 0,
      normalized_path: p.normalized_path || 'N/A'
    })).slice(0, 10),
    extractedFiles: extractedFiles.map(f => ({
      name: f.name || 'Unknown',
      fileSize: f.file_size || 0,
      sha256: f.sha256 || 'N/A',
      threatscore: f.threatscore || 0
    })).slice(0, 10),
    totalProcesses: processes.length,
    totalExtractedFiles: extractedFiles.length,
    totalDomains: domains.length,
    totalCompromisedHosts: compromisedHosts.length,
    raw: latestReport
  };
}

/**
 * Query Hybrid Analysis for URL lookups
 */
async function queryHybridAnalysisUrl(url, apiKey) {
  const apiUrl = `https://hybrid-analysis.com/api/v2/search/terms?url=${encodeURIComponent(url)}`;

  const response = await axios.get(apiUrl, {
    headers: {
      'api-key': apiKey,
      'User-Agent': 'Falcon Sandbox'
    },
    timeout: 15000
  });

  const data = response.data;

  if (!data || !data.result || data.result.length === 0) {
    return {
      found: false,
      message: 'No analysis reports found for this URL'
    };
  }

  const latestReport = data.result[0];

  const verdict = latestReport.verdict || 'unknown';
  const threatScore = latestReport.threat_score || 0;
  const vxFamily = latestReport.vx_family || 'Unknown';
  const environmentDescription = latestReport.environment_description || 'N/A';
  const submitName = latestReport.submit_name || 'N/A';
  const analysisStartTime = latestReport.analysis_start_time || 'N/A';
  const sha256 = latestReport.sha256 || 'N/A';
  const jobId = latestReport.job_id || 'N/A';

  const mitreTechniques = Array.isArray(latestReport.mitre_attcks) ? latestReport.mitre_attcks : [];
  const domains = Array.isArray(latestReport.domains) ? latestReport.domains : [];
  const compromisedHosts = Array.isArray(latestReport.compromised_hosts) ? latestReport.compromised_hosts : [];

  return {
    found: true,
    verdict: verdict,
    threatScore: threatScore,
    detectedFamily: vxFamily,
    submitName: submitName,
    analysisDate: analysisStartTime,
    environment: environmentDescription,
    sha256: sha256,
    jobId: jobId,
    reportUrl: sha256 !== 'N/A' ? `https://www.hybrid-analysis.com/sample/${sha256}` : 'N/A',
    mitreTechniques: mitreTechniques.map(m => ({
      attackId: m.attck_id || 'N/A',
      tactic: m.tactic || 'N/A',
      technique: m.technique || 'N/A'
    })),
    domains: domains,
    compromisedHosts: compromisedHosts,
    totalDomains: domains.length,
    totalCompromisedHosts: compromisedHosts.length,
    raw: latestReport
  };
}

module.exports = {
  queryHybridAnalysis
};
