// /api/HybridAnalysisLookup.js
const { app } = require('@azure/functions');
const axios = require('axios');

app.http('HybridAnalysisLookup', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log('Hybrid Analysis Lookup function triggered');

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      };
    }

    try {
      const body = await request.json();
      const { indicator } = body || {};

      if (!indicator) {
        return {
          status: 400,
          jsonBody: { error: 'Missing indicator field' }
        };
      }

      const hybridAnalysisApiKey = process.env.HYBRID_ANALYSIS_API_KEY;

      if (!hybridAnalysisApiKey) {
        return {
          status: 500,
          jsonBody: { error: 'Hybrid Analysis API key not configured' }
        };
      }

      const indicatorType = detectIndicatorType(indicator);
      context.log(`Detected indicator type: ${indicatorType} for ${indicator}`);

      let results = {
        indicator,
        type: indicatorType,
        hybridAnalysis: null
      };

      // Query Hybrid Analysis based on indicator type
      try {
        if (indicatorType === 'SHA1' || indicatorType === 'SHA256' || indicatorType === 'MD5') {
          context.log('Querying Hybrid Analysis for hash:', indicator);
          results.hybridAnalysis = await queryHybridAnalysisHash(indicator, hybridAnalysisApiKey, context);
        } else if (indicatorType === 'URL') {
          context.log('Querying Hybrid Analysis for URL:', indicator);
          results.hybridAnalysis = await queryHybridAnalysisUrl(indicator, hybridAnalysisApiKey, context);
        } else {
          results.hybridAnalysis = {
            found: false,
            error: `Unsupported indicator type: ${indicatorType}. Hybrid Analysis supports hashes (MD5, SHA1, SHA256) and URLs.`
          };
        }
        context.log('Hybrid Analysis query completed. Found:', results.hybridAnalysis?.found !== false);
      } catch (error) {
        context.log.error('Hybrid Analysis query error:', error.message);
        context.log.error('Error stack:', error.stack);

        // Create detailed error object
        const errorDetail = {
          found: false,
          error: error.message || 'Query failed',
          errorType: error.constructor?.name,
        };

        // Add axios-specific error details
        if (error.response) {
          errorDetail.apiStatus = error.response.status;
          errorDetail.apiStatusText = error.response.statusText;
          errorDetail.apiError = error.response.data;
        } else if (error.request) {
          errorDetail.requestError = 'No response received from Hybrid Analysis API';
        }

        results.hybridAnalysis = errorDetail;
      }

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: results
      };

    } catch (error) {
      context.log.error('CRITICAL ERROR in HybridAnalysisLookup:', error.message);
      context.log.error('Error stack:', error.stack);
      context.log.error('Error details:', JSON.stringify(error, null, 2));

      // Build detailed error response
      const errorResponse = {
        error: 'Failed to perform Hybrid Analysis lookup',
        details: error.message || 'Unknown error',
        errorType: error.constructor.name,
        stack: error.stack
      };

      // Add response details if it's an axios error
      if (error.response) {
        errorResponse.apiStatus = error.response.status;
        errorResponse.apiStatusText = error.response.statusText;
        errorResponse.apiData = error.response.data;
      }

      return {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: errorResponse
      };
    }
  }
});

/* ---------------------- helpers ---------------------- */

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
 * Query Hybrid Analysis API for hash lookups
 * Endpoint: POST https://www.hybrid-analysis.com/api/v2/search/hash
 */
async function queryHybridAnalysisHash(hash, apiKey, context) {
  try {
    context.log('Making request to Hybrid Analysis API for hash:', hash);
    context.log('API endpoint: https://www.hybrid-analysis.com/api/v2/search/hash');
    context.log('API key configured:', apiKey ? `Yes (${apiKey.substring(0, 8)}...)` : 'No');

    const response = await axios.post(
      'https://www.hybrid-analysis.com/api/v2/search/hash',
      `hash=${encodeURIComponent(hash)}`,
      {
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Falcon Sandbox'
        },
        timeout: 15000
      }
    );

    context.log('Hybrid Analysis API response status:', response.status);
    context.log('Response data length:', response.data?.length || 0);

    const data = response.data;

    // If no results found
    if (!data || data.length === 0) {
      return {
        found: false,
        message: 'No analysis reports found for this hash'
      };
    }

    // Get the most recent report
    const latestReport = data[0];

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
    const mitreTechniques = latestReport.mitre_attcks || [];

    // Extract network indicators
    const domains = latestReport.domains || [];
    const compromisedHosts = latestReport.compromised_hosts || [];
    const contacted_hosts = latestReport.contacted_hosts || [];

    // Extract processes
    const processes = latestReport.processes || [];

    // Extract extracted files
    const extractedFiles = latestReport.extracted_files || [];

    // Build normalized response
    return {
      found: true,
      verdict: verdict, // clean, suspicious, malicious
      threatScore: threatScore, // 0-100
      confidenceScore: latestReport.threat_level || 0,

      // Malware family
      detectedFamily: vxFamily,
      avDetect: malwareFamily,
      submitName: submitName,

      // Analysis metadata
      analysisDate: analysisStartTime,
      environment: environmentDescription,
      sha256: sha256,
      jobId: jobId,
      reportUrl: `https://www.hybrid-analysis.com/sample/${sha256}`,

      // MITRE ATT&CK
      mitreTechniques: mitreTechniques.map(m => ({
        attackId: m.attck_id || 'N/A',
        tactic: m.tactic || 'N/A',
        technique: m.technique || 'N/A',
        maliciousIdentifiers: m.malicious_identifiers || []
      })),

      // Network IoCs
      domains: domains,
      compromisedHosts: compromisedHosts,
      contactedHosts: contacted_hosts,

      // Process information
      processes: processes.map(p => ({
        name: p.name || 'Unknown',
        pid: p.pid || 0,
        normalized_path: p.normalized_path || 'N/A'
      })).slice(0, 10), // Limit to first 10

      // Extracted files
      extractedFiles: extractedFiles.map(f => ({
        name: f.name || 'Unknown',
        fileSize: f.file_size || 0,
        sha256: f.sha256 || 'N/A',
        threatscore: f.threatscore || 0
      })).slice(0, 10), // Limit to first 10

      // Additional metadata
      totalProcesses: processes.length,
      totalExtractedFiles: extractedFiles.length,
      totalDomains: domains.length,
      totalCompromisedHosts: compromisedHosts.length,

      // Raw data for advanced users
      raw: latestReport
    };

  } catch (error) {
    if (error.response) {
      const status = error.response.status;
      const errorData = error.response.data;

      if (status === 404) {
        return {
          found: false,
          message: 'Hash not found in Hybrid Analysis database'
        };
      } else if (status === 403) {
        throw new Error('Hybrid Analysis API authentication failed. Check your API key.');
      } else if (status === 429) {
        throw new Error('Hybrid Analysis API rate limit exceeded. Please try again later.');
      } else {
        throw new Error(`Hybrid Analysis API error (${status}): ${JSON.stringify(errorData)}`);
      }
    }
    throw new Error(`Hybrid Analysis hash query failed: ${error.message}`);
  }
}

/**
 * Query Hybrid Analysis API for URL lookups
 * Endpoint: POST https://www.hybrid-analysis.com/api/v2/search/terms
 */
async function queryHybridAnalysisUrl(url, apiKey, context) {
  try {
    context.log('Making request to Hybrid Analysis API for URL:', url);
    context.log('API endpoint: https://www.hybrid-analysis.com/api/v2/search/terms');
    context.log('API key configured:', apiKey ? `Yes (${apiKey.substring(0, 8)}...)` : 'No');

    // For URL searches, we use the terms endpoint with url field
    const response = await axios.post(
      'https://www.hybrid-analysis.com/api/v2/search/terms',
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Falcon Sandbox'
        },
        timeout: 15000
      }
    );

    context.log('Hybrid Analysis API response status:', response.status);
    context.log('Response data results length:', response.data?.result?.length || 0);

    const data = response.data;

    // If no results found
    if (!data || !data.result || data.result.length === 0) {
      return {
        found: false,
        message: 'No analysis reports found for this URL'
      };
    }

    // Get the most recent report
    const latestReport = data.result[0];

    // Extract key information similar to hash lookup
    const verdict = latestReport.verdict || 'unknown';
    const threatScore = latestReport.threat_score || 0;
    const vxFamily = latestReport.vx_family || 'Unknown';
    const environmentDescription = latestReport.environment_description || 'N/A';
    const submitName = latestReport.submit_name || 'N/A';
    const analysisStartTime = latestReport.analysis_start_time || 'N/A';
    const sha256 = latestReport.sha256 || 'N/A';
    const jobId = latestReport.job_id || 'N/A';

    // Extract MITRE ATT&CK techniques
    const mitreTechniques = latestReport.mitre_attcks || [];

    // Extract network indicators
    const domains = latestReport.domains || [];
    const compromisedHosts = latestReport.compromised_hosts || [];

    return {
      found: true,
      verdict: verdict,
      threatScore: threatScore,

      // Malware family
      detectedFamily: vxFamily,
      submitName: submitName,

      // Analysis metadata
      analysisDate: analysisStartTime,
      environment: environmentDescription,
      sha256: sha256,
      jobId: jobId,
      reportUrl: sha256 !== 'N/A' ? `https://www.hybrid-analysis.com/sample/${sha256}` : 'N/A',

      // MITRE ATT&CK
      mitreTechniques: mitreTechniques.map(m => ({
        attackId: m.attck_id || 'N/A',
        tactic: m.tactic || 'N/A',
        technique: m.technique || 'N/A'
      })),

      // Network IoCs
      domains: domains,
      compromisedHosts: compromisedHosts,
      totalDomains: domains.length,
      totalCompromisedHosts: compromisedHosts.length,

      // Raw data
      raw: latestReport
    };

  } catch (error) {
    if (error.response) {
      const status = error.response.status;
      const errorData = error.response.data;

      if (status === 404) {
        return {
          found: false,
          message: 'URL not found in Hybrid Analysis database'
        };
      } else if (status === 403) {
        throw new Error('Hybrid Analysis API authentication failed. Check your API key.');
      } else if (status === 429) {
        throw new Error('Hybrid Analysis API rate limit exceeded. Please try again later.');
      } else {
        throw new Error(`Hybrid Analysis API error (${status}): ${JSON.stringify(errorData)}`);
      }
    }
    throw new Error(`Hybrid Analysis URL query failed: ${error.message}`);
  }
}
