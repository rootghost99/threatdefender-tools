// ThreatIntelLookup.js
// Azure Functions v4 (CommonJS) + axios
// POST { "indicator": "<ip|domain|url|sha1|sha256>" }

const { app } = require('@azure/functions');
const axios = require('axios');

// axios defaults
axios.defaults.timeout = 12000;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

app.http('ThreatIntelLookup', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log('Threat Intel Lookup function triggered');

    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS };
    }

    let indicator = null;

    try {
      // Safer body parsing
      const raw = await request.text();
      let body = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch { /* noop */ }

      indicator = (body?.indicator ?? '').toString().trim();
      if (!indicator) {
        return {
          status: 400,
          headers: { ...CORS, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Missing indicator field' }
        };
      }

      const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
      const aipdbApiKey = process.env.ABUSEIPDB_API_KEY;
      const urlscanApiKey = process.env.URLSCAN_API_KEY;
      const greynoiseApiKey = process.env.GREYNOISE_API_KEY;
      const shodanApiKey = process.env.SHODAN_API_KEY;
      const otxApiKey = process.env.ALIENVAULT_OTX_API_KEY;

      const indicatorType = detectIndicatorType(indicator);

      const results = {
        indicator,
        type: indicatorType,
        virusTotal: null,
        abuseIPDB: null,
        urlScan: null,
        greyNoise: null,
        shodan: null,
        alienVault: null
      };

      // VirusTotal
      if (vtApiKey) {
        try {
          context.log('Querying VirusTotal for:', indicator);
          results.virusTotal = await queryVirusTotal(indicator, indicatorType, vtApiKey);
        } catch (error) {
          context.log.error('VirusTotal error:', error.message);
          results.virusTotal = { error: error.message };
        }
      }

      // AbuseIPDB (IP only)
      if (indicatorType === 'IP' && aipdbApiKey) {
        try {
          context.log('Querying AbuseIPDB for:', indicator);
          results.abuseIPDB = await queryAbuseIPDB(indicator, aipdbApiKey);
        } catch (error) {
          context.log.error('AbuseIPDB error:', error.message);
          results.abuseIPDB = { error: error.message };
        }
      }

      // URLScan (URL or Domain)
      if ((indicatorType === 'URL' || indicatorType === 'Domain') && urlscanApiKey) {
        try {
          context.log('Querying URLScan for:', indicator);
          results.urlScan = await queryURLScan(indicator, indicatorType, urlscanApiKey);
        } catch (error) {
          context.log.error('URLScan error:', error.message);
          results.urlScan = { error: error.message };
        }
      }

      // GreyNoise (IP only)
      if (indicatorType === 'IP' && greynoiseApiKey) {
        try {
          context.log('Querying GreyNoise for:', indicator);
          results.greyNoise = await queryGreyNoise(indicator, greynoiseApiKey);
        } catch (error) {
          context.log.error('GreyNoise error:', error.message);
          results.greyNoise = { error: error.message };
        }
      }

      // Shodan (IP only)
      if (indicatorType === 'IP' && shodanApiKey) {
        try {
          context.log('Querying Shodan for:', indicator);
          results.shodan = await queryShodan(indicator, shodanApiKey);
        } catch (error) {
          context.log.error('Shodan error:', error.message);
          results.shodan = { error: error.message };
        }
      }

      // AlienVault OTX
      if (otxApiKey) {
        try {
          context.log('Querying AlienVault OTX for:', indicator);
          results.alienVault = await queryAlienVault(indicator, indicatorType, otxApiKey);
        } catch (error) {
          context.log.error('AlienVault OTX error:', error.message);
          results.alienVault = { error: error.message };
        }
      }

      context.log('All queries complete');
      return {
        status: 200,
        headers: { ...CORS, 'Content-Type': 'application/json' },
        jsonBody: results
      };

    } catch (error) {
      context.log.error('CRITICAL ERROR in ThreatIntelLookup:', error?.message);
      context.log.error('Error stack:', error?.stack);
      return {
        status: 500,
        headers: { ...CORS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'Failed to perform lookup', details: error?.message }
      };
    }
  }
});

// ------- Helpers --------

function detectIndicatorType(indicator) {
  const ipRegex =
    /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/; // IPv4
  const sha1Regex = /^[a-fA-F0-9]{40}$/;
  const sha256Regex = /^[a-fA-F0-9]{64}$/;
  const urlRegex = /^(https?:\/\/)[^\s/$.?#].[^\s]*$/i;
  const domainRegex = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;

  if (ipRegex.test(indicator)) return 'IP';
  if (sha256Regex.test(indicator)) return 'SHA256';
  if (sha1Regex.test(indicator)) return 'SHA1';
  if (urlRegex.test(indicator)) return 'URL';
  if (domainRegex.test(indicator)) return 'Domain';
  return 'Unknown';
}

async function queryVirusTotal(indicator, type, apiKey) {
  let endpoint;

  switch (type) {
    case 'IP':
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`;
      break;
    case 'SHA1':
    case 'SHA256':
      endpoint = `https://www.virustotal.com/api/v3/files/${indicator}`;
      break;
    case 'URL': {
      // VT requires base64url of the full URL
      const urlId = Buffer.from(indicator).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      break;
    }
    case 'Domain':
      endpoint = `https://www.virustotal.com/api/v3/domains/${indicator}`;
      break;
    default:
      throw new Error('Unsupported indicator type for VirusTotal');
  }

  const response = await axios.get(endpoint, {
    headers: { 'x-apikey': apiKey, 'Accept': 'application/json' }
  });

  const attrs = response?.data?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const lastAnalysisDate = attrs.last_analysis_date;

  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    undetected: stats.undetected ?? 0,
    harmless: stats.harmless ?? 0,
    reputation: attrs.reputation ?? 'N/A',
    lastAnalysis: lastAnalysisDate ? new Date(lastAnalysisDate * 1000).toISOString() : 'N/A'
  };
}

async function queryAbuseIPDB(ip, apiKey) {
  const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
    headers: { 'Key': apiKey, 'Accept': 'application/json' },
    params: { ipAddress: ip, maxAgeInDays: 90 }
  });

  const d = response?.data?.data || {};
  return {
    abuseScore: d.abuseConfidenceScore ?? 0,
    totalReports: d.totalReports ?? 0,
    countryCode: d.countryCode ?? 'N/A',
    usageType: d.usageType ?? 'N/A',
    isp: d.isp ?? 'N/A',
    domain: d.domain ?? 'N/A',
    isWhitelisted: d.isWhitelisted ?? false
  };
}

async function queryURLScan(indicator, type, apiKey) {
  const searchQuery = type === 'URL' ? `page.url:"${indicator}"` : `domain:${indicator}`;
  // 1) search existing scans
  const searchResp = await axios.get('https://urlscan.io/api/v1/search/', {
    headers: { 'API-Key': apiKey },
    params: { q: searchQuery }
  });

  const hit = searchResp?.data?.results?.[0];
  if (hit) {
    return {
      verdictMalicious: hit?.verdicts?.overall?.malicious || false,
      score: hit?.verdicts?.overall?.score || 0,
      categories: hit?.verdicts?.overall?.categories || [],
      screenshot: hit?.screenshot,
      reportUrl: hit?.result,
      ip: hit?.page?.ip,
      server: hit?.page?.server,
      scanDate: hit?.task?.time
    };
  }

  // 2) submit a scan if nothing found
  const submitResp = await axios.post(
    'https://urlscan.io/api/v1/scan/',
    { url: indicator, visibility: 'public' },
    { headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' } }
  );

  return {
    scanning: true,
    reportUrl: submitResp?.data?.result,
    message: 'Scan submitted, results will be available shortly'
  };
}

async function queryGreyNoise(ip, apiKey) {
  try {
    // Community endpoint uses GET with optional key header. Enterprise uses bearer.
    const response = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
      headers: { 'key': apiKey }
    });

    const d = response?.data || {};
    return {
      noise: d.noise || false,
      riot: d.riot || false,
      classification: d.classification || 'unknown',
      name: d.name || 'N/A',
      lastSeen: d.last_seen || 'N/A',
      message: d.message || ''
    };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      return {
        noise: false,
        riot: false,
        classification: 'unknown',
        message: 'IP not found in GreyNoise'
      };
    }
    throw new Error(`GreyNoise query failed: ${error.message}`);
  }
}

async function queryShodan(ip, apiKey) {
  try {
    const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
      params: { key: apiKey }
    });

    const data = response?.data || {};
    const ports = data.ports || [];
    const services = (data.data || []).slice(0, 10).map(s => ({
      port: s.port || 0,
      protocol: s.transport || 'unknown',
      product: s.product || 'Unknown',
      version: s.version || '',
      banner: s.data ? s.data.substring(0, 200) : ''
    }));

    const vulns = data.vulns || {};
    const topVulns = Object.keys(vulns).slice(0, 10);

    return {
      organization: data.org || 'Unknown',
      isp: data.isp || 'Unknown',
      asn: data.asn || 'Unknown',
      country: data.country_name || 'Unknown',
      city: data.city || 'Unknown',
      ports,
      openPortsCount: ports.length,
      services,
      vulnerabilities: topVulns,
      vulnCount: topVulns.length,
      lastUpdate: data.last_update || 'N/A',
      hostnames: data.hostnames || [],
      tags: data.tags || [],
      hasData: true
    };
  } catch (error) {
    return {
      message: 'No information available for this IP',
      hasData: false,
      error: 'not_found'
    };
  }
}

async function queryAlienVault(indicator, type, apiKey) {
  try {
    let endpoint;
    switch (type) {
      case 'IP':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general`;
        break;
      case 'Domain':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${indicator}/general`;
        break;
      case 'URL': {
        const encodedUrl = encodeURIComponent(indicator);
        endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodedUrl}/general`;
        break;
      }
      case 'SHA1':
      case 'SHA256':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${indicator}/general`;
        break;
      default:
        throw new Error('Unsupported indicator type for AlienVault OTX');
    }

    const response = await axios.get(endpoint, {
      headers: { 'X-OTX-API-KEY': apiKey }
    });

    const data = response?.data || {};
    const pulses = data.pulse_info?.pulses || [];
    const topPulses = pulses.slice(0, 5).map(pulse => ({
      name: pulse.name,
      tags: pulse.tags || [],
      malwareFamilies: pulse.malware_families || [],
      adversary: pulse.adversary || null,
      created: pulse.created,
      modified: pulse.modified,
      id: pulse.id
    }));

    const validations = data.validation || [];
    const reputation = data.reputation || 0;

    return {
      pulseCount: data.pulse_info?.count || 0,
      pulses: topPulses,
      validations,
      reputation,
      sections: data.sections || [],
      whois: data.whois || null,
      hasData: pulses.length > 0 || validations.length > 0
    };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      return {
        pulseCount: 0,
        pulses: [],
        validations: [],
        reputation: 0,
        hasData: false,
        message: 'No threat intelligence data found'
      };
    }
    throw new Error(`AlienVault OTX query failed: ${error.message}`);
  }
}