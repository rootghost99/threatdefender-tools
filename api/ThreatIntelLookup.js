// ThreatIntelLookup.js
// Azure Functions v4 (CommonJS) + axios
// POST { "indicator": "<ip|domain|url|sha1|sha256>" }

const { app } = require('@azure/functions');
const axios = require('axios');

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
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS };
    }

    let indicator = null;
    try {
      const raw = await request.text();
      let body = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch { /* ignore */ }
      indicator = (body?.indicator ?? '').toString().trim();

      if (!indicator) {
        return { status: 400, headers: { ...CORS, 'Content-Type': 'application/json' }, jsonBody: { error: 'Missing indicator field' } };
      }

      const indicatorType = detectIndicatorType(indicator);
      context.log(`ThreatIntelLookup start: indicator=${indicator} type=${indicatorType}`);

      const vtApiKey      = process.env.VIRUSTOTAL_API_KEY;
      const aipdbApiKey   = process.env.ABUSEIPDB_API_KEY;
      const urlscanApiKey = process.env.URLSCAN_API_KEY;
      const greynoiseKey  = process.env.GREYNOISE_API_KEY;
      const shodanApiKey  = process.env.SHODAN_API_KEY;
      const otxApiKey     = process.env.ALIENVAULT_OTX_API_KEY;

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

      // Always safe: providers never throw; they return { error } on failure.
      if (vtApiKey) {
        context.log('VT lookup…');
        results.virusTotal = await safeQuery(() => queryVirusTotal(indicator, indicatorType, vtApiKey), 'virustotal', context);
      }

      if (indicatorType === 'IP' && aipdbApiKey) {
        context.log('AbuseIPDB lookup…');
        results.abuseIPDB = await safeQuery(() => queryAbuseIPDB(indicator, aipdbApiKey), 'abuseipdb', context);
      }

      if ((indicatorType === 'URL' || indicatorType === 'Domain') && urlscanApiKey) {
        context.log('URLScan lookup…');
        results.urlScan = await safeQuery(() => queryURLScan(indicator, indicatorType, urlscanApiKey), 'urlscan', context);
      }

      if (indicatorType === 'IP' && greynoiseKey) {
        context.log('GreyNoise lookup…');
        results.greyNoise = await safeQuery(() => queryGreyNoise(indicator, greynoiseKey), 'greynoise', context);
      }

      if (indicatorType === 'IP' && shodanApiKey) {
        context.log('Shodan lookup…');
        results.shodan = await safeQuery(() => queryShodan(indicator, shodanApiKey), 'shodan', context);
      }

      if (otxApiKey) {
        context.log('AlienVault OTX lookup…');
        results.alienVault = await safeQuery(() => queryAlienVault(indicator, indicatorType, otxApiKey), 'otx', context);
      }

      context.log('ThreatIntelLookup done');
      return { status: 200, headers: { ...CORS, 'Content-Type': 'application/json' }, jsonBody: results };

    } catch (err) {
      // No references to possibly undefined locals here.
      context.log.error('ThreatIntelLookup fatal:', err?.message);
      context.log.error(err?.stack);
      return {
        status: 500,
        headers: { ...CORS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'Failed to perform lookup', details: err?.message }
      };
    }
  }
});

// ---- Helpers (no throws past these points) ----

function detectIndicatorType(indicator) {
  const ipRegex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/; // IPv4
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

// Wrap any provider call; never throw.
async function safeQuery(fn, name, context) {
  try {
    const r = await fn();
    // Log non-happy statuses if present
    if (r && typeof r === 'object' && r.error) context.log.warn(`${name} error:`, summarizeError(r.error));
    return r;
  } catch (e) {
    context.log.error(`${name} exception:`, e?.message);
    return { error: e?.message || 'unknown_error' };
  }
}

function summarizeError(err) {
  if (typeof err === 'string') return err.slice(0, 300);
  if (err && err.message) return err.message.slice(0, 300);
  try { return JSON.stringify(err).slice(0, 300); } catch { return 'error'; }
}

// ---------- Providers (return objects; do not throw) ----------

async function queryVirusTotal(indicator, type, apiKey) {
  try {
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
        const urlId = Buffer.from(indicator).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        break;
      }
      case 'Domain':
        endpoint = `https://www.virustotal.com/api/v3/domains/${indicator}`;
        break;
      default:
        return { error: 'Unsupported indicator type for VirusTotal' };
    }

    const { data } = await axios.get(endpoint, { headers: { 'x-apikey': apiKey, Accept: 'application/json' } });
    const attrs = data?.data?.attributes || {};
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
  } catch (e) {
    return { error: extractAxiosError(e) };
  }
}

async function queryAbuseIPDB(ip, apiKey) {
  try {
    const { data } = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { Key: apiKey, Accept: 'application/json' },
      params: { ipAddress: ip, maxAgeInDays: 90 }
    });
    const d = data?.data || {};
    return {
      abuseScore: d.abuseConfidenceScore ?? 0,
      totalReports: d.totalReports ?? 0,
      countryCode: d.countryCode ?? 'N/A',
      usageType: d.usageType ?? 'N/A',
      isp: d.isp ?? 'N/A',
      domain: d.domain ?? 'N/A',
      isWhitelisted: d.isWhitelisted ?? false
    };
  } catch (e) {
    return { error: extractAxiosError(e) };
  }
}

async function queryURLScan(indicator, type, apiKey) {
  try {
    const q = type === 'URL' ? `page.url:"${indicator}"` : `domain:${indicator}`;
    const search = await axios.get('https://urlscan.io/api/v1/search/', { headers: { 'API-Key': apiKey }, params: { q } });
    const hit = search?.data?.results?.[0];
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
    const submit = await axios.post('https://urlscan.io/api/v1/scan/', { url: indicator, visibility: 'public' }, { headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' } });
    return { scanning: true, reportUrl: submit?.data?.result, message: 'Scan submitted, results shortly' };
  } catch (e) {
    return { error: extractAxiosError(e) };
  }
}

async function queryGreyNoise(ip, apiKey) {
  try {
    const res = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
      headers: { key: apiKey, Accept: 'application/json' }
    });
    const d = res?.data || {};
    return {
      noise: d.noise || false,
      riot: d.riot || false,
      classification: d.classification || 'unknown',
      name: d.name || 'N/A',
      lastSeen: d.last_seen || 'N/A',
      message: d.message || ''
    };
  } catch (e) {
    if (e.response && e.response.status === 404) {
      return { noise: false, riot: false, classification: 'unknown', message: 'IP not found in GreyNoise' };
    }
    return { error: extractAxiosError(e) };
  }
}

async function queryShodan(ip, apiKey) {
  try {
    const res = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, { params: { key: apiKey } });
    const data = res?.data || {};
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
  } catch (e) {
    // Return a non-throwing shape even for 401/404/etc.
    return { hasData: false, message: 'No information available for this IP', error: extractAxiosError(e) };
  }
}

async function queryAlienVault(indicator, type, apiKey) {
  try {
    let endpoint;
    switch (type) {
      case 'IP':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general`; break;
      case 'Domain':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${indicator}/general`; break;
      case 'URL': {
        const encoded = encodeURIComponent(indicator);
        endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encoded}/general`; break;
      }
      case 'SHA1':
      case 'SHA256':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${indicator}/general`; break;
      default:
        return { error: 'Unsupported indicator type for AlienVault OTX' };
    }
    const res = await axios.get(endpoint, { headers: { 'X-OTX-API-KEY': apiKey } });
    const data = res?.data || {};
    const pulses = data.pulse_info?.pulses || [];
    const topPulses = pulses.slice(0, 5).map(p => ({
      name: p.name, tags: p.tags || [], malwareFamilies: p.malware_families || [],
      adversary: p.adversary || null, created: p.created, modified: p.modified, id: p.id
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
  } catch (e) {
    if (e.response && e.response.status === 404) {
      return { pulseCount: 0, pulses: [], validations: [], reputation: 0, hasData: false, message: 'No threat intelligence data found' };
    }
    return { error: extractAxiosError(e) };
  }
}

function extractAxiosError(e) {
  if (e?.response) {
    return { status: e.response.status, data: e.response.data ?? null };
  }
  return e?.message || 'request_failed';
}
