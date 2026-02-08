const axios = require('axios');

/**
 * Main function to query all threat intelligence sources
 */
async function queryThreatIntel(indicator) {
  const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
  const aipdbApiKey = process.env.ABUSEIPDB_API_KEY;
  const urlscanApiKey = process.env.URLSCAN_API_KEY;
  const greynoiseApiKey = process.env.GREYNOISE_API_KEY;
  const shodanApiKey = process.env.SHODAN_API_KEY;
  const otxApiKey = process.env.ALIENVAULT_OTX_API_KEY;
  const mxToolboxApiKey = process.env.MXTOOLBOX_API_KEY;

  const indicatorType = detectIndicatorType(indicator);

  // Block private/internal IPs to prevent SSRF
  if (indicatorType === 'PrivateIP') {
    throw new Error('Private or internal IP addresses are not allowed for external lookups');
  }

  const results = {
    indicator,
    type: indicatorType,
    virusTotal: null,
    abuseIPDB: null,
    urlScan: null,
    greyNoise: null,
    shodan: null,
    alienVault: null,
    mxToolbox: null,
    arin: null
  };

  // Run all queries in parallel for speed
  const queries = [];

  // VirusTotal
  if (vtApiKey) {
    queries.push(
      queryVirusTotal(indicator, indicatorType, vtApiKey)
        .then(data => { results.virusTotal = data; })
        .catch(error => { results.virusTotal = { error: error.message }; })
    );
  }

  // AbuseIPDB (IP only)
  if (indicatorType === 'IP' && aipdbApiKey) {
    queries.push(
      queryAbuseIPDB(indicator, aipdbApiKey)
        .then(data => { results.abuseIPDB = data; })
        .catch(error => { results.abuseIPDB = { error: error.message }; })
    );
  }

  // URLScan (URL or Domain)
  if ((indicatorType === 'URL' || indicatorType === 'Domain') && urlscanApiKey) {
    queries.push(
      queryURLScan(indicator, indicatorType, urlscanApiKey)
        .then(data => { results.urlScan = data; })
        .catch(error => { results.urlScan = { error: error.message }; })
    );
  }

  // GreyNoise (IP only)
  if (indicatorType === 'IP' && greynoiseApiKey) {
    queries.push(
      queryGreyNoise(indicator, greynoiseApiKey)
        .then(data => { results.greyNoise = data; })
        .catch(error => { results.greyNoise = { error: error.message }; })
    );
  }

  // Shodan (IP only)
  if (indicatorType === 'IP' && shodanApiKey) {
    queries.push(
      queryShodan(indicator, shodanApiKey)
        .then(data => { results.shodan = data; })
        .catch(error => { results.shodan = { error: error.message }; })
    );
  }

  // AlienVault OTX
  if (otxApiKey) {
    queries.push(
      queryAlienVault(indicator, indicatorType, otxApiKey)
        .then(data => { results.alienVault = data; })
        .catch(error => { results.alienVault = { error: error.message }; })
    );
  }

  // MXToolbox (IP only)
  if (indicatorType === 'IP' && mxToolboxApiKey) {
    queries.push(
      queryMXToolbox(indicator, mxToolboxApiKey)
        .then(data => { results.mxToolbox = data; })
        .catch(error => { results.mxToolbox = { error: error.message }; })
    );
  }

  // ARIN RDAP (IP only, no API key needed)
  if (indicatorType === 'IP') {
    queries.push(
      queryArinRdap(indicator)
        .then(data => { results.arin = data; })
        .catch(error => { results.arin = { error: error.message }; })
    );
  }

  // Wait for all queries to complete
  await Promise.all(queries);

  return results;
}

/**
 * Check if an IP address is private/internal (SSRF protection)
 */
function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 255) return true;
  if (parts.every(p => p === 0)) return true;
  return false;
}

/**
 * Detect the type of indicator
 */
function detectIndicatorType(indicator) {
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const sha1Regex = /^[a-fA-F0-9]{40}$/;
  const sha256Regex = /^[a-fA-F0-9]{64}$/;
  const urlRegex = /^https?:\/\//;
  const domainRegex = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

  if (ipRegex.test(indicator)) {
    // Validate octet ranges and block private IPs
    const parts = indicator.split('.').map(Number);
    if (parts.some(p => p > 255)) return 'Unknown';
    if (isPrivateIP(indicator)) return 'PrivateIP';
    return 'IP';
  }
  if (sha256Regex.test(indicator)) return 'SHA256';
  if (sha1Regex.test(indicator)) return 'SHA1';
  if (urlRegex.test(indicator)) return 'URL';
  if (domainRegex.test(indicator)) return 'Domain';
  return 'Unknown';
}

/**
 * Query VirusTotal API
 */
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
    case 'URL':
      const urlId = Buffer.from(indicator)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      break;
    case 'Domain':
      endpoint = `https://www.virustotal.com/api/v3/domains/${indicator}`;
      break;
    default:
      throw new Error('Unsupported indicator type for VirusTotal');
  }

  const response = await axios.get(endpoint, {
    headers: { 'x-apikey': apiKey },
    timeout: 15000
  });

  const stats = response.data.data.attributes.last_analysis_stats || {};
  const lastAnalysisDate = response.data.data.attributes.last_analysis_date;

  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    undetected: stats.undetected || 0,
    harmless: stats.harmless || 0,
    reputation: response.data.data.attributes.reputation ?? 'N/A',
    lastAnalysis: lastAnalysisDate ? new Date(lastAnalysisDate * 1000).toISOString() : 'N/A'
  };
}

/**
 * Query AbuseIPDB API
 */
async function queryAbuseIPDB(ip, apiKey) {
  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { Key: apiKey, Accept: 'application/json' },
      params: { ipAddress: ip, maxAgeInDays: 90 },
      timeout: 10000
    });

    const data = response.data.data || {};
    return {
      abuseScore: data.abuseConfidenceScore || 0,
      totalReports: data.totalReports || 0,
      countryCode: data.countryCode || 'N/A',
      usageType: data.usageType || 'N/A',
      isp: data.isp || 'Unknown',
      domain: data.domain || 'N/A',
      isWhitelisted: data.isWhitelisted || false
    };
  } catch (error) {
    if (error.response) {
      throw new Error(
        `AbuseIPDB API error (${error.response.status}): ${
          error.response.data?.errors?.[0]?.detail || 'Unknown error'
        }`
      );
    }
    throw new Error(`AbuseIPDB query failed: ${error.message}`);
  }
}

/**
 * Query URLScan.io API
 */
async function queryURLScan(indicator, type, apiKey) {
  const searchQuery = type === 'URL' ? `page.url:"${indicator}"` : `domain:${indicator}`;

  try {
    const searchResponse = await axios.get('https://urlscan.io/api/v1/search/', {
      headers: { 'API-Key': apiKey },
      params: { q: searchQuery },
      timeout: 10000
    });

    if (searchResponse.data.results && searchResponse.data.results.length > 0) {
      const latestResult = searchResponse.data.results[0];
      return {
        verdictMalicious: latestResult.verdicts?.overall?.malicious || false,
        score: latestResult.verdicts?.overall?.score || 0,
        categories: latestResult.verdicts?.overall?.categories || [],
        screenshot: latestResult.screenshot,
        reportUrl: latestResult.result,
        ip: latestResult.page?.ip,
        server: latestResult.page?.server,
        scanDate: latestResult.task?.time
      };
    }

    // Submit new scan if nothing found
    const submitResponse = await axios.post(
      'https://urlscan.io/api/v1/scan/',
      { url: indicator, visibility: 'public' },
      { headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' }, timeout: 10000 }
    );

    return {
      scanning: true,
      reportUrl: submitResponse.data.result,
      message: 'Scan submitted, results will be available in ~30 seconds'
    };
  } catch (error) {
    throw new Error(`URLScan query failed: ${error.message}`);
  }
}

/**
 * Query GreyNoise API
 */
async function queryGreyNoise(ip, apiKey) {
  try {
    const response = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
      headers: { key: apiKey },
      timeout: 10000
    });

    const data = response.data || {};
    return {
      noise: data.noise || false,
      riot: data.riot || false,
      classification: data.classification || 'unknown',
      name: data.name || 'N/A',
      lastSeen: data.last_seen || 'N/A',
      message: data.message || ''
    };
  } catch (error) {
    return {
      noise: false,
      riot: false,
      classification: 'unknown',
      name: 'N/A',
      lastSeen: 'N/A',
      message:
        error.response?.status === 404
          ? 'IP not found in GreyNoise database'
          : `Query failed: ${error.message || 'Unknown error'}`,
      error: true,
      errorCode: error.response?.status || 'timeout'
    };
  }
}

/**
 * Query Shodan API
 */
async function queryShodan(ip, apiKey) {
  try {
    const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
      params: { key: apiKey },
      timeout: 10000
    });

    const data = response.data || {};
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
  } catch {
    return { message: 'No information available for this IP', hasData: false, error: 'not_found' };
  }
}

/**
 * Query AlienVault OTX API
 */
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
      case 'URL':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(indicator)}/general`;
        break;
      case 'SHA1':
      case 'SHA256':
        endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${indicator}/general`;
        break;
      default:
        throw new Error('Unsupported indicator type for AlienVault OTX');
    }

    const response = await axios.get(endpoint, {
      headers: { 'X-OTX-API-KEY': apiKey },
      timeout: 15000
    });

    const data = response.data || {};
    const pulses = data.pulse_info?.pulses || [];
    const topPulses = pulses.slice(0, 5).map(p => ({
      name: p.name,
      tags: p.tags || [],
      malwareFamilies: p.malware_families || [],
      adversary: p.adversary || null,
      created: p.created,
      modified: p.modified,
      id: p.id
    }));

    return {
      pulseCount: data.pulse_info?.count || 0,
      pulses: topPulses,
      validations: data.validation || [],
      reputation: data.reputation || 0,
      sections: data.sections || [],
      whois: data.whois || null,
      hasData: pulses.length > 0 || (data.validation || []).length > 0
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

/**
 * Query MXToolbox API
 */
async function queryMXToolbox(ip, apiKey) {
  try {
    const response = await axios.get('https://mxtoolbox.com/api/v1/Lookup/whois', {
      params: { argument: ip },
      headers: { Authorization: apiKey },
      timeout: 15000
    });

    const data = response.data || {};
    const info = data.Information || [];
    const failed = data.Failed || [];
    const relatedIP = data.RelatedIP || [];

    let organization = 'Unknown';
    let netRange = 'N/A';
    let netName = 'N/A';
    let country = 'N/A';
    let registrationDate = 'N/A';
    let updated = 'N/A';
    let abuseEmail = 'N/A';
    let techEmail = 'N/A';

    info.forEach(item => {
      const line = item.Information || '';
      if (line.includes('Organization:')) organization = line.split('Organization:')[1]?.trim() || organization;
      if (line.includes('OrgName:')) organization = line.split('OrgName:')[1]?.trim() || organization;
      if (line.includes('NetRange:')) netRange = line.split('NetRange:')[1]?.trim() || netRange;
      if (line.includes('CIDR:')) {
        const cidr = line.split('CIDR:')[1]?.trim();
        if (cidr && netRange === 'N/A') netRange = cidr;
      }
      if (line.includes('NetName:')) netName = line.split('NetName:')[1]?.trim() || netName;
      if (line.includes('Country:')) country = line.split('Country:')[1]?.trim() || country;
      if (line.includes('RegDate:')) registrationDate = line.split('RegDate:')[1]?.trim() || registrationDate;
      if (line.includes('Updated:')) updated = line.split('Updated:')[1]?.trim() || updated;
      if (line.includes('OrgAbuseEmail:')) abuseEmail = line.split('OrgAbuseEmail:')[1]?.trim() || abuseEmail;
      if (line.includes('OrgTechEmail:')) techEmail = line.split('OrgTechEmail:')[1]?.trim() || techEmail;
    });

    return {
      organization,
      netRange,
      netName,
      country,
      registrationDate,
      updated,
      abuseContact: abuseEmail,
      techContact: techEmail,
      relatedIPs: relatedIP.slice(0, 5),
      rawInfo: info.slice(0, 20).map(i => i.Information || ''),
      hasData: info.length > 0 && !failed.length,
      failed: failed.length > 0,
      failedMessage: failed.length > 0 ? failed[0].Failed : null
    };
  } catch (error) {
    return {
      organization: 'Unknown',
      netRange: 'N/A',
      netName: 'N/A',
      country: 'N/A',
      registrationDate: 'N/A',
      updated: 'N/A',
      abuseContact: 'N/A',
      techContact: 'N/A',
      relatedIPs: [],
      rawInfo: [],
      hasData: false,
      error: true,
      errorMessage:
        error.response?.status === 404 ? 'IP not found in ARIN database' : `Query failed: ${error.message || 'Unknown error'}`,
      errorCode: error.response?.status || 'timeout'
    };
  }
}

/**
 * Query ARIN RDAP (no API key needed)
 */
async function queryArinRdap(ip) {
  try {
    const response = await axios.get(`https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`, {
      timeout: 10000
    });

    const data = response.data || {};
    const orgEntity = (data.entities || []).find(e => e.roles?.includes('registrant'));
    const abuseEntity = (data.entities || []).find(e => e.roles?.includes('abuse'));

    const orgName = orgEntity?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'Unknown';
    const abuseEmail = abuseEntity?.vcardArray?.[1]?.find(v => v[0] === 'email')?.[3] || 'N/A';

    const lastChanged = (data.events || []).find(e => e.eventAction === 'last changed')?.eventDate || 'N/A';
    const registrationDate = (data.events || []).find(e => e.eventAction === 'registration')?.eventDate || 'N/A';

    return {
      handle: data.handle || 'N/A',
      name: data.name || 'N/A',
      type: data.type || 'N/A',
      startAddress: data.startAddress || 'N/A',
      endAddress: data.endAddress || 'N/A',
      parentHandle: data.parentHandle || 'N/A',
      org: orgName,
      abuseContact: abuseEmail,
      country: data.country || 'N/A',
      lastChanged,
      registrationDate,
      hasData: true,
      rawData: data
    };
  } catch (error) {
    return {
      handle: 'N/A',
      org: 'Unknown',
      hasData: false,
      error: true,
      message:
        error.response?.status === 404
          ? 'IP not found in ARIN RDAP database'
          : `Query failed: ${error.message || 'Unknown error'}`
    };
  }
}

module.exports = {
  queryThreatIntel,
  detectIndicatorType
};
