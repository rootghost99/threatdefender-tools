// /api/EmailPosture.js
const { app } = require('@azure/functions');
const dns = require('dns').promises;
const axios = require('axios');

// Configure DNS resolver to use Cloudflare
dns.setServers(['1.1.1.1', '1.0.0.1']);

// In-memory cache for rate limiting and performance
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

app.http('EmailPosture', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log('Email Posture function triggered');

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
      const { domain, dkimSelectors } = body || {};

      if (!domain) {
        return { status: 400, jsonBody: { error: 'Missing domain field' } };
      }

      // Validate and sanitize domain (convert to punycode if needed)
      const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');

      // Check cache
      const cacheKey = `${cleanDomain}:${(dkimSelectors || []).join(',')}`;
      const cached = cache.get(cacheKey);
      if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
        context.log('Returning cached result for:', cleanDomain);
        return {
          status: 200,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
          },
          jsonBody: { ...cached.data, cached: true }
        };
      }

      context.log('Analyzing email posture for:', cleanDomain);

      // Default DKIM selectors to try
      const defaultSelectors = ['selector1', 'selector2', 'default', 'google', 'k1', 's1024', 's2048'];
      const selectorsToCheck = dkimSelectors && dkimSelectors.length > 0
        ? dkimSelectors
        : defaultSelectors;

      // Perform all DNS checks in parallel
      const [spfResult, dmarcResult, dkimResults, mxResult, mtaStsResult, bimiResult] = await Promise.allSettled([
        analyzeSPF(cleanDomain, context),
        analyzeDMARC(cleanDomain, context),
        analyzeDKIM(cleanDomain, selectorsToCheck, context),
        analyzeMX(cleanDomain, context),
        analyzeMTASTS(cleanDomain, context),
        analyzeBIMI(cleanDomain, context)
      ]);

      // MXToolbox enrichment (optional)
      let mxToolboxResult = null;
      const mxToolboxApiKey = process.env.MXTOOLBOX_API_KEY;
      if (mxToolboxApiKey) {
        try {
          context.log('Querying MXToolbox Email Health for:', cleanDomain);
          mxToolboxResult = await queryMXToolboxEmailHealth(cleanDomain, mxToolboxApiKey, context);
        } catch (error) {
          context.error('MXToolbox error:', error.message);
          mxToolboxResult = { error: error.message };
        }
      }

      // Compile results
      const results = {
        domain: cleanDomain,
        timestamp: new Date().toISOString(),
        spf: spfResult.status === 'fulfilled' ? spfResult.value : { error: spfResult.reason?.message },
        dmarc: dmarcResult.status === 'fulfilled' ? dmarcResult.value : { error: dmarcResult.reason?.message },
        dkim: dkimResults.status === 'fulfilled' ? dkimResults.value : { error: dkimResults.reason?.message },
        mx: mxResult.status === 'fulfilled' ? mxResult.value : { error: mxResult.reason?.message },
        mtaSts: mtaStsResult.status === 'fulfilled' ? mtaStsResult.value : { error: mtaStsResult.reason?.message },
        bimi: bimiResult.status === 'fulfilled' ? bimiResult.value : { error: bimiResult.reason?.message },
        mxToolbox: mxToolboxResult
      };

      // Calculate summary
      results.summary = calculateSummary(results);

      // Cache the results
      cache.set(cacheKey, { data: results, timestamp: Date.now() });

      context.log('Email posture analysis complete for:', cleanDomain);

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: results
      };

    } catch (error) {
      context.error('CRITICAL ERROR in EmailPosture:', error.message);
      context.error('Error stack:', error.stack);
      return {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          error: 'Failed to analyze email posture',
          details: error.message
        }
      };
    }
  }
});

/* ---------------------- SPF Analysis ---------------------- */

async function analyzeSPF(domain, context) {
  try {
    const records = await dns.resolveTxt(domain);
    const spfRecords = records.filter(record =>
      record.join('').startsWith('v=spf1')
    );

    if (spfRecords.length === 0) {
      return {
        status: 'fail',
        record: null,
        issues: ['No SPF record found'],
        lookupCount: 0,
        mechanism: null
      };
    }

    if (spfRecords.length > 1) {
      return {
        status: 'fail',
        record: spfRecords.map(r => r.join('')),
        issues: ['Multiple SPF records found (RFC violation)'],
        lookupCount: 0,
        mechanism: null
      };
    }

    const spfRecord = spfRecords[0].join('');
    const issues = [];
    let lookupCount = 0;

    // Count DNS lookups (mechanisms that require DNS: include, a, mx, exists, ptr)
    const mechanisms = spfRecord.split(' ');
    for (const mech of mechanisms) {
      if (mech.startsWith('include:') || mech.startsWith('a:') || mech.startsWith('a ') ||
          mech.startsWith('mx:') || mech.startsWith('mx ') || mech.startsWith('exists:') ||
          mech.startsWith('ptr:') || mech.startsWith('ptr ')) {
        lookupCount++;
      }
    }

    // Recursively expand includes (limit depth)
    const expandedLookups = await countSPFLookups(domain, spfRecord, 0, 10, context);
    lookupCount = expandedLookups;

    // Check for issues
    if (lookupCount > 10) {
      issues.push(`Exceeds 10 DNS lookup limit (${lookupCount} lookups) - may cause validation failures`);
    }

    if (spfRecord.includes('+all')) {
      issues.push('Uses +all (allows all senders) - serious security risk');
    }

    if (spfRecord.includes('?all')) {
      issues.push('Uses ?all (neutral policy) - provides no protection');
    }

    if (spfRecord.includes('ptr:') || spfRecord.includes('ptr ')) {
      issues.push('Uses deprecated ptr mechanism - should be removed');
    }

    const hasHardFail = spfRecord.includes('-all');
    const hasSoftFail = spfRecord.includes('~all');

    if (!hasHardFail && !hasSoftFail) {
      issues.push('No terminal mechanism (-all or ~all) found');
    }

    const status = issues.length === 0 ? 'pass' : (issues.some(i => i.includes('serious') || i.includes('RFC')) ? 'fail' : 'warn');

    return {
      status,
      record: spfRecord,
      lookupCount,
      mechanism: hasHardFail ? 'fail' : (hasSoftFail ? 'softfail' : 'unknown'),
      issues: issues.length > 0 ? issues : null
    };

  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return {
        status: 'fail',
        record: null,
        issues: ['No SPF record found'],
        lookupCount: 0,
        mechanism: null
      };
    }
    throw error;
  }
}

async function countSPFLookups(domain, record, depth, maxDepth, context) {
  if (depth >= maxDepth) return 0;

  let count = 0;
  const mechanisms = record.split(' ');

  for (const mech of mechanisms) {
    if (mech.startsWith('include:')) {
      count++;
      const includeDomain = mech.split(':')[1];
      try {
        const includeRecords = await dns.resolveTxt(includeDomain);
        const includeSpf = includeRecords.find(r => r.join('').startsWith('v=spf1'));
        if (includeSpf) {
          count += await countSPFLookups(includeDomain, includeSpf.join(''), depth + 1, maxDepth, context);
        }
      } catch (err) {
        context.log.warn(`Failed to resolve include: ${includeDomain}`);
      }
    } else if (mech.startsWith('a:') || mech.startsWith('a ') ||
               mech.startsWith('mx:') || mech.startsWith('mx ') ||
               mech.startsWith('exists:') || mech.startsWith('ptr:')) {
      count++;
    }
  }

  return count;
}

/* ---------------------- DMARC Analysis ---------------------- */

async function analyzeDMARC(domain, context) {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const records = await dns.resolveTxt(dmarcDomain);
    const dmarcRecords = records.filter(record =>
      record.join('').startsWith('v=DMARC1')
    );

    if (dmarcRecords.length === 0) {
      return {
        status: 'fail',
        record: null,
        policy: null,
        issues: ['No DMARC record found']
      };
    }

    const dmarcRecord = dmarcRecords[0].join('');
    const issues = [];

    // Parse DMARC tags
    const tags = {};
    dmarcRecord.split(';').forEach(part => {
      const [key, value] = part.trim().split('=');
      if (key && value) {
        tags[key.trim()] = value.trim();
      }
    });

    const policy = tags.p;
    const subdomainPolicy = tags.sp;
    const pct = tags.pct ? parseInt(tags.pct) : 100;
    const adkim = tags.adkim || 'r'; // relaxed by default
    const aspf = tags.aspf || 'r'; // relaxed by default

    // Check for issues
    if (policy === 'none') {
      issues.push('Policy is p=none (monitoring only) - consider p=quarantine or p=reject for production');
    }

    if (!tags.rua) {
      issues.push('No aggregate reporting (rua) configured - missing visibility into email authentication failures');
    }

    if (tags.rua && !tags.rua.startsWith('mailto:')) {
      issues.push('Invalid rua format - should start with mailto:');
    }

    if (tags.ruf && !tags.ruf.startsWith('mailto:')) {
      issues.push('Invalid ruf format - should start with mailto:');
    }

    if (pct < 100) {
      issues.push(`Policy applies to only ${pct}% of messages - consider 100% enforcement`);
    }

    const status = policy === 'reject' || policy === 'quarantine' ? (issues.length === 0 ? 'pass' : 'warn') : 'warn';

    return {
      status,
      record: dmarcRecord,
      policy,
      subdomainPolicy,
      percentage: pct,
      alignment: { dkim: adkim, spf: aspf },
      reporting: {
        aggregate: tags.rua || null,
        forensic: tags.ruf || null
      },
      issues: issues.length > 0 ? issues : null
    };

  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return {
        status: 'fail',
        record: null,
        policy: null,
        issues: ['No DMARC record found']
      };
    }
    throw error;
  }
}

/* ---------------------- DKIM Analysis ---------------------- */

async function analyzeDKIM(domain, selectors, context) {
  const results = [];

  for (const selector of selectors) {
    try {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      const records = await dns.resolveTxt(dkimDomain);

      if (records.length === 0) {
        results.push({
          selector,
          status: 'not_found',
          record: null,
          keyLength: null,
          issues: ['No DKIM record found for this selector']
        });
        continue;
      }

      const dkimRecord = records[0].join('');
      const issues = [];

      // Parse DKIM tags
      const tags = {};
      dkimRecord.split(';').forEach(part => {
        const [key, value] = part.trim().split('=');
        if (key && value) {
          tags[key.trim()] = value.trim();
        }
      });

      // Extract public key and determine length
      const publicKey = tags.p;
      if (!publicKey) {
        results.push({
          selector,
          status: 'fail',
          record: dkimRecord,
          keyLength: null,
          issues: ['No public key (p=) found in DKIM record']
        });
        continue;
      }

      // Estimate key length (base64 encoded)
      const keyLength = publicKey.length < 300 ? 1024 : 2048;

      if (keyLength < 2048) {
        issues.push('Key length is 1024 bits - recommend upgrading to 2048 bits for better security');
      }

      if (tags.v && tags.v !== 'DKIM1') {
        issues.push(`Unexpected DKIM version: ${tags.v}`);
      }

      if (tags.k && tags.k !== 'rsa') {
        issues.push(`Unexpected key type: ${tags.k} (expected rsa)`);
      }

      results.push({
        selector,
        status: issues.length === 0 ? 'pass' : 'warn',
        record: dkimRecord,
        keyLength,
        keyType: tags.k || 'rsa',
        issues: issues.length > 0 ? issues : null
      });

    } catch (error) {
      if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        results.push({
          selector,
          status: 'not_found',
          record: null,
          keyLength: null,
          issues: null
        });
      } else {
        results.push({
          selector,
          status: 'error',
          record: null,
          keyLength: null,
          issues: [error.message]
        });
      }
    }
  }

  const validKeys = results.filter(r => r.status === 'pass' || r.status === 'warn');
  const overallStatus = validKeys.length > 0 ? 'pass' : 'fail';

  return {
    status: overallStatus,
    selectors: results,
    validKeysCount: validKeys.length,
    totalChecked: results.length
  };
}

/* ---------------------- MX Analysis ---------------------- */

async function analyzeMX(domain, context) {
  try {
    const mxRecords = await dns.resolveMx(domain);

    if (mxRecords.length === 0) {
      return {
        status: 'fail',
        records: [],
        issues: ['No MX records found']
      };
    }

    const issues = [];
    const records = [];

    for (const mx of mxRecords.slice(0, 10)) { // Limit to top 10
      const mxInfo = {
        exchange: mx.exchange,
        priority: mx.priority,
        resolved: false,
        ips: []
      };

      // Check if MX points to CNAME (not allowed)
      try {
        const cnameRecords = await dns.resolveCname(mx.exchange);
        issues.push(`MX record ${mx.exchange} points to CNAME (RFC violation)`);
      } catch (err) {
        // Expected - MX should NOT be a CNAME
      }

      // Resolve A/AAAA records
      try {
        const aRecords = await dns.resolve4(mx.exchange);
        mxInfo.ips.push(...aRecords);
        mxInfo.resolved = true;
      } catch (err) {
        // A records not found
      }

      try {
        const aaaaRecords = await dns.resolve6(mx.exchange);
        mxInfo.ips.push(...aaaaRecords);
        mxInfo.resolved = true;
      } catch (err) {
        // AAAA records not found
      }

      if (!mxInfo.resolved) {
        issues.push(`MX record ${mx.exchange} does not resolve to any IP address`);
      }

      // Detect mail provider
      const vendor = detectMailVendor(mx.exchange);
      if (vendor) {
        mxInfo.vendor = vendor;
      }

      records.push(mxInfo);
    }

    const status = issues.length === 0 ? 'pass' : (issues.some(i => i.includes('RFC') || i.includes('not resolve')) ? 'fail' : 'warn');

    return {
      status,
      records,
      count: mxRecords.length,
      issues: issues.length > 0 ? issues : null
    };

  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return {
        status: 'fail',
        records: [],
        issues: ['No MX records found']
      };
    }
    throw error;
  }
}

function detectMailVendor(exchange) {
  const vendors = {
    'google.com': 'Google Workspace',
    'googlemail.com': 'Google Workspace',
    'outlook.com': 'Microsoft 365',
    'protection.outlook.com': 'Microsoft 365',
    'mail.protection.outlook.com': 'Microsoft 365',
    'pphosted.com': 'Proofpoint',
    'mimecast.com': 'Mimecast',
    'barracudanetworks.com': 'Barracuda',
    'messagelabs.com': 'Symantec',
    'ppe-hosted.com': 'Proofpoint Essentials'
  };

  for (const [key, value] of Object.entries(vendors)) {
    if (exchange.includes(key)) {
      return value;
    }
  }

  return null;
}

/* ---------------------- MTA-STS Analysis ---------------------- */

async function analyzeMTASTS(domain, context) {
  try {
    // Check for MTA-STS DNS record
    const mtaStsDomain = `_mta-sts.${domain}`;
    const records = await dns.resolveTxt(mtaStsDomain);
    const mtaStsRecords = records.filter(record =>
      record.join('').startsWith('v=STSv1')
    );

    if (mtaStsRecords.length === 0) {
      return {
        status: 'not_configured',
        dnsRecord: null,
        policy: null,
        issues: ['MTA-STS not configured']
      };
    }

    const dnsRecord = mtaStsRecords[0].join('');

    // Try to fetch the policy file (may be blocked by egress rules)
    let policy = null;
    let policyIssues = [];

    try {
      const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
      const response = await axios.get(policyUrl, { timeout: 5000 });
      policy = response.data;

      // Parse policy
      const policyLines = policy.split('\n');
      const policyData = {};
      policyLines.forEach(line => {
        const [key, value] = line.split(':');
        if (key && value) {
          policyData[key.trim()] = value.trim();
        }
      });

      if (policyData.mode === 'testing') {
        policyIssues.push('MTA-STS in testing mode - consider moving to enforce for production');
      }

      if (policyData.mode === 'none') {
        policyIssues.push('MTA-STS policy set to none - not providing protection');
      }

    } catch (err) {
      policyIssues.push('Could not fetch MTA-STS policy file (may be blocked by egress rules)');
    }

    return {
      status: policy ? 'pass' : 'warn',
      dnsRecord,
      policy,
      issues: policyIssues.length > 0 ? policyIssues : null
    };

  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return {
        status: 'not_configured',
        dnsRecord: null,
        policy: null,
        issues: null
      };
    }
    throw error;
  }
}

/* ---------------------- BIMI Analysis ---------------------- */

async function analyzeBIMI(domain, context) {
  try {
    const bimiDomain = `default._bimi.${domain}`;
    const records = await dns.resolveTxt(bimiDomain);
    const bimiRecords = records.filter(record =>
      record.join('').startsWith('v=BIMI1')
    );

    if (bimiRecords.length === 0) {
      return {
        status: 'not_configured',
        record: null,
        logoUrl: null,
        vmcUrl: null,
        issues: null
      };
    }

    const bimiRecord = bimiRecords[0].join('');

    // Parse BIMI tags
    const tags = {};
    bimiRecord.split(';').forEach(part => {
      const [key, value] = part.trim().split('=');
      if (key && value) {
        tags[key.trim()] = value.trim();
      }
    });

    return {
      status: 'pass',
      record: bimiRecord,
      logoUrl: tags.l || null,
      vmcUrl: tags.a || null,
      issues: null
    };

  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return {
        status: 'not_configured',
        record: null,
        logoUrl: null,
        vmcUrl: null,
        issues: null
      };
    }
    throw error;
  }
}

/* ---------------------- MXToolbox Email Health ---------------------- */

async function queryMXToolboxEmailHealth(domain, apiKey, context) {
  try {
    // Query multiple MXToolbox endpoints
    const [spfCheck, dmarcCheck, dkimCheck, mxCheck] = await Promise.allSettled([
      axios.get('https://mxtoolbox.com/api/v1/Lookup/spf', {
        params: { argument: domain },
        headers: { Authorization: apiKey },
        timeout: 10000
      }),
      axios.get('https://mxtoolbox.com/api/v1/Lookup/dmarc', {
        params: { argument: domain },
        headers: { Authorization: apiKey },
        timeout: 10000
      }),
      axios.get('https://mxtoolbox.com/api/v1/Lookup/dkim', {
        params: { argument: `selector1:${domain}` },
        headers: { Authorization: apiKey },
        timeout: 10000
      }),
      axios.get('https://mxtoolbox.com/api/v1/Lookup/mx', {
        params: { argument: domain },
        headers: { Authorization: apiKey },
        timeout: 10000
      })
    ]);

    const results = {
      spf: spfCheck.status === 'fulfilled' ? parseMXToolboxResult(spfCheck.value.data) : { error: spfCheck.reason?.message },
      dmarc: dmarcCheck.status === 'fulfilled' ? parseMXToolboxResult(dmarcCheck.value.data) : { error: dmarcCheck.reason?.message },
      dkim: dkimCheck.status === 'fulfilled' ? parseMXToolboxResult(dkimCheck.value.data) : { error: dkimCheck.reason?.message },
      mx: mxCheck.status === 'fulfilled' ? parseMXToolboxResult(mxCheck.value.data) : { error: mxCheck.reason?.message },
      deepLink: `https://mxtoolbox.com/SuperTool.aspx?action=mx:${domain}`
    };

    // Calculate email health score
    let score = 100;
    if (results.spf.failed > 0) score -= 20;
    if (results.dmarc.failed > 0) score -= 25;
    if (results.dkim.failed > 0) score -= 15;
    if (results.mx.failed > 0) score -= 20;
    if (results.spf.warnings > 0) score -= 5;
    if (results.dmarc.warnings > 0) score -= 5;
    if (results.dkim.warnings > 0) score -= 5;
    if (results.mx.warnings > 0) score -= 5;

    results.emailHealthScore = Math.max(0, score);

    return results;

  } catch (error) {
    throw new Error(`MXToolbox API query failed: ${error.message}`);
  }
}

function parseMXToolboxResult(data) {
  const failed = data.Failed || [];
  const warnings = data.Warnings || [];
  const passed = data.Passed || [];
  const information = data.Information || [];

  return {
    passed: passed.length,
    warnings: warnings.length,
    failed: failed.length,
    details: {
      passed: passed.map(p => p.Name || p.Title || 'Unknown'),
      warnings: warnings.map(w => w.Name || w.Title || 'Unknown'),
      failed: failed.map(f => f.Name || f.Title || 'Unknown')
    },
    information: information.slice(0, 5).map(i => i.Information || '')
  };
}

/* ---------------------- Summary Calculation ---------------------- */

function calculateSummary(results) {
  const issues = [];
  let passCount = 0;
  let warnCount = 0;
  let failCount = 0;

  // SPF
  if (results.spf.status === 'pass') passCount++;
  else if (results.spf.status === 'warn') warnCount++;
  else failCount++;

  if (results.spf.issues) {
    issues.push(...results.spf.issues.map(i => ({ category: 'SPF', severity: results.spf.status === 'fail' ? 'high' : 'medium', message: i })));
  }

  // DMARC
  if (results.dmarc.status === 'pass') passCount++;
  else if (results.dmarc.status === 'warn') warnCount++;
  else failCount++;

  if (results.dmarc.issues) {
    issues.push(...results.dmarc.issues.map(i => ({ category: 'DMARC', severity: results.dmarc.status === 'fail' ? 'high' : 'medium', message: i })));
  }

  // DKIM
  if (results.dkim.status === 'pass') passCount++;
  else if (results.dkim.status === 'warn') warnCount++;
  else failCount++;

  results.dkim.selectors?.forEach(sel => {
    if (sel.issues) {
      issues.push(...sel.issues.map(i => ({ category: 'DKIM', severity: sel.status === 'fail' ? 'high' : 'low', message: `${sel.selector}: ${i}` })));
    }
  });

  // MX
  if (results.mx.status === 'pass') passCount++;
  else if (results.mx.status === 'warn') warnCount++;
  else failCount++;

  if (results.mx.issues) {
    issues.push(...results.mx.issues.map(i => ({ category: 'MX', severity: results.mx.status === 'fail' ? 'high' : 'medium', message: i })));
  }

  // Overall status
  let overallStatus = 'pass';
  if (failCount > 0) overallStatus = 'fail';
  else if (warnCount > 0) overallStatus = 'warn';

  return {
    overallStatus,
    passCount,
    warnCount,
    failCount,
    totalChecks: passCount + warnCount + failCount,
    issues: issues.length > 0 ? issues : []
  };
}
