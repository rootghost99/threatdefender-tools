// /api/EmailHeaderAnalyzer.js
// Email Header Security Analyzer - Parses and analyzes email headers for security issues
const { app } = require('@azure/functions');

app.http('EmailHeaderAnalyzer', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log('Email Header Analyzer function triggered');

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
      const { headers: rawHeaders } = body || {};

      if (!rawHeaders || typeof rawHeaders !== 'string' || rawHeaders.trim().length === 0) {
        return {
          status: 400,
          headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
          jsonBody: { error: 'Missing or invalid headers field. Please provide raw email headers.' }
        };
      }

      context.log('Analyzing email headers, length:', rawHeaders.length);

      // Parse the headers
      const parsedHeaders = parseEmailHeaders(rawHeaders);

      // Analyze delivery path from Received headers
      const deliveryPath = analyzeDeliveryPath(parsedHeaders.received || []);

      // Extract authentication results
      const authentication = analyzeAuthentication(parsedHeaders);

      // Perform security analysis
      const securityAnalysis = performSecurityAnalysis(parsedHeaders, deliveryPath, authentication);

      // Extract key header information
      const keyHeaders = extractKeyHeaders(parsedHeaders);

      // Calculate overall summary
      const summary = calculateSummary(securityAnalysis, authentication, deliveryPath);

      const results = {
        timestamp: new Date().toISOString(),
        keyHeaders,
        deliveryPath,
        authentication,
        securityAnalysis,
        allHeaders: parsedHeaders,
        summary
      };

      context.log('Email header analysis complete');

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: results
      };

    } catch (error) {
      context.log.error('CRITICAL ERROR in EmailHeaderAnalyzer:', error.message);
      context.log.error('Error stack:', error.stack);
      return {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          error: 'Failed to analyze email headers',
          details: error.message
        }
      };
    }
  }
});

/* ---------------------- Header Parsing ---------------------- */

function parseEmailHeaders(rawHeaders) {
  const headers = {};
  const lines = rawHeaders.split(/\r?\n/);
  let currentHeader = null;
  let currentValue = '';

  for (const line of lines) {
    // Check if this is a continuation of the previous header (starts with whitespace)
    if (line.match(/^[\t ]/)) {
      if (currentHeader) {
        currentValue += ' ' + line.trim();
      }
      continue;
    }

    // Save the previous header if we have one
    if (currentHeader) {
      saveHeader(headers, currentHeader, currentValue);
    }

    // Check for new header
    const match = line.match(/^([A-Za-z0-9\-]+):\s*(.*)$/);
    if (match) {
      currentHeader = match[1].toLowerCase();
      currentValue = match[2];
    } else {
      currentHeader = null;
      currentValue = '';
    }
  }

  // Don't forget the last header
  if (currentHeader) {
    saveHeader(headers, currentHeader, currentValue);
  }

  return headers;
}

function saveHeader(headers, name, value) {
  const normalizedName = name.toLowerCase();

  // Headers that can appear multiple times
  const multipleHeaders = ['received', 'dkim-signature', 'arc-seal', 'arc-message-signature', 'arc-authentication-results', 'x-received'];

  if (multipleHeaders.includes(normalizedName)) {
    if (!headers[normalizedName]) {
      headers[normalizedName] = [];
    }
    headers[normalizedName].push(value.trim());
  } else {
    // For single-value headers, keep the first occurrence
    if (!headers[normalizedName]) {
      headers[normalizedName] = value.trim();
    }
  }
}

/* ---------------------- Delivery Path Analysis ---------------------- */

function analyzeDeliveryPath(receivedHeaders) {
  if (!receivedHeaders || receivedHeaders.length === 0) {
    return {
      hops: [],
      totalHops: 0,
      totalTransitTime: null,
      issues: ['No Received headers found - unable to trace delivery path']
    };
  }

  const hops = [];
  const issues = [];

  // Received headers are in reverse order (most recent first)
  const reversedHeaders = [...receivedHeaders].reverse();

  for (let i = 0; i < reversedHeaders.length; i++) {
    const header = reversedHeaders[i];
    const hop = parseReceivedHeader(header);
    hop.hopNumber = i + 1;
    hops.push(hop);
  }

  // Calculate delays between hops
  for (let i = 1; i < hops.length; i++) {
    const prevHop = hops[i - 1];
    const currHop = hops[i];

    if (prevHop.timestamp && currHop.timestamp) {
      const delayMs = currHop.timestamp.getTime() - prevHop.timestamp.getTime();
      currHop.delayFromPrevious = delayMs;
      currHop.delayFormatted = formatDelay(delayMs);

      // Flag unusual delays
      if (delayMs > 300000) { // More than 5 minutes
        issues.push({
          type: 'delay',
          severity: delayMs > 1800000 ? 'high' : 'medium', // 30 min threshold for high
          message: `Unusual delay of ${currHop.delayFormatted} at hop ${currHop.hopNumber} (${currHop.by || 'unknown server'})`,
          hopNumber: currHop.hopNumber
        });
      }

      // Flag negative delays (clock skew)
      if (delayMs < -60000) { // More than 1 minute negative
        issues.push({
          type: 'clock_skew',
          severity: 'low',
          message: `Possible clock skew detected at hop ${currHop.hopNumber} (${Math.abs(delayMs / 1000)}s earlier than previous hop)`,
          hopNumber: currHop.hopNumber
        });
      }
    }
  }

  // Calculate total transit time
  let totalTransitTime = null;
  if (hops.length >= 2 && hops[0].timestamp && hops[hops.length - 1].timestamp) {
    totalTransitTime = hops[hops.length - 1].timestamp.getTime() - hops[0].timestamp.getTime();
  }

  // Check for suspicious patterns
  const internalHops = hops.filter(h => isInternalIP(h.fromIP));
  const externalHops = hops.filter(h => h.fromIP && !isInternalIP(h.fromIP));

  if (externalHops.length > 0) {
    const firstExternalHop = externalHops[0];
    if (firstExternalHop.fromIP) {
      // Check if originating IP looks suspicious (documented later via threat intel)
    }
  }

  return {
    hops,
    totalHops: hops.length,
    totalTransitTime,
    totalTransitFormatted: totalTransitTime ? formatDelay(totalTransitTime) : null,
    issues: issues.length > 0 ? issues : null
  };
}

function parseReceivedHeader(header) {
  const result = {
    raw: header,
    from: null,
    fromIP: null,
    by: null,
    byIP: null,
    with: null,
    timestamp: null,
    timestampRaw: null,
    tls: false
  };

  // Extract "from" server
  const fromMatch = header.match(/from\s+([^\s\(]+)(?:\s*\(([^\)]+)\))?/i);
  if (fromMatch) {
    result.from = fromMatch[1];
    if (fromMatch[2]) {
      // Extract IP from parenthetical
      const ipMatch = fromMatch[2].match(/\[?([\d\.]+|[a-f0-9:]+)\]?/i);
      if (ipMatch) {
        result.fromIP = ipMatch[1];
      }
    }
  }

  // Also try to extract IP directly if not found
  if (!result.fromIP) {
    const directIPMatch = header.match(/from\s+[^\s]+\s+\(.*?\[([\d\.]+)\]/i);
    if (directIPMatch) {
      result.fromIP = directIPMatch[1];
    }
  }

  // Extract "by" server
  const byMatch = header.match(/by\s+([^\s;]+)/i);
  if (byMatch) {
    result.by = byMatch[1];
  }

  // Extract protocol
  const withMatch = header.match(/with\s+(\w+)/i);
  if (withMatch) {
    result.with = withMatch[1].toUpperCase();
    // Check for TLS/secure transmission
    if (['ESMTPS', 'SMTPS', 'TLS', 'STARTTLS'].includes(result.with) ||
        header.toLowerCase().includes('tls') ||
        header.toLowerCase().includes('cipher')) {
      result.tls = true;
    }
  }

  // Extract timestamp - multiple formats
  const datePatterns = [
    /;\s*(.+)$/,
    /(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]?\d{0,4})/,
    /(\w{3},\s*\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s*[+-]?\d{0,4})/
  ];

  for (const pattern of datePatterns) {
    const dateMatch = header.match(pattern);
    if (dateMatch) {
      try {
        const parsedDate = new Date(dateMatch[1].trim());
        if (!isNaN(parsedDate.getTime())) {
          result.timestamp = parsedDate;
          result.timestampRaw = dateMatch[1].trim();
          break;
        }
      } catch (e) {
        // Continue to next pattern
      }
    }
  }

  // Check for authentication info
  if (header.toLowerCase().includes('authenticated')) {
    result.authenticated = true;
  }

  return result;
}

function formatDelay(ms) {
  if (ms < 0) return `${Math.round(ms / 1000)}s (negative)`;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
  return `${Math.floor(ms / 3600000)}h ${Math.round((ms % 3600000) / 60000)}m`;
}

function isInternalIP(ip) {
  if (!ip) return false;
  return ip.startsWith('10.') ||
         ip.startsWith('192.168.') ||
         ip.startsWith('172.16.') ||
         ip.startsWith('172.17.') ||
         ip.startsWith('172.18.') ||
         ip.startsWith('172.19.') ||
         ip.startsWith('172.2') ||
         ip.startsWith('172.30.') ||
         ip.startsWith('172.31.') ||
         ip.startsWith('127.') ||
         ip.startsWith('::1') ||
         ip.startsWith('fc') ||
         ip.startsWith('fd');
}

/* ---------------------- Authentication Analysis ---------------------- */

function analyzeAuthentication(headers) {
  const result = {
    spf: { status: 'unknown', details: null },
    dkim: { status: 'unknown', details: null, signatures: [] },
    dmarc: { status: 'unknown', details: null },
    arc: { status: 'unknown', details: null },
    compauth: { status: 'unknown', details: null }
  };

  // Parse Authentication-Results header
  const authResults = headers['authentication-results'];
  if (authResults) {
    result.authenticationResultsRaw = authResults;

    // Extract SPF result
    const spfMatch = authResults.match(/spf=(\w+)(?:\s*\(([^\)]*)\))?/i);
    if (spfMatch) {
      result.spf.status = spfMatch[1].toLowerCase();
      result.spf.details = spfMatch[2] || null;
    }

    // Extract DKIM result
    const dkimMatch = authResults.match(/dkim=(\w+)(?:\s*\(([^\)]*)\))?/i);
    if (dkimMatch) {
      result.dkim.status = dkimMatch[1].toLowerCase();
      result.dkim.details = dkimMatch[2] || null;
    }

    // Extract DMARC result
    const dmarcMatch = authResults.match(/dmarc=(\w+)(?:\s*\(([^\)]*)\))?/i);
    if (dmarcMatch) {
      result.dmarc.status = dmarcMatch[1].toLowerCase();
      result.dmarc.details = dmarcMatch[2] || null;
    }

    // Extract compauth (Microsoft specific)
    const compauthMatch = authResults.match(/compauth=(\w+)(?:\s*reason=(\d+))?/i);
    if (compauthMatch) {
      result.compauth.status = compauthMatch[1].toLowerCase();
      result.compauth.reason = compauthMatch[2] || null;
    }
  }

  // Parse Received-SPF header (alternative SPF source)
  const receivedSpf = headers['received-spf'];
  if (receivedSpf && result.spf.status === 'unknown') {
    const spfStatusMatch = receivedSpf.match(/^(\w+)/);
    if (spfStatusMatch) {
      result.spf.status = spfStatusMatch[1].toLowerCase();
      result.spf.details = receivedSpf;
    }
  }

  // Parse DKIM-Signature headers
  const dkimSignatures = headers['dkim-signature'];
  if (dkimSignatures) {
    const signatures = Array.isArray(dkimSignatures) ? dkimSignatures : [dkimSignatures];
    for (const sig of signatures) {
      const dkimInfo = parseDKIMSignature(sig);
      result.dkim.signatures.push(dkimInfo);
    }
    if (result.dkim.status === 'unknown' && signatures.length > 0) {
      result.dkim.status = 'present';
    }
  }

  // Parse ARC headers
  const arcSeal = headers['arc-seal'];
  const arcMsgSig = headers['arc-message-signature'];
  const arcAuthResults = headers['arc-authentication-results'];

  if (arcSeal || arcMsgSig || arcAuthResults) {
    result.arc.status = 'present';
    result.arc.seals = arcSeal ? (Array.isArray(arcSeal) ? arcSeal.length : 1) : 0;
    result.arc.signatures = arcMsgSig ? (Array.isArray(arcMsgSig) ? arcMsgSig.length : 1) : 0;

    // Parse latest ARC-Authentication-Results
    if (arcAuthResults) {
      const latestArc = Array.isArray(arcAuthResults) ? arcAuthResults[0] : arcAuthResults;
      const arcValidMatch = latestArc.match(/arc=(\w+)/i);
      if (arcValidMatch) {
        result.arc.status = arcValidMatch[1].toLowerCase();
      }
    }
  }

  // Overall authentication summary
  result.overallStatus = determineOverallAuthStatus(result);

  return result;
}

function parseDKIMSignature(signature) {
  const result = {
    domain: null,
    selector: null,
    algorithm: null,
    headerFields: [],
    raw: signature
  };

  // Extract domain (d=)
  const domainMatch = signature.match(/d=([^;\s]+)/i);
  if (domainMatch) {
    result.domain = domainMatch[1];
  }

  // Extract selector (s=)
  const selectorMatch = signature.match(/s=([^;\s]+)/i);
  if (selectorMatch) {
    result.selector = selectorMatch[1];
  }

  // Extract algorithm (a=)
  const algoMatch = signature.match(/a=([^;\s]+)/i);
  if (algoMatch) {
    result.algorithm = algoMatch[1];
  }

  // Extract signed headers (h=)
  const headersMatch = signature.match(/h=([^;\s]+)/i);
  if (headersMatch) {
    result.headerFields = headersMatch[1].split(':').map(h => h.trim());
  }

  return result;
}

function determineOverallAuthStatus(auth) {
  const statuses = {
    pass: ['pass', 'passed'],
    fail: ['fail', 'failed', 'hardfail', 'permerror'],
    neutral: ['neutral', 'none', 'softfail', 'temperror'],
    unknown: ['unknown', 'present']
  };

  const spfPassed = statuses.pass.includes(auth.spf.status);
  const dkimPassed = statuses.pass.includes(auth.dkim.status);
  const dmarcPassed = statuses.pass.includes(auth.dmarc.status);

  const spfFailed = statuses.fail.includes(auth.spf.status);
  const dkimFailed = statuses.fail.includes(auth.dkim.status);
  const dmarcFailed = statuses.fail.includes(auth.dmarc.status);

  if (spfPassed && dkimPassed && dmarcPassed) return 'pass';
  if (dmarcFailed || (spfFailed && dkimFailed)) return 'fail';
  if (spfPassed || dkimPassed) return 'partial';
  if (spfFailed || dkimFailed) return 'warn';
  return 'unknown';
}

/* ---------------------- Security Analysis ---------------------- */

function performSecurityAnalysis(headers, deliveryPath, authentication) {
  const findings = [];

  // 1. Check for From/Return-Path mismatch (potential spoofing)
  const from = extractEmailAddress(headers['from']);
  const returnPath = extractEmailAddress(headers['return-path']);
  const replyTo = extractEmailAddress(headers['reply-to']);

  if (from && returnPath) {
    const fromDomain = extractDomain(from);
    const returnPathDomain = extractDomain(returnPath);

    if (fromDomain && returnPathDomain && fromDomain.toLowerCase() !== returnPathDomain.toLowerCase()) {
      findings.push({
        id: 'from_returnpath_mismatch',
        severity: 'medium',
        category: 'spoofing',
        title: 'From/Return-Path Domain Mismatch',
        description: `The From domain (${fromDomain}) differs from Return-Path domain (${returnPathDomain}). This may indicate email spoofing or use of third-party email services.`,
        details: { from, returnPath, fromDomain, returnPathDomain }
      });
    }
  }

  // 2. Check for Reply-To mismatch (common phishing indicator)
  if (from && replyTo) {
    const fromDomain = extractDomain(from);
    const replyToDomain = extractDomain(replyTo);

    if (fromDomain && replyToDomain && fromDomain.toLowerCase() !== replyToDomain.toLowerCase()) {
      findings.push({
        id: 'replyto_mismatch',
        severity: 'high',
        category: 'phishing',
        title: 'Reply-To Domain Mismatch',
        description: `Reply-To (${replyToDomain}) differs from From (${fromDomain}). This is a common phishing technique to redirect responses to attacker-controlled addresses.`,
        details: { from, replyTo, fromDomain, replyToDomain }
      });
    }
  }

  // 3. Check for missing critical headers
  if (!headers['message-id']) {
    findings.push({
      id: 'missing_message_id',
      severity: 'low',
      category: 'header_integrity',
      title: 'Missing Message-ID Header',
      description: 'Message-ID header is missing. Legitimate email servers typically include this header.',
      details: {}
    });
  }

  if (!headers['date']) {
    findings.push({
      id: 'missing_date',
      severity: 'low',
      category: 'header_integrity',
      title: 'Missing Date Header',
      description: 'Date header is missing. This is required by RFC 5322.',
      details: {}
    });
  }

  // 4. Check authentication failures
  if (authentication.spf.status === 'fail' || authentication.spf.status === 'hardfail') {
    findings.push({
      id: 'spf_fail',
      severity: 'high',
      category: 'authentication',
      title: 'SPF Authentication Failed',
      description: `SPF check failed: ${authentication.spf.details || 'The sending server is not authorized to send email for this domain.'}`,
      details: { status: authentication.spf.status, details: authentication.spf.details }
    });
  } else if (authentication.spf.status === 'softfail') {
    findings.push({
      id: 'spf_softfail',
      severity: 'medium',
      category: 'authentication',
      title: 'SPF Soft Fail',
      description: 'SPF returned softfail. The sending server may not be authorized for this domain.',
      details: { status: authentication.spf.status, details: authentication.spf.details }
    });
  }

  if (authentication.dkim.status === 'fail') {
    findings.push({
      id: 'dkim_fail',
      severity: 'high',
      category: 'authentication',
      title: 'DKIM Authentication Failed',
      description: `DKIM signature verification failed: ${authentication.dkim.details || 'The email may have been modified in transit or the signature is invalid.'}`,
      details: { status: authentication.dkim.status, details: authentication.dkim.details }
    });
  }

  if (authentication.dmarc.status === 'fail') {
    findings.push({
      id: 'dmarc_fail',
      severity: 'high',
      category: 'authentication',
      title: 'DMARC Authentication Failed',
      description: `DMARC policy check failed: ${authentication.dmarc.details || 'The email failed domain authentication requirements.'}`,
      details: { status: authentication.dmarc.status, details: authentication.dmarc.details }
    });
  }

  // 5. Check for suspicious X-Originating-IP
  const originatingIP = headers['x-originating-ip'] || headers['x-sender-ip'];
  if (originatingIP) {
    const cleanIP = originatingIP.replace(/[\[\]]/g, '');
    findings.push({
      id: 'originating_ip_exposed',
      severity: 'info',
      category: 'metadata',
      title: 'Originating IP Exposed',
      description: `The original sender IP address is visible: ${cleanIP}. This can be used for geolocation and reputation analysis.`,
      details: { ip: cleanIP }
    });
  }

  // 6. Check for spam headers
  const spamScore = headers['x-spam-score'] || headers['x-spam-status'];
  if (spamScore) {
    const scoreMatch = spamScore.match(/(\d+(?:\.\d+)?)/);
    if (scoreMatch) {
      const score = parseFloat(scoreMatch[1]);
      if (score >= 5) {
        findings.push({
          id: 'high_spam_score',
          severity: 'high',
          category: 'spam',
          title: 'High Spam Score Detected',
          description: `This email has a spam score of ${score}. It was likely flagged as suspicious by spam filters.`,
          details: { score, raw: spamScore }
        });
      } else if (score >= 3) {
        findings.push({
          id: 'elevated_spam_score',
          severity: 'medium',
          category: 'spam',
          title: 'Elevated Spam Score',
          description: `This email has a spam score of ${score}. Some spam characteristics were detected.`,
          details: { score, raw: spamScore }
        });
      }
    }
  }

  // 7. Check for missing TLS in delivery
  if (deliveryPath.hops && deliveryPath.hops.length > 0) {
    const nonTLSHops = deliveryPath.hops.filter(h => !h.tls && h.hopNumber > 1);
    if (nonTLSHops.length > 0) {
      findings.push({
        id: 'missing_tls',
        severity: 'medium',
        category: 'encryption',
        title: 'Unencrypted Email Transit Detected',
        description: `${nonTLSHops.length} hop(s) did not use TLS encryption. Email content may have been visible to intermediaries.`,
        details: { hops: nonTLSHops.map(h => h.hopNumber) }
      });
    }
  }

  // 8. Check for suspicious mailer
  const mailer = headers['x-mailer'] || headers['user-agent'];
  if (mailer) {
    const suspiciousMailers = ['PHPMailer', 'Swiftmailer', 'Perl', 'Python'];
    const suspiciousMatch = suspiciousMailers.find(m => mailer.toLowerCase().includes(m.toLowerCase()));
    if (suspiciousMatch) {
      findings.push({
        id: 'script_mailer',
        severity: 'low',
        category: 'metadata',
        title: 'Script-Based Email Client Detected',
        description: `Email was sent using ${suspiciousMatch}. While this can be legitimate, scripted senders are commonly used for phishing and spam campaigns.`,
        details: { mailer }
      });
    }
  }

  // 9. Check for display name spoofing
  const fromFull = headers['from'];
  if (fromFull) {
    const displayNameMatch = fromFull.match(/^["']?([^"'<]+)["']?\s*</);
    if (displayNameMatch) {
      const displayName = displayNameMatch[1].trim().toLowerCase();
      // Check if display name looks like an email address
      if (displayName.includes('@')) {
        findings.push({
          id: 'display_name_spoofing',
          severity: 'high',
          category: 'phishing',
          title: 'Possible Display Name Spoofing',
          description: 'The display name contains an email address, which may be used to trick recipients into thinking the email is from a different sender.',
          details: { from: fromFull }
        });
      }
      // Check for brand impersonation keywords
      const brandKeywords = ['microsoft', 'google', 'apple', 'amazon', 'paypal', 'bank', 'security', 'support', 'helpdesk', 'admin'];
      const brandMatch = brandKeywords.find(b => displayName.includes(b));
      if (brandMatch && from) {
        const fromDomain = extractDomain(from);
        if (fromDomain && !fromDomain.toLowerCase().includes(brandMatch)) {
          findings.push({
            id: 'brand_impersonation',
            severity: 'high',
            category: 'phishing',
            title: 'Possible Brand Impersonation',
            description: `Display name suggests "${brandMatch}" but the sender domain (${fromDomain}) does not match. This may be a phishing attempt.`,
            details: { displayName, fromDomain, brandMatch }
          });
        }
      }
    }
  }

  // 10. Check date anomalies
  const dateHeader = headers['date'];
  if (dateHeader) {
    try {
      const emailDate = new Date(dateHeader);
      const now = new Date();
      const diffMs = Math.abs(now.getTime() - emailDate.getTime());
      const diffDays = diffMs / (1000 * 60 * 60 * 24);

      // Future date
      if (emailDate > now && diffMs > 86400000) { // More than 1 day in future
        findings.push({
          id: 'future_date',
          severity: 'medium',
          category: 'timestamp',
          title: 'Future Date Detected',
          description: `The email date is set to the future (${emailDate.toISOString()}). This may indicate clock manipulation.`,
          details: { date: dateHeader }
        });
      }

      // Very old date
      if (diffDays > 30) {
        findings.push({
          id: 'old_date',
          severity: 'low',
          category: 'timestamp',
          title: 'Old Email Date',
          description: `The email is dated ${Math.round(diffDays)} days ago. Consider if this is expected.`,
          details: { date: dateHeader }
        });
      }
    } catch (e) {
      // Invalid date format
      findings.push({
        id: 'invalid_date',
        severity: 'low',
        category: 'header_integrity',
        title: 'Invalid Date Format',
        description: 'The Date header has an invalid format.',
        details: { date: dateHeader }
      });
    }
  }

  // Sort findings by severity
  const severityOrder = { 'high': 0, 'medium': 1, 'low': 2, 'info': 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return {
    findings,
    highCount: findings.filter(f => f.severity === 'high').length,
    mediumCount: findings.filter(f => f.severity === 'medium').length,
    lowCount: findings.filter(f => f.severity === 'low').length,
    infoCount: findings.filter(f => f.severity === 'info').length,
    totalFindings: findings.length
  };
}

function extractEmailAddress(headerValue) {
  if (!headerValue) return null;
  const match = headerValue.match(/<([^>]+)>/);
  if (match) return match[1];
  // Try to extract bare email
  const bareMatch = headerValue.match(/([^\s<>]+@[^\s<>]+)/);
  return bareMatch ? bareMatch[1] : null;
}

function extractDomain(email) {
  if (!email) return null;
  const parts = email.split('@');
  return parts.length === 2 ? parts[1] : null;
}

/* ---------------------- Key Headers Extraction ---------------------- */

function extractKeyHeaders(headers) {
  return {
    from: headers['from'] || null,
    to: headers['to'] || null,
    cc: headers['cc'] || null,
    subject: headers['subject'] || null,
    date: headers['date'] || null,
    messageId: headers['message-id'] || null,
    replyTo: headers['reply-to'] || null,
    returnPath: headers['return-path'] || null,
    contentType: headers['content-type'] || null,
    mimeVersion: headers['mime-version'] || null,
    xMailer: headers['x-mailer'] || headers['user-agent'] || null,
    xOriginatingIP: headers['x-originating-ip'] || headers['x-sender-ip'] || null,
    xPriority: headers['x-priority'] || null,
    importance: headers['importance'] || null,
    listUnsubscribe: headers['list-unsubscribe'] || null
  };
}

/* ---------------------- Summary Calculation ---------------------- */

function calculateSummary(securityAnalysis, authentication, deliveryPath) {
  let riskLevel = 'low';
  const recommendations = [];

  // Determine risk level based on findings
  if (securityAnalysis.highCount > 0) {
    riskLevel = 'high';
  } else if (securityAnalysis.mediumCount > 0) {
    riskLevel = 'medium';
  } else if (securityAnalysis.lowCount > 0) {
    riskLevel = 'low';
  } else {
    riskLevel = 'clean';
  }

  // Generate recommendations based on findings
  const findingCategories = new Set(securityAnalysis.findings.map(f => f.category));

  if (findingCategories.has('phishing')) {
    recommendations.push({
      priority: 'critical',
      action: 'Do not click any links or download attachments from this email. Verify sender identity through alternative channels.'
    });
  }

  if (findingCategories.has('spoofing')) {
    recommendations.push({
      priority: 'high',
      action: 'Verify the actual sender by checking the full email headers and Return-Path address.'
    });
  }

  if (findingCategories.has('authentication')) {
    if (authentication.overallStatus === 'fail') {
      recommendations.push({
        priority: 'high',
        action: 'Email authentication failed. This email may not be from who it claims to be.'
      });
    } else if (authentication.overallStatus === 'partial') {
      recommendations.push({
        priority: 'medium',
        action: 'Email authentication is partial. Some security checks passed but not all.'
      });
    }
  }

  if (findingCategories.has('encryption')) {
    recommendations.push({
      priority: 'medium',
      action: 'Email was transmitted without full encryption. Do not send sensitive information in replies.'
    });
  }

  // Add general recommendations
  if (riskLevel === 'clean') {
    recommendations.push({
      priority: 'info',
      action: 'No significant security issues detected. Standard email hygiene practices are still recommended.'
    });
  }

  return {
    riskLevel,
    riskScore: calculateRiskScore(securityAnalysis, authentication),
    authenticationStatus: authentication.overallStatus,
    totalHops: deliveryPath.totalHops,
    totalTransitTime: deliveryPath.totalTransitFormatted,
    findingsCount: {
      high: securityAnalysis.highCount,
      medium: securityAnalysis.mediumCount,
      low: securityAnalysis.lowCount,
      info: securityAnalysis.infoCount
    },
    recommendations
  };
}

function calculateRiskScore(securityAnalysis, authentication) {
  let score = 0;

  // Add points for findings
  score += securityAnalysis.highCount * 30;
  score += securityAnalysis.mediumCount * 15;
  score += securityAnalysis.lowCount * 5;

  // Add points for authentication failures
  if (authentication.spf.status === 'fail' || authentication.spf.status === 'hardfail') score += 20;
  if (authentication.dkim.status === 'fail') score += 20;
  if (authentication.dmarc.status === 'fail') score += 25;

  // Cap at 100
  return Math.min(100, score);
}
