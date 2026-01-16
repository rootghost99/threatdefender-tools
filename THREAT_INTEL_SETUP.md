# Threat Intelligence APIs - Setup Guide

This guide covers the configuration of all threat intelligence API integrations for the ThreatDefender Operations Suite.

---

## Overview

The Threat Intel Lookup feature queries 8+ external threat intelligence sources in parallel:

| Source | Indicators | Free Tier | Rate Limit | API Required |
|--------|------------|-----------|------------|--------------|
| VirusTotal | IP, Domain, URL, Hash | Yes | 4/min | Yes |
| AbuseIPDB | IP | Yes | 1000/day | Yes |
| GreyNoise | IP | Yes (Community) | 50/day | Yes |
| Shodan | IP | Yes | 100/month | Yes |
| AlienVault OTX | IP, Domain, URL, Hash | Yes | 10000/day | Yes |
| URLScan.io | URL, Domain | Yes | 100/day | Yes |
| MXToolbox | Domain (Email) | Limited | Varies | Optional |
| Hybrid Analysis | Hash, URL | Yes | 200/day | Yes |
| ARIN RDAP | IP | Yes | Unlimited | No |

**Note:** All APIs are optional. The feature gracefully degrades when keys are unavailable, querying only configured sources.

---

## Quick Start

1. Get API keys from the sources you want to use (see sections below)
2. Add keys to `api/local.settings.json` (local) or Azure App Settings (production)
3. Restart the backend
4. Test with a known indicator

---

## API Configuration

### VirusTotal

**Purpose:** Comprehensive file, URL, IP, and domain reputation data.

**Sign Up:** https://www.virustotal.com/gui/join-us

**Get API Key:**
1. Log in to VirusTotal
2. Click your profile icon → API Key
3. Copy the API key

**Free Tier Limits:**
- 4 requests per minute
- 500 requests per day
- 15,500 requests per month

**Environment Variable:**
```
VIRUSTOTAL_API_KEY=your-api-key-here
```

**Indicators Supported:**
- IPv4/IPv6 addresses
- Domains
- URLs
- MD5, SHA1, SHA256 hashes

---

### AbuseIPDB

**Purpose:** IP abuse reports and confidence scores from community reports.

**Sign Up:** https://www.abuseipdb.com/register

**Get API Key:**
1. Log in to AbuseIPDB
2. Go to API tab
3. Create/copy API key

**Free Tier Limits:**
- 1,000 checks per day
- Additional checks with contribution credits

**Environment Variable:**
```
ABUSEIPDB_API_KEY=your-api-key-here
```

**Indicators Supported:**
- IPv4/IPv6 addresses only

**Response Data:**
- Abuse confidence score (0-100)
- Total reports
- Last reported date
- ISP information
- Country code

---

### GreyNoise

**Purpose:** IP classification distinguishing between benign scanners, malicious actors, and unknown.

**Sign Up:** https://viz.greynoise.io/signup

**Get API Key:**
1. Log in to GreyNoise
2. Go to Account → API Key
3. Copy the API key

**Free Tier (Community):**
- 50 requests per day
- Limited to IP lookups
- No context on benign actors

**Environment Variable:**
```
GREYNOISE_API_KEY=your-api-key-here
```

**Indicators Supported:**
- IPv4 addresses only

**Response Classifications:**
- `benign` - Known good actor (scanner, security company)
- `malicious` - Known bad actor
- `unknown` - Not seen by GreyNoise

---

### Shodan

**Purpose:** Internet-wide scanning data including open ports, services, and banners.

**Sign Up:** https://account.shodan.io/register

**Get API Key:**
1. Log in to Shodan
2. Go to Account
3. Copy API key

**Free Tier:**
- 100 query credits per month
- Basic search capabilities

**Environment Variable:**
```
SHODAN_API_KEY=your-api-key-here
```

**Indicators Supported:**
- IPv4 addresses only

**Response Data:**
- Open ports
- Running services
- Banners/versions
- Hostnames
- Organization
- ASN information
- Vulnerabilities (paid)

---

### AlienVault OTX

**Purpose:** Open Threat Exchange - community-driven threat intelligence with pulse data.

**Sign Up:** https://otx.alienvault.com/

**Get API Key:**
1. Log in to OTX
2. Go to Settings → API Integration
3. Copy API key

**Free Tier:**
- 10,000 requests per day
- Full access to pulses

**Environment Variable:**
```
ALIENVAULT_OTX_API_KEY=your-api-key-here
```

**Indicators Supported:**
- IPv4/IPv6 addresses
- Domains
- URLs
- MD5, SHA1, SHA256 hashes

**Response Data:**
- Pulse count
- Related pulses with descriptions
- Tags and indicators
- Reputation score

---

### URLScan.io

**Purpose:** URL and domain behavioral analysis through sandboxed browser scanning.

**Sign Up:** https://urlscan.io/user/signup

**Get API Key:**
1. Log in to URLScan
2. Go to Profile → API
3. Copy API key

**Free Tier:**
- 100 scans per day
- 1,000 API requests per day

**Environment Variable:**
```
URLSCAN_API_KEY=your-api-key-here
```

**Indicators Supported:**
- URLs
- Domains

**Response Data:**
- Scan results
- Screenshot (link)
- Technologies detected
- DOM content
- Network requests
- Malicious verdicts

---

### MXToolbox

**Purpose:** Email and DNS infrastructure analysis, DKIM/SPF/DMARC checks.

**Sign Up:** https://mxtoolbox.com/user/api/

**Get API Key:**
1. Create MXToolbox account
2. Go to API section
3. Subscribe to API plan
4. Copy API key

**Pricing:**
- Limited free queries
- Paid plans for more volume

**Environment Variable:**
```
MXTOOLBOX_API_KEY=your-api-key-here
```

**Indicators Supported:**
- Domains (for email security checks)

**Response Data:**
- Email health score
- Blacklist status
- SPF/DKIM/DMARC records
- MX record analysis

**Note:** MXToolbox is optional. The Email Posture Check feature works without it using native DNS queries.

---

### Hybrid Analysis

**Purpose:** Malware sandbox analysis with behavioral and static analysis.

**Sign Up:** https://www.hybrid-analysis.com/signup

**Get API Key:**
1. Log in to Hybrid Analysis
2. Go to My Account → API Key tab
3. Copy API key

**Free Tier:**
- 200 API calls per day
- Access to public reports

**Environment Variable:**
```
HYBRID_ANALYSIS_API_KEY=your-api-key-here
```

**Indicators Supported:**
- MD5, SHA1, SHA256 hashes
- URLs

**Response Data:**
- Verdict (malicious/suspicious/clean)
- Threat score (0-100)
- Malware families detected
- MITRE ATT&CK techniques
- Network indicators
- Process tree
- Dropped files
- Full analysis report link

See [HYBRID_ANALYSIS_SETUP.md](HYBRID_ANALYSIS_SETUP.md) for detailed setup instructions.

---

### ARIN RDAP

**Purpose:** IP address ownership and allocation information.

**No API Key Required!**

ARIN RDAP is a free, public service that always works as a fallback for IP lookups.

**Indicators Supported:**
- IPv4/IPv6 addresses

**Response Data:**
- Network name
- Organization
- Handle
- Address range
- Registration date

---

## Configuration Examples

### Local Development

Edit `api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",

    "VIRUSTOTAL_API_KEY": "your-vt-key",
    "ABUSEIPDB_API_KEY": "your-abuseipdb-key",
    "GREYNOISE_API_KEY": "your-greynoise-key",
    "SHODAN_API_KEY": "your-shodan-key",
    "ALIENVAULT_OTX_API_KEY": "your-otx-key",
    "URLSCAN_API_KEY": "your-urlscan-key",
    "MXTOOLBOX_API_KEY": "your-mxtoolbox-key",
    "HYBRID_ANALYSIS_API_KEY": "your-ha-key"
  }
}
```

### Azure Production

Azure Portal → Static Web App → Configuration → Application Settings

Add each key as an application setting.

---

## Indicator Type Detection

The system automatically detects indicator types:

| Pattern | Detected Type | Sources Queried |
|---------|---------------|-----------------|
| `1.2.3.4` | IPv4 | VT, AbuseIPDB, GreyNoise, Shodan, OTX, ARIN |
| `2001:db8::1` | IPv6 | VT, AbuseIPDB, OTX, ARIN |
| `example.com` | Domain | VT, OTX, URLScan |
| `https://example.com/path` | URL | VT, URLScan, Hybrid Analysis |
| `d41d8cd98f00b204e9800998ecf8427e` (32 chars) | MD5 | VT, OTX, Hybrid Analysis |
| `da39a3ee5e6b4b0d3255bfef95601890afd80709` (40 chars) | SHA1 | VT, OTX, Hybrid Analysis |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (64 chars) | SHA256 | VT, OTX, Hybrid Analysis |
| `user@example.com` | Email | MXToolbox |

---

## Rate Limit Handling

The application handles rate limits gracefully:

1. **Parallel Queries:** All sources are queried simultaneously
2. **Individual Failures:** If one source fails, others still return data
3. **Error Messages:** Rate limit errors are displayed per source
4. **Retry Logic:** No automatic retry (to respect rate limits)

**Best Practices:**
- Don't spam lookups for the same indicator
- Consider caching results on your end
- Upgrade to paid tiers for high-volume use

---

## Testing the Integration

### Test with Known Indicators

**Benign IP (Google DNS):**
```
8.8.8.8
```
Expected: Low/no threat scores, classified as benign by GreyNoise

**Known Malicious Hash (EICAR test file):**
```
44d88612fea8a8f36de82e1278abb02f
```
Expected: High detection rates from VT, malicious verdict

**Domain:**
```
google.com
```
Expected: Clean reputation, no issues

### Verify Each Source

1. Navigate to Threat Intel Lookup
2. Enter test indicator
3. Check that each configured source returns data
4. Verify unconfigured sources show "Not configured"

---

## Troubleshooting

### "API key not configured"
- Verify the environment variable name is correct
- Check for typos in the key value
- Restart the backend after adding keys

### "Rate limited" errors
- Wait for rate limit window to reset
- Check your quota on the provider's dashboard
- Consider upgrading to paid tier

### No data returned
- Check browser console for errors
- Verify indicator type is supported by that source
- Some sources don't have data for all indicators

### Timeout errors
- External APIs may be slow or unavailable
- The application has 30-second timeouts per source
- Results from faster sources still display

### "Invalid API key"
- Regenerate the API key on provider's site
- Check for trailing/leading whitespace
- Verify the key hasn't been revoked

---

## Security Best Practices

1. **Never commit API keys** to source control
2. **Use separate keys** for development and production
3. **Monitor usage** on each provider's dashboard
4. **Rotate keys** periodically
5. **Use IP allowlisting** where supported (paid features)
6. **Review audit logs** for unusual activity

---

## Cost Optimization

### Free Tier Strategies
- Query only necessary sources
- Avoid duplicate lookups
- Cache results when possible
- Use community/free tiers appropriately

### When to Upgrade
- Hitting rate limits regularly
- Need additional features (Shodan CVEs, etc.)
- Production/MSSP use cases
- SLA requirements

---

## Related Documentation

- [AZURE_CONFIG.md](AZURE_CONFIG.md) - All environment variables
- [HYBRID_ANALYSIS_SETUP.md](HYBRID_ANALYSIS_SETUP.md) - Detailed Hybrid Analysis setup
- [FEATURES_OVERVIEW.md](FEATURES_OVERVIEW.md) - Feature reference
- [API_REFERENCE.md](API_REFERENCE.md) - API endpoints
