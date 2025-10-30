# Hybrid Analysis Integration Setup

This document explains how to configure the Hybrid Analysis integration for the ThreatDefender Tools application.

## Overview

The Hybrid Analysis integration provides deep malware behavioral analysis including:
- Malware family detection
- MITRE ATT&CK technique mappings
- Network indicators of compromise (IoCs)
- Process trees and behavioral analysis
- Extracted/dropped files analysis

## Prerequisites

1. A Hybrid Analysis API key from https://www.hybrid-analysis.com/
2. Azure Static Web App deployed

## Configuration Steps

### Local Development

For local testing, the API key is stored in `api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AzureWebJobsStorage": "",
    "HYBRID_ANALYSIS_API_KEY": "your-api-key-here"
  }
}
```

**Note**: This file is not deployed to Azure and should be in `.gitignore`.

### Azure Production Environment

#### Method 1: Azure Portal

1. Navigate to https://portal.azure.com
2. Open your Static Web App resource
3. Go to **Configuration** (under Settings)
4. Click **+ Add** under Application settings
5. Add the setting:
   - **Name**: `HYBRID_ANALYSIS_API_KEY`
   - **Value**: Your Hybrid Analysis API key
6. Click **OK** then **Save**
7. Wait 1-2 minutes for the configuration to propagate

#### Method 2: Azure CLI

```bash
az staticwebapp appsettings set \
  --name <your-static-web-app-name> \
  --setting-names HYBRID_ANALYSIS_API_KEY=<your-api-key>
```

#### Method 3: GitHub Secrets (CI/CD)

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add:
   - **Name**: `HYBRID_ANALYSIS_API_KEY`
   - **Secret**: Your API key
5. Update your GitHub Actions workflow to pass this as an application setting during deployment

## Verifying the Integration

After configuration:

1. Wait 1-2 minutes for Azure to apply the settings
2. Refresh your application (hard refresh: Ctrl+F5 or Cmd+Shift+R)
3. Perform a threat intel lookup with a hash or URL
4. The Hybrid Analysis section should appear with analysis results

### Test Indicators

Use these known malicious samples to verify the integration:

**MD5 Hash:**
```
44d88612fea8a8f36de82e1278abb02f
```

**SHA256 Hashes:**
```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (Emotet)
8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
```

## Troubleshooting

### Error: "Hybrid Analysis API key not configured"

**Cause**: The environment variable is not set in Azure.

**Solution**: Follow the Azure configuration steps above.

### No Results Displayed

**Possible causes:**
1. The indicator hasn't been analyzed by Hybrid Analysis yet
2. API key is invalid
3. Rate limiting

**Check browser console** (F12) for detailed error messages.

### Supported Indicator Types

Hybrid Analysis supports:
- ✅ MD5 hashes (32 characters)
- ✅ SHA1 hashes (40 characters)
- ✅ SHA256 hashes (64 characters)
- ✅ URLs (http:// or https://)

Not supported:
- ❌ IP addresses
- ❌ Domain names (without http://)

For IPs and domains, use the other integrated threat intel sources (VirusTotal, AbuseIPDB, URLScan, etc.).

## API Endpoints

### Backend
- **Endpoint**: `/api/HybridAnalysisLookup`
- **Method**: POST
- **Body**: `{ "indicator": "hash or URL" }`

### Frontend
The integration is built into the **ThreatIntelLookup** component and calls the API automatically when you perform a lookup.

## Features Displayed

When analysis data is available, you'll see:

1. **Verdict Badge**: Clean, Suspicious, or Malicious with color coding
2. **Threat Score**: 0-100 scale
3. **Behavior Summary**: Process, domain, and file counts
4. **Detected Families**: Malware family names
5. **MITRE ATT&CK Techniques**: Mapped tactics and techniques
6. **Network IoCs**: Domains, compromised hosts, contacted hosts
7. **Process Tree**: Executed processes with PIDs
8. **Extracted Files**: Dropped files with threat scores
9. **Analysis Metadata**: Environment, date, submission details
10. **Full Report Link**: Direct link to Hybrid Analysis website

## Rate Limits

Hybrid Analysis has API rate limits depending on your account tier. Consult their documentation at https://www.hybrid-analysis.com/docs/api/v2 for details.

## Support

For issues with:
- **API key**: Contact Hybrid Analysis support
- **Integration**: Check browser console and Azure Function logs
- **Missing data**: The sample may not have been analyzed yet

## Security Note

**Never commit API keys to source control!**

- Keep `api/local.settings.json` in `.gitignore`
- Use Azure Application Settings or GitHub Secrets for production keys
- Rotate keys periodically for security
