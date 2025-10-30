# Azure Configuration for ThreatDefender Tools

This document outlines the Azure environment variables required for the ThreatDefender Operations Suite.

## Email Posture Check Configuration

The **Email Posture Check** feature requires the following Azure environment variable to enable MXToolbox API enrichment:

### Required Environment Variable

| Variable Name | Description | Required | Example Value |
|--------------|-------------|----------|---------------|
| `MXTOOLBOX_API_KEY` | Your MXToolbox API key for email health enrichment | Optional* | `87181cb2-80b7-484a-b0ee-9041c40224b4` |

\* **Note:** The Email Posture Check feature works without the MXToolbox API key. Native DNS analysis (SPF, DMARC, DKIM, MX, MTA-STS, BIMI) will always run. The MXToolbox API key provides additional enrichment data and email health scoring.

### How to Configure in Azure

#### Azure Portal Method:

1. Navigate to your **Azure Function App** in the Azure Portal
2. Go to **Configuration** → **Application settings**
3. Click **+ New application setting**
4. Add the following:
   - **Name:** `MXTOOLBOX_API_KEY`
   - **Value:** `87181cb2-80b7-484a-b0ee-9041c40224b4`
5. Click **OK**, then **Save**
6. Restart your Function App if necessary

#### Azure CLI Method:

```bash
az functionapp config appsettings set \
  --name <your-function-app-name> \
  --resource-group <your-resource-group> \
  --settings MXTOOLBOX_API_KEY="87181cb2-80b7-484a-b0ee-9041c40224b4"
```

#### Local Development:

For local testing, add the following to `/api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "",
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "MXTOOLBOX_API_KEY": "87181cb2-80b7-484a-b0ee-9041c40224b4"
  }
}
```

## Existing Environment Variables

The following environment variables are already configured for other features:

| Variable Name | Description | Feature |
|--------------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | Threat Intel Lookup |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | Threat Intel Lookup |
| `URLSCAN_API_KEY` | URLScan.io API key | Threat Intel Lookup |
| `GREYNOISE_API_KEY` | GreyNoise API key | Threat Intel Lookup |
| `SHODAN_API_KEY` | Shodan API key | Threat Intel Lookup |
| `ALIENVAULT_OTX_API_KEY` | AlienVault OTX API key | Threat Intel Lookup |
| `OPENAI_API_KEY` | Azure OpenAI API key | KQL Analyzer |

## Feature Behavior

### Email Posture Check

**With MXTOOLBOX_API_KEY configured:**
- ✅ Native DNS analysis (SPF, DMARC, DKIM, MX, MTA-STS, BIMI)
- ✅ MXToolbox Email Health Score
- ✅ MXToolbox enrichment data for SPF/DMARC/DKIM/MX
- ✅ Deep-link to MXToolbox SuperTool for detailed analysis

**Without MXTOOLBOX_API_KEY:**
- ✅ Native DNS analysis (SPF, DMARC, DKIM, MX, MTA-STS, BIMI)
- ❌ No MXToolbox enrichment data
- ❌ No Email Health Score

The feature is designed to work gracefully without the API key, ensuring that basic email security analysis is always available.

## Security Best Practices

1. **Never commit API keys** to source control
2. Store API keys as **Azure Application Settings** (encrypted at rest)
3. Use **Azure Key Vault** for production environments
4. Rotate API keys regularly according to your security policy
5. Monitor API key usage and set up alerts for unusual activity

## Troubleshooting

### Email Posture Check not showing MXToolbox data

**Symptom:** Email Posture Check runs but doesn't show MXToolbox Email Health Score

**Solution:**
1. Verify `MXTOOLBOX_API_KEY` is set in Azure Application Settings
2. Restart the Function App
3. Check the Function App logs for MXToolbox API errors
4. Verify your MXToolbox API key is valid and has sufficient quota

### API Rate Limiting

The Email Posture Check feature includes built-in caching (5-minute TTL) to reduce API calls and avoid rate limiting. If you encounter rate limits:

1. Check your MXToolbox API quota
2. Increase cache TTL in `/api/EmailPosture.js` (line 13)
3. Consider upgrading your MXToolbox API plan

## Support

For issues or questions about configuration:
- Check Azure Function App logs
- Review MXToolbox API documentation: https://mxtoolbox.com/api/
- Contact your Azure administrator for Function App configuration access
