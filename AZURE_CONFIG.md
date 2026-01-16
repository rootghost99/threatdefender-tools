# ThreatDefender Operations Suite - Environment Variables Reference

This document provides a comprehensive reference for all environment variables required by the ThreatDefender Operations Suite.

---

## Quick Reference

| Category | Variables Count | Required |
|----------|-----------------|----------|
| Azure Functions Runtime | 2 | Yes |
| Azure OpenAI | 3 | Yes |
| Azure Storage (Prompts) | 4 | Yes* |
| Azure Cosmos DB (Triage Chat) | 1 | Yes* |
| Claude AI (Triage Chat) | 3 | Yes* |
| Threat Intelligence APIs | 8 | Optional |

*Required for respective feature functionality

---

## Configuration Locations

### Local Development
Edit `/api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AzureWebJobsStorage": "",
    // Add all variables here
  }
}
```

### Azure Production
Azure Portal > Static Web App > Configuration > Application Settings

---

## Core Azure Functions Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FUNCTIONS_WORKER_RUNTIME` | Yes | - | Must be `node` |
| `AzureWebJobsStorage` | No | - | Can be empty for local dev |

---

## Azure OpenAI Configuration

Required for: KQL Analyzer, IR Playbook Generator, Prompt Gallery execution

| Variable | Required | Default | Example | Description |
|----------|----------|---------|---------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Yes | - | `https://your-openai.openai.azure.com/` | Azure OpenAI service endpoint URL |
| `AZURE_OPENAI_API_KEY` | Yes | - | `abc123def456...` | Azure OpenAI API key |
| `AZURE_OPENAI_DEPLOYMENT` | No | `gpt-4` | `gpt-4` | Model deployment name |

### How to Get Azure OpenAI Credentials

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your Azure OpenAI resource
3. Click **Keys and Endpoint** in the left menu
4. Copy:
   - **Endpoint** URL
   - **KEY 1** or **KEY 2**
5. Click **Model deployments** > **Manage Deployments**
6. Note your deployment name (e.g., `gpt-4`)

---

## Azure Storage Configuration (Prompt Gallery)

Required for: Prompt Gallery feature

| Variable | Required | Default | Example | Description |
|----------|----------|---------|---------|-------------|
| `AZURE_STORAGE_ACCOUNT_NAME` | Yes | - | `threatdefenderstorage` | Storage account name (lowercase) |
| `AZURE_STORAGE_ACCOUNT_KEY` | Yes | - | `abc123...` | Primary or secondary access key |
| `PROMPTS_TABLE_NAME` | No | `Prompts` | `Prompts` | Table name for prompt storage |
| `PROMPT_RUNS_TABLE_NAME` | No | `PromptRuns` | `PromptRuns` | Table name for execution logs |

### How to Get Storage Credentials

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your Storage Account
3. Click **Access Keys** in the left menu
4. Copy:
   - **Storage account name** (from the overview)
   - **key1** or **key2** value

### Creating Required Tables

Tables are auto-created on first use, or create manually:

**Azure Portal:**
1. Storage Account > Storage Browser > Tables
2. Click **Add Table**
3. Create `Prompts` and `PromptRuns`

**Azure CLI:**
```bash
az storage table create --name Prompts --account-name <your-account>
az storage table create --name PromptRuns --account-name <your-account>
```

---

## Azure Cosmos DB Configuration (AI Triage Chat)

Required for: AI Triage Chat feature

| Variable | Required | Default | Example | Description |
|----------|----------|---------|---------|-------------|
| `COSMOS_CONNECTION` | Yes | - | `AccountEndpoint=https://...;AccountKey=...` | Full Cosmos DB connection string |

### Connection String Format

```
AccountEndpoint=https://your-cosmos.documents.azure.com:443/;AccountKey=your-key-here==
```

### How to Get Cosmos DB Credentials

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to your Cosmos DB account
3. Click **Keys** in the left menu
4. Copy **PRIMARY CONNECTION STRING** or **SECONDARY CONNECTION STRING**

### Required Database Structure

- **Database:** `TriageDB`
- **Container:** `Sessions`
- **Partition Key:** `/incidentId`

---

## Claude AI Configuration (AI Triage Chat)

Required for: AI Triage Chat feature

| Variable | Required | Default | Example | Description |
|----------|----------|---------|---------|-------------|
| `CLAUDE_API_ENDPOINT` | Yes | - | `https://your-service.services.ai.azure.com/anthropic/v1/messages` | Azure AI Foundry Claude endpoint |
| `CLAUDE_API_KEY` | Yes | - | `xyz789...` | Claude API key |
| `CLAUDE_MODEL` | No | `claude-sonnet-4-20250514` | `claude-sonnet-4-20250514` | Claude model identifier |

### How to Get Claude API Credentials

1. Go to [Azure AI Foundry](https://ai.azure.com)
2. Navigate to your deployment
3. Find the Anthropic/Claude model deployment
4. Copy endpoint URL and API key from deployment details

---

## Threat Intelligence API Keys

All threat intel API keys are **optional**. Features gracefully degrade when keys are unavailable.

| Variable | Service | Indicators Supported | Free Tier | How to Get |
|----------|---------|---------------------|-----------|------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal | IP, Domain, URL, Hash | Yes (rate limited) | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP | Yes | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| `GREYNOISE_API_KEY` | GreyNoise | IP | Yes (Community) | [viz.greynoise.io/account/api-key](https://viz.greynoise.io/account/api-key) |
| `SHODAN_API_KEY` | Shodan | IP | Yes (limited) | [account.shodan.io](https://account.shodan.io/) |
| `ALIENVAULT_OTX_API_KEY` | AlienVault OTX | IP, Domain, URL, Hash | Yes | [otx.alienvault.com/api](https://otx.alienvault.com/api) |
| `URLSCAN_API_KEY` | URLScan.io | URL, Domain | Yes | [urlscan.io/user/profile](https://urlscan.io/user/profile/) |
| `MXTOOLBOX_API_KEY` | MXToolbox | Domain (Email) | Limited | [mxtoolbox.com/user/api](https://mxtoolbox.com/user/api/) |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis | Hash, URL | Yes | [hybrid-analysis.com/my-account?tab=api-key](https://www.hybrid-analysis.com/my-account?tab=api-key) |

### ARIN RDAP (No Key Required)
The ARIN RDAP service provides IP ownership data and does not require an API key. This source is always available as a fallback.

---

## Feature Availability by Configuration

| Feature | Azure OpenAI | Storage | Cosmos DB | Claude | TI APIs |
|---------|--------------|---------|-----------|--------|---------|
| KQL Diff Viewer | Required | - | - | - | - |
| KQL AI Analysis | Required | - | - | - | - |
| IR Playbook Generator | Required | - | - | - | - |
| Prompt Gallery Browse | - | Required | - | - | - |
| Prompt Execution | Required | Required | - | - | - |
| Email Posture Check | - | - | - | - | Optional |
| Threat Intel Lookup | - | - | - | - | Optional |
| AI Triage Chat | - | - | Required | Required | - |
| SOC Handoff | - | - | - | - | - |

---

## Complete local.settings.json Template

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AzureWebJobsStorage": "",

    "AZURE_OPENAI_ENDPOINT": "https://your-openai.openai.azure.com/",
    "AZURE_OPENAI_API_KEY": "your-openai-api-key",
    "AZURE_OPENAI_DEPLOYMENT": "gpt-4",

    "AZURE_STORAGE_ACCOUNT_NAME": "your-storage-account",
    "AZURE_STORAGE_ACCOUNT_KEY": "your-storage-key",
    "PROMPTS_TABLE_NAME": "Prompts",
    "PROMPT_RUNS_TABLE_NAME": "PromptRuns",

    "COSMOS_CONNECTION": "AccountEndpoint=https://your-cosmos.documents.azure.com:443/;AccountKey=your-key==",

    "CLAUDE_API_ENDPOINT": "https://your-service.services.ai.azure.com/anthropic/v1/messages",
    "CLAUDE_API_KEY": "your-claude-api-key",
    "CLAUDE_MODEL": "claude-sonnet-4-20250514",

    "VIRUSTOTAL_API_KEY": "your-virustotal-key",
    "ABUSEIPDB_API_KEY": "your-abuseipdb-key",
    "GREYNOISE_API_KEY": "your-greynoise-key",
    "SHODAN_API_KEY": "your-shodan-key",
    "ALIENVAULT_OTX_API_KEY": "your-alienvault-key",
    "URLSCAN_API_KEY": "your-urlscan-key",
    "MXTOOLBOX_API_KEY": "your-mxtoolbox-key",
    "HYBRID_ANALYSIS_API_KEY": "your-hybrid-analysis-key"
  }
}
```

---

## Security Best Practices

1. **Never commit API keys** to source control
   - `api/local.settings.json` is already in `.gitignore`

2. **Use Azure Key Vault** for production (recommended)
   - Reference secrets from Key Vault in App Settings

3. **Rotate keys regularly**
   - Set calendar reminders for key rotation
   - Most services support multiple active keys for zero-downtime rotation

4. **Use least-privilege access**
   - Create read-only API keys where possible
   - Use SAS tokens with limited scope for storage

5. **Monitor API usage**
   - Set up alerts for unusual activity
   - Review API call logs regularly

---

## Troubleshooting

### "Azure Storage credentials not configured"
- Verify `AZURE_STORAGE_ACCOUNT_NAME` and `AZURE_STORAGE_ACCOUNT_KEY` are set
- Check for typos in variable names
- Ensure no extra whitespace in values

### "Azure OpenAI credentials not configured"
- Verify `AZURE_OPENAI_ENDPOINT` format includes trailing slash
- Check `AZURE_OPENAI_DEPLOYMENT` matches your actual deployment name

### "Cosmos DB connection failed"
- Verify `COSMOS_CONNECTION` is the full connection string
- Check firewall rules allow Azure Functions access
- Ensure database and container exist

### "Threat Intel API not returning data"
- Verify API key is valid and has not expired
- Check rate limits haven't been exceeded
- Some APIs require account verification

### API key changes not taking effect
- After changing Azure App Settings, wait 1-2 minutes
- For local development, restart the Azure Functions host

---

## Related Documentation

- [DEV_SETUP.md](DEV_SETUP.md) - Local development setup
- [PROMPT_GALLERY_SETUP.md](PROMPT_GALLERY_SETUP.md) - Detailed Prompt Gallery configuration
- [AI_TRIAGE_CHAT_SETUP.md](AI_TRIAGE_CHAT_SETUP.md) - AI Triage Chat configuration
- [THREAT_INTEL_SETUP.md](THREAT_INTEL_SETUP.md) - Threat intelligence API setup
- [HYBRID_ANALYSIS_SETUP.md](HYBRID_ANALYSIS_SETUP.md) - Hybrid Analysis integration
