# Prompt Gallery — Azure Configuration Guide

## Quick Reference: Azure Services Required

| Azure Service | Status | Purpose | Estimated Cost |
|--------------|--------|---------|----------------|
| **Azure Storage Account** | ✅ NEW - Must Create | Store prompts and execution history | $5-10/month |
| **Azure OpenAI** | ♻️ REUSE EXISTING | Power AI prompt execution | Already configured |
| **Azure Static Web Apps** | ♻️ REUSE EXISTING | Host application | Already configured |

---

## Environment Variables Configuration

### Overview

All environment variables must be configured in **TWO** locations:

1. **Local Development**: `/api/local.settings.json` (for testing locally)
2. **Azure Production**: Azure Portal → Static Web App → Configuration → Application Settings

---

### Complete Environment Variables Table

| Variable Name | Required | Source | Example Value | Description |
|--------------|----------|--------|---------------|-------------|
| **Storage Configuration** |
| `AZURE_STORAGE_ACCOUNT_NAME` | ✅ Yes | Azure Storage Account → Overview | `threatdefenderstorage` | Storage account name (lowercase, no spaces) |
| `AZURE_STORAGE_ACCOUNT_KEY` | ✅ Yes | Azure Storage Account → Access Keys → Key1 | `abc123def456...` | Primary access key (long base64 string) |
| `PROMPTS_TABLE_NAME` | ⚙️ Optional | Manual | `Prompts` | Table for storing prompts (default: `Prompts`) |
| `PROMPT_RUNS_TABLE_NAME` | ⚙️ Optional | Manual | `PromptRuns` | Table for storing runs (default: `PromptRuns`) |
| **Azure OpenAI Configuration** |
| `AZURE_OPENAI_ENDPOINT` | ✅ Yes | Azure OpenAI → Keys and Endpoint | `https://your-openai.openai.azure.com/` | OpenAI service endpoint URL |
| `AZURE_OPENAI_API_KEY` | ✅ Yes | Azure OpenAI → Keys and Endpoint → Key1 | `xyz789abc123...` | OpenAI API key |
| `AZURE_OPENAI_DEPLOYMENT` | ⚙️ Optional | Azure OpenAI → Deployments | `gpt-4` | Model deployment name (default: `gpt-4`) |

**Legend**:
- ✅ Required - Must be configured
- ⚙️ Optional - Has default value if not specified

---

## Step-by-Step Setup Instructions

### Step 1: Create Azure Storage Account (NEW)

1. **Navigate to Azure Portal**
   - Go to [portal.azure.com](https://portal.azure.com)
   - Click **Create a resource** → Search for **Storage Account** → Click **Create**

2. **Configure Basic Settings**
   - **Subscription**: Choose your subscription
   - **Resource Group**: Use existing (e.g., same as your Static Web App)
   - **Storage account name**: Choose unique name (e.g., `threatdefenderstorage`)
   - **Region**: Same as your other resources
   - **Performance**: **Standard**
   - **Redundancy**: **Locally-redundant storage (LRS)**

3. **Review and Create**
   - Click **Review + Create**
   - Click **Create**
   - Wait for deployment to complete (~30 seconds)

4. **Get Access Credentials**
   - Go to your new Storage Account
   - In left menu, click **Access Keys**
   - Copy:
     - **Storage account name** (from the top)
     - **key1** → Click **Show** → Copy the key value

5. **Create Tables** (Optional - auto-created on first use)
   - In left menu, click **Storage Browser**
   - Click **Tables**
   - Click **Add Table** → Name: `Prompts` → Click **OK**
   - Click **Add Table** → Name: `PromptRuns` → Click **OK**

---

### Step 2: Verify Azure OpenAI Configuration (EXISTING)

**Check if Already Configured**:
- You already have Azure OpenAI configured for IR Playbook Generator and KQL Analyzer
- You can reuse the same service - **no new resource needed**

**Get Your Existing Credentials**:
1. Go to Azure Portal → Search for **Azure OpenAI**
2. Click on your OpenAI resource
3. In left menu, click **Keys and Endpoint**
4. Copy:
   - **Endpoint** (e.g., `https://your-openai.openai.azure.com/`)
   - **KEY 1** value
5. In left menu, click **Model deployments** → **Manage Deployments**
6. Note your **Deployment name** (e.g., `gpt-4` or `gpt-35-turbo`)

**If Not Already Configured**:
- You'll need to create a new Azure OpenAI resource
- Note: Azure OpenAI requires access approval (can take 1-2 business days)
- See `PROMPT_GALLERY_SETUP.md` for detailed setup instructions

---

### Step 3: Configure Local Development Environment

Edit `/api/local.settings.json` and fill in your values:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AzureWebJobsStorage": "",

    "AZURE_STORAGE_ACCOUNT_NAME": "your-storage-account-name",
    "AZURE_STORAGE_ACCOUNT_KEY": "your-storage-account-key-from-step-1",
    "PROMPTS_TABLE_NAME": "Prompts",
    "PROMPT_RUNS_TABLE_NAME": "PromptRuns",

    "AZURE_OPENAI_ENDPOINT": "https://your-openai.openai.azure.com/",
    "AZURE_OPENAI_API_KEY": "your-openai-key-from-step-2",
    "AZURE_OPENAI_DEPLOYMENT": "gpt-4"
  }
}
```

**Important**:
- Replace all placeholder values with your actual credentials
- Never commit this file to git (already in `.gitignore`)

---

### Step 4: Configure Azure Production Environment

Add environment variables to your deployed Static Web App:

1. **Navigate to Static Web App**
   - Go to Azure Portal
   - Find your **Static Web App** resource
   - Click to open it

2. **Open Configuration**
   - In left menu, click **Configuration**
   - You should see existing Application Settings

3. **Add New Application Settings**
   - Click **+ Add** for each variable below
   - Enter **Name** and **Value**
   - Click **OK**

   Add these settings:

   | Name | Value |
   |------|-------|
   | `AZURE_STORAGE_ACCOUNT_NAME` | *your storage account name from Step 1* |
   | `AZURE_STORAGE_ACCOUNT_KEY` | *your storage key from Step 1* |
   | `PROMPTS_TABLE_NAME` | `Prompts` |
   | `PROMPT_RUNS_TABLE_NAME` | `PromptRuns` |
   | `AZURE_OPENAI_ENDPOINT` | *your OpenAI endpoint from Step 2* |
   | `AZURE_OPENAI_API_KEY` | *your OpenAI key from Step 2* |
   | `AZURE_OPENAI_DEPLOYMENT` | *your deployment name from Step 2* |

4. **Save Configuration**
   - Click **Save** at the top
   - Configuration will be applied automatically

---

### Step 5: Deploy to Production

Your GitHub Actions workflow will automatically deploy when you push to `main`:

1. **Merge Your Branch** (or push to main)
   ```bash
   # If working with PR, merge via GitHub UI
   # Or push directly to main if you have permissions
   ```

2. **Monitor Deployment**
   - Go to GitHub → Your repository → **Actions** tab
   - Watch the deployment workflow run
   - Deployment takes ~3-5 minutes

3. **Verify Deployment**
   - Once complete, navigate to your app URL
   - Click on **📚 Prompt Gallery** tab
   - You should see the empty gallery with "Create First Prompt" button

---

### Step 6: Test the Feature

1. **Create Your First Prompt**
   - Click **➕ New Prompt**
   - Fill in:
     - **Title**: "Test Prompt"
     - **Description**: "Testing Prompt Gallery"
     - **Category**: "General"
     - **User Instructions**: "Summarize this security event: {{context}}"
   - Click **Create Prompt**

2. **Run the Prompt**
   - Click on your new prompt card
   - In **Context** field, paste: "Suspicious login from IP 192.168.1.100"
   - Click **▶️ Run Prompt**
   - You should see AI-generated output

3. **Check Audit Trail**
   - Click **📊 Audit**
   - You should see your prompt run logged
   - Verify token usage is displayed

4. **Verify Data in Azure**
   - Go to Azure Portal → Your Storage Account
   - Click **Storage Browser** → **Tables**
   - Click on **Prompts** → You should see 1 entry
   - Click on **PromptRuns** → You should see 1 entry

---

## Pre-Production Checklist

Complete these steps before using Prompt Gallery in production:

### Azure Resources
- [ ] Azure Storage Account created and accessible
- [ ] Storage account access keys copied and secured
- [ ] Tables (`Prompts`, `PromptRuns`) created or confirmed auto-creation works
- [ ] Azure OpenAI service is active and accessible
- [ ] Azure OpenAI deployment is available and named correctly

### Configuration
- [ ] All 7 environment variables added to Azure Static Web App Configuration
- [ ] Configuration saved and applied in Azure Portal
- [ ] Local development environment variables configured (optional, for testing)
- [ ] Credentials stored securely (not committed to git)

### Deployment
- [ ] Latest code merged to `main` branch
- [ ] GitHub Actions deployment completed successfully
- [ ] Application is accessible at production URL
- [ ] Prompt Gallery tab appears in navigation

### Testing
- [ ] Created test prompt successfully
- [ ] Executed test prompt and received output
- [ ] Verified prompt appears in gallery
- [ ] Checked audit trail shows execution record
- [ ] Confirmed token usage is tracked
- [ ] Verified data is stored in Azure Tables

### Cost Monitoring
- [ ] Azure Cost Management alerts configured
- [ ] Monitoring Azure OpenAI token usage
- [ ] Storage account metrics baseline established
- [ ] Budget alerts set for unexpected costs

### Security & Compliance
- [ ] Storage account firewall rules reviewed (if applicable)
- [ ] Access keys rotated and secured in Key Vault (optional)
- [ ] Team trained on redaction guidelines
- [ ] Audit log review process established

### Documentation
- [ ] Team members have access to PROMPT_GALLERY_SETUP.md
- [ ] Example prompts shared with team
- [ ] Escalation process documented for issues
- [ ] Backup/disaster recovery plan reviewed

---

## Quick Troubleshooting

### "Azure Storage credentials not configured"
**Problem**: Backend can't connect to storage
**Solution**:
1. Verify `AZURE_STORAGE_ACCOUNT_NAME` and `AZURE_STORAGE_ACCOUNT_KEY` are set in Azure Static Web App Configuration
2. Check values are correct (no extra spaces)
3. Restart the application or redeploy

### "Failed to fetch prompts"
**Problem**: Tables don't exist or network issue
**Solution**:
1. Manually create tables in Azure Portal (see Step 1.5)
2. Check storage account firewall settings allow Azure services
3. Verify storage account is in same region

### "Azure OpenAI credentials not configured"
**Problem**: Backend can't connect to OpenAI
**Solution**:
1. Verify `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY` are set
2. Check endpoint URL format: `https://[name].openai.azure.com/`
3. Verify deployment name matches `AZURE_OPENAI_DEPLOYMENT`

### Prompts not appearing in gallery
**Problem**: Empty state or error
**Solution**:
1. Open browser console (F12) and check for errors
2. Verify API endpoint `/api/prompts` returns 200 status
3. Check Azure Storage Browser to see if tables have data
4. Try creating a prompt - check for specific error messages

---

## Support & Resources

**Documentation**:
- Complete setup guide: `PROMPT_GALLERY_SETUP.md`
- Azure Storage docs: https://docs.microsoft.com/azure/storage/
- Azure OpenAI docs: https://docs.microsoft.com/azure/cognitive-services/openai/

**Cost Management**:
- Azure Cost Management: [portal.azure.com/#blade/Microsoft_Azure_CostManagement/Menu/overview](https://portal.azure.com/#blade/Microsoft_Azure_CostManagement/Menu/overview)
- Azure OpenAI pricing: https://azure.microsoft.com/pricing/details/cognitive-services/openai-service/

**Repository**:
- GitHub Issues: https://github.com/rootghost99/threatdefender-tools/issues

---

## Summary

**What You Need to Do**:
1. ✅ Create Azure Storage Account (one-time, ~5 minutes)
2. ✅ Copy 2 values: storage name + key
3. ✅ Get Azure OpenAI credentials (likely already have)
4. ✅ Add 7 environment variables to Azure Static Web App
5. ✅ Deploy and test

**What's Already Done**:
- All code implemented and tested
- Full documentation provided
- GitHub Actions deployment configured
- Audit trail and security features built-in

You're ready to go once the Azure resources are configured! 🚀
