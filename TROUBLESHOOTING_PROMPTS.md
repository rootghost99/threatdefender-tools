# Troubleshooting Prompt Gallery Storage Issues

## The "Failed to fetch prompts" Error

This error means the application cannot connect to Azure Table Storage. The solution depends on **where** you're running the app.

---

## Scenario 1: Running on Azure Static Web App (Deployed/Production)

### ✅ Steps to Verify and Fix

1. **Verify Environment Variables in Azure Portal:**
   - Go to Azure Portal → Your Static Web App
   - Navigate to **Configuration** → **Application settings**
   - Ensure these variables are set:
     ```
     AZURE_STORAGE_ACCOUNT_NAME = <your-storage-account-name>
     AZURE_STORAGE_ACCOUNT_KEY = <your-storage-account-key>
     PROMPTS_TABLE_NAME = Prompts
     PROMPT_RUNS_TABLE_NAME = PromptRuns
     ```

2. **Check the Table Exists:**
   - Go to Azure Portal → Your Storage Account
   - Navigate to **Data storage** → **Tables**
   - You should see tables named `Prompts` and `PromptRuns`
   - If they don't exist, create them manually

3. **Check API Logs:**
   - In Azure Portal → Static Web App → **Application Insights** (if enabled)
   - Look for errors in the logs when accessing `/api/prompts`

4. **Test the API Directly:**
   ```bash
   curl https://YOUR-APP-NAME.azurestaticapps.net/api/prompts
   ```

   Expected response:
   ```json
   {
     "prompts": [],
     "count": 0
   }
   ```

   Error response indicates configuration issue:
   ```json
   {
     "error": "Azure Storage credentials not configured..."
   }
   ```

---

## Scenario 2: Running Locally (Development)

### ✅ Steps to Configure Local Environment

1. **Update `api/local.settings.json`:**

   Open `/api/local.settings.json` and add your Azure credentials:

   ```json
   {
     "IsEncrypted": false,
     "Values": {
       "FUNCTIONS_WORKER_RUNTIME": "node",
       "AzureWebJobsStorage": "",
       "AZURE_STORAGE_ACCOUNT_NAME": "your-storage-account-name",
       "AZURE_STORAGE_ACCOUNT_KEY": "your-storage-account-key-here",
       "PROMPTS_TABLE_NAME": "Prompts",
       "PROMPT_RUNS_TABLE_NAME": "PromptRuns",
       "AZURE_OPENAI_ENDPOINT": "",
       "AZURE_OPENAI_API_KEY": "",
       "AZURE_OPENAI_DEPLOYMENT": "gpt-4"
     }
   }
   ```

   **⚠️ IMPORTANT:**
   - This file is git-ignored for security
   - Never commit credentials to git
   - Use your actual Azure Storage account name and key

2. **Run the Diagnostic Script:**
   ```bash
   cd api
   node check-prompts-storage.js
   ```

   This will verify:
   - ✅ Credentials are configured
   - ✅ Can connect to Azure
   - ✅ Tables exist
   - ✅ Show what data is stored

3. **Start the Local Development Server:**
   ```bash
   # Terminal 1: Start the API
   cd api
   func start

   # Terminal 2: Start the React app
   npm start
   ```

---

## Alternative: Use Azurite for Local Development

If you prefer not to use production Azure Storage for local development:

1. **Install Azurite (Azure Storage Emulator):**
   ```bash
   npm install -g azurite
   ```

2. **Start Azurite:**
   ```bash
   azurite --silent --location /tmp/azurite
   ```

3. **Update `api/local.settings.json` with Emulator Settings:**
   ```json
   {
     "IsEncrypted": false,
     "Values": {
       "FUNCTIONS_WORKER_RUNTIME": "node",
       "AzureWebJobsStorage": "UseDevelopmentStorage=true",
       "AZURE_STORAGE_ACCOUNT_NAME": "devstoreaccount1",
       "AZURE_STORAGE_ACCOUNT_KEY": "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
       "PROMPTS_TABLE_NAME": "Prompts",
       "PROMPT_RUNS_TABLE_NAME": "PromptRuns"
     }
   }
   ```

   **Note:** The account name and key above are the default Azurite credentials.

4. **Create Tables in Azurite:**
   The tables will be auto-created on first use, or you can use Azure Storage Explorer to manage them.

---

## Common Issues and Solutions

### Issue: "Prompt created successfully" but nothing appears in gallery

**Cause:** Backend save might be failing silently.

**Solution:**
1. Check browser console for API errors
2. Check backend logs (Azure Portal or local terminal)
3. Verify table exists in storage account
4. Run diagnostic script to see if data actually exists

### Issue: Tables don't exist

**Solution:**
Create them manually:
```bash
# Using Azure CLI
az storage table create --name Prompts --account-name YOUR_ACCOUNT
az storage table create --name PromptRuns --account-name YOUR_ACCOUNT
```

Or use Azure Storage Explorer (GUI tool).

### Issue: "Failed to fetch prompts" only on deployed app

**Cause:** Environment variables not set in Azure Static Web App.

**Solution:**
1. Go to Azure Portal → Static Web App → Configuration
2. Add all required environment variables
3. Save and wait 2-3 minutes for deployment
4. Refresh your app

### Issue: Works locally but not deployed

**Cause:** Different configurations between local and production.

**Solution:**
1. Verify all `api/local.settings.json` values are also in Azure environment variables
2. Check that table names match exactly (case-sensitive)
3. Verify storage account key is correct in Azure

---

## Quick Diagnostic Checklist

Run through this checklist to identify your issue:

- [ ] Where are you seeing the error? (Local or Deployed)
- [ ] Are Azure credentials configured for that environment?
- [ ] Do the tables exist in your storage account?
- [ ] Can you access `/api/prompts` directly and see a response?
- [ ] Are there any errors in the browser console (F12)?
- [ ] Are there any errors in the backend logs?
- [ ] Did you run the diagnostic script? What did it show?

---

## Need More Help?

1. Run the diagnostic script and share the output:
   ```bash
   cd api && node check-prompts-storage.js
   ```

2. Check the browser console (F12) and share any errors

3. Test the API endpoint directly:
   ```bash
   # Local
   curl http://localhost:7071/api/prompts

   # Deployed
   curl https://YOUR-APP.azurestaticapps.net/api/prompts
   ```

Share these outputs for more specific troubleshooting assistance.
