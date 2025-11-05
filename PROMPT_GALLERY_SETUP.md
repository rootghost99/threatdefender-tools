# Prompt Gallery — Setup Guide

## Overview

The **Prompt Gallery** is a new feature in the ThreatDefender Operations Suite that allows security analysts to:

- Browse and search vetted AI prompts for security analysis
- Fill variables and run prompts against incident context
- View and export AI-generated results
- Create and edit prompts with custom variables
- Track prompt usage and audit all executions

This feature provides a centralized library of reusable AI prompts for common SOC tasks like incident triage, threat analysis, and client communication.

---

## Architecture

### Frontend Components

Located in `/src/components/`:

1. **PromptGallery.jsx** - Main gallery view with search and filtering
2. **PromptDetail.jsx** - View prompt details and execute with context/variables
3. **PromptEditor.jsx** - Create and edit prompts with variable definitions
4. **PromptAdmin.jsx** - Audit log and usage statistics

### Backend APIs

Located in `/api/`:

1. **PromptsAPI.js** - CRUD operations for prompts
   - `GET /api/prompts` - List all prompts
   - `GET /api/prompts/{id}` - Get single prompt
   - `POST /api/prompts` - Create new prompt
   - `PUT /api/prompts/{id}` - Update prompt
   - `DELETE /api/prompts/{id}` - Soft delete prompt

2. **PromptRunAPI.js** - Execute prompts and track runs
   - `POST /api/prompts/{id}/run` - Execute a prompt
   - `GET /api/prompt-runs` - List all runs (audit)
   - `GET /api/prompt-runs/{id}` - Get run details with full output

### Data Storage

- **Azure Table Storage** - Stores prompts and run metadata
  - `Prompts` table - Prompt definitions with variables and instructions
  - `PromptRuns` table - Execution audit trail with token usage

- **Azure Blob Storage** - (Optional) For storing large outputs
  - Not implemented in Phase 1, but storage package is installed

---

## Azure Resources Required

### 1. Azure Storage Account

**Purpose**: Store prompts and execution history

**What to Create**:
1. Go to Azure Portal → Create a resource → Storage Account
2. Choose:
   - **Performance**: Standard
   - **Replication**: LRS (Locally Redundant Storage) is sufficient
   - **Account kind**: StorageV2 (general purpose v2)
3. After creation, go to **Access Keys** and copy:
   - Storage account name
   - Key1 (or Key2)

**Tables to Create**:
The tables will be automatically created when first accessed by the API, but you can pre-create them:
1. Go to Storage Account → Storage Browser → Tables
2. Create two tables:
   - `Prompts`
   - `PromptRuns`

**Cost**: Very low (~$0.02-0.05 per GB/month for storage)

---

### 2. Azure OpenAI Service

**Purpose**: Power AI prompt execution (reuses existing service)

**What to Configure**:
If not already configured:
1. Go to Azure Portal → Create a resource → Azure OpenAI
2. Request access if needed (approval required)
3. After approval, create a deployment:
   - Model: `gpt-4` or `gpt-35-turbo`
   - Deployment name: `gpt-4` (or custom)
4. Copy from **Keys and Endpoint**:
   - Endpoint URL
   - API Key

**Note**: If you're already using Azure OpenAI for IR Playbook Generator or KQL Analyzer, you can reuse the same service and deployment.

**Cost**: Token-based pricing
- GPT-4: ~$0.03/1K prompt tokens, ~$0.06/1K completion tokens
- GPT-3.5-Turbo: ~$0.0015/1K prompt tokens, ~$0.002/1K completion tokens

---

### 3. Azure Static Web Apps (Existing)

**Purpose**: Host the application (already configured)

**What to Update**:
Add the new environment variables to your Static Web App configuration:
1. Go to Azure Portal → Your Static Web App → Configuration
2. Add application settings (see Environment Variables section below)

---

## Environment Variables

### Local Development

Update `/api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AzureWebJobsStorage": "",

    "AZURE_STORAGE_ACCOUNT_NAME": "your-storage-account-name",
    "AZURE_STORAGE_ACCOUNT_KEY": "your-storage-account-key",
    "PROMPTS_TABLE_NAME": "Prompts",
    "PROMPT_RUNS_TABLE_NAME": "PromptRuns",

    "AZURE_OPENAI_ENDPOINT": "https://your-openai.openai.azure.com/",
    "AZURE_OPENAI_API_KEY": "your-openai-api-key",
    "AZURE_OPENAI_DEPLOYMENT": "gpt-4"
  }
}
```

### Azure Production

Add these to your Azure Static Web App → Configuration → Application Settings:

| Variable Name | Example Value | Description |
|--------------|---------------|-------------|
| `AZURE_STORAGE_ACCOUNT_NAME` | `threatdefenderstorage` | Storage account name |
| `AZURE_STORAGE_ACCOUNT_KEY` | `abc123...` | Storage account access key |
| `PROMPTS_TABLE_NAME` | `Prompts` | Table name for prompts (default: `Prompts`) |
| `PROMPT_RUNS_TABLE_NAME` | `PromptRuns` | Table name for runs (default: `PromptRuns`) |
| `AZURE_OPENAI_ENDPOINT` | `https://your-openai.openai.azure.com/` | Azure OpenAI endpoint |
| `AZURE_OPENAI_API_KEY` | `xyz789...` | Azure OpenAI API key |
| `AZURE_OPENAI_DEPLOYMENT` | `gpt-4` | Deployment name (default: `gpt-4`) |

**Note**: The Azure OpenAI variables may already be configured if you're using IR Playbook Generator or KQL Analyzer.

---

## Setup Instructions

### Step 1: Install Dependencies

Backend dependencies have been updated. Ensure you have:

```bash
cd api
npm install
```

This will install:
- `@azure/data-tables` - For Azure Table Storage
- `@azure/storage-blob` - For Azure Blob Storage (future use)

Frontend dependencies use existing packages:
- `react-markdown` - Already installed for rendering markdown prompts

### Step 2: Configure Azure Resources

1. **Create Azure Storage Account** (see Azure Resources section above)
2. **Get Azure OpenAI credentials** (reuse existing or create new)
3. **Update environment variables** (see Environment Variables section above)

### Step 3: Initialize Tables

The tables will be created automatically on first use, but you can manually create them:

Using Azure Portal:
1. Go to Storage Account → Storage Browser → Tables
2. Click "Add Table"
3. Create `Prompts` table
4. Create `PromptRuns` table

Or using Azure CLI:
```bash
az storage table create --name Prompts --account-name <your-account-name>
az storage table create --name PromptRuns --account-name <your-account-name>
```

### Step 4: Deploy to Azure

The GitHub Actions workflow will automatically deploy your changes when you push to the main branch. The workflow already handles:
- Building the React frontend
- Deploying Azure Functions
- Updating Static Web App

Ensure environment variables are set in Azure Portal before deployment.

### Step 5: Test the Feature

1. Navigate to the app in your browser
2. Click on the **📚 Prompt Gallery** tab
3. Create your first prompt:
   - Click **➕ New Prompt**
   - Fill in title, description, and instructions
   - Add variables if needed
   - Save
4. Run the prompt:
   - Click on the prompt card
   - Paste incident context
   - Fill variables
   - Click **▶️ Run Prompt**
   - View and copy the output

---

## Usage Guide

### Creating a Prompt

1. Go to Prompt Gallery → **➕ New Prompt**
2. Fill in basic information:
   - **Title**: Short, descriptive name
   - **Description**: What this prompt does
   - **Category**: Choose from predefined categories
   - **Tags**: Comma-separated keywords for search
3. Write the prompt:
   - **System Guidance**: Instructions for the AI on how to behave (optional)
   - **User Instructions**: The main prompt template (supports Markdown)
4. Add variables (optional):
   - Click **+ Add Variable**
   - Define name, type, and whether it's required
   - Supported types: string, text, number, boolean, enum
5. Configure model settings:
   - **Temperature**: 0-1 (lower = more focused, higher = more creative)
   - **Max Tokens**: Maximum response length
6. Click **Create Prompt**

### Running a Prompt

1. Browse the gallery and click on a prompt
2. **Paste Context**: Add incident data, logs, or relevant information
   - Remember to redact sensitive info (credentials, PII, secrets)
3. **Fill Variables**: Complete any required or optional variables
4. Click **▶️ Run Prompt**
5. **View Output**: AI-generated response appears below
6. **Copy Output**: Click 📋 Copy to use in tickets or communications

### Variable Placeholders

Use these formats in your prompt templates:
- `{{variable_name}}` - Double curly braces
- `{variable_name}` - Single curly braces
- `[variable_name]` - Square brackets

Example:
```markdown
# Incident Analysis for {{client_name}}

Analyze the following security event:

## Event Details
- User: {{username}}
- IP Address: {{ip_address}}
- Severity: {{severity}}

{{context}}

## Instructions
1. Assess the risk level
2. Recommend next steps
```

### Audit Trail

1. Go to Prompt Gallery → **📊 Audit**
2. View statistics:
   - Total runs
   - Unique prompts used
   - Active users
   - Average tokens per run
3. Filter runs by:
   - Prompt ID
   - User
4. Click **View Details** to see:
   - Full input context
   - Variables used
   - Complete output
   - Token usage

---

## Security Considerations

### Data Handling

✅ **Safe to use with client data**: Azure OpenAI runs within Microsoft's secure boundary. Data is not shared with external services or used for model training.

⚠️ **Redaction reminders**: The UI prompts analysts to redact sensitive information (credentials, PII, secrets) before running prompts.

📝 **Audit logging**: Every prompt execution is logged with:
- User who ran it
- Timestamp
- Prompt used
- Token usage
- Summary of context (first 500 chars)

### Access Control

**Phase 1 (Current)**:
- Any authenticated user can create, edit, and run prompts
- Authentication via Azure Active Directory
- Audit trail provides accountability

**Phase 2 (Future)**:
- Optional approval workflow for new prompts
- Role-based access control (RBAC)
- Prompt versioning and change history

### Data Retention

- **Prompts**: Stored indefinitely (soft delete)
- **Runs**: Stored indefinitely (consider implementing retention policy)
- **Context**: Only first 500 characters stored for audit
- **Output**: First 10,000 characters stored in table

For long-term storage or compliance requirements, consider:
1. Implementing periodic export to Azure Blob Storage
2. Setting up data retention policies
3. Adding data classification labels

---

## Cost Estimation

### Storage Costs

**Azure Storage Account (Table Storage)**:
- Storage: ~$0.045 per GB/month
- Transactions: ~$0.10 per 100,000 operations
- Estimated: **$5-10/month** for moderate usage (1000 prompts, 10,000 runs)

### Compute Costs

**Azure OpenAI**:
Depends on usage volume and model:
- GPT-4: $0.03/1K prompt + $0.06/1K completion tokens
- GPT-3.5-Turbo: $0.0015/1K prompt + $0.002/1K completion tokens

Example calculation (GPT-4):
- 100 prompt runs/day
- Average 500 prompt tokens + 1000 completion tokens per run
- Cost = (500 × $0.03/1K + 1000 × $0.06/1K) × 100 = $7.50/day = **$225/month**

**Optimization Tips**:
1. Use GPT-3.5-Turbo for simpler tasks (20x cheaper)
2. Set appropriate max token limits
3. Use lower temperature for focused outputs
4. Cache common prompts and results

---

## Troubleshooting

### Error: "Azure Storage credentials not configured"

**Cause**: Missing or incorrect storage account environment variables

**Solution**:
1. Verify `AZURE_STORAGE_ACCOUNT_NAME` and `AZURE_STORAGE_ACCOUNT_KEY` are set
2. Check Azure Portal → Storage Account → Access Keys
3. Ensure variables are added to both local.settings.json (dev) and Azure Static Web App configuration (prod)

### Error: "Azure OpenAI credentials not configured"

**Cause**: Missing Azure OpenAI environment variables

**Solution**:
1. Verify `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY` are set
2. Check Azure Portal → Azure OpenAI → Keys and Endpoint
3. Ensure deployment name matches `AZURE_OPENAI_DEPLOYMENT`

### Error: "Failed to fetch prompts"

**Cause**: Table storage not accessible or tables don't exist

**Solution**:
1. Verify storage account is accessible
2. Check firewall rules allow your Azure Functions to access storage
3. Manually create tables if needed (see Setup Instructions)

### Prompts not showing in gallery

**Cause**: No prompts created yet or all prompts are deleted

**Solution**:
1. Click **➕ New Prompt** to create your first prompt
2. Check Admin view for any deleted prompts

### High token usage / costs

**Solution**:
1. Review prompt templates for unnecessary verbosity
2. Reduce max token limits in model settings
3. Use GPT-3.5-Turbo instead of GPT-4 where appropriate
4. Monitor usage in Admin → Audit view

---

## Example Prompts

### Security Event Triage

**Category**: Triage
**Variables**: `username`, `ip_address`, `event_type`, `severity`

```markdown
# Security Event Triage

Analyze the following security event and provide triage guidance:

## Event Details
- User: {{username}}
- IP Address: {{ip_address}}
- Event Type: {{event_type}}
- Severity: {{severity}}

## Context
{{context}}

## Instructions
1. Assess if this is a true positive or false positive
2. Determine the urgency level (Critical/High/Medium/Low)
3. List immediate next steps for the analyst
4. Recommend any additional context needed
```

### Client Communication

**Category**: Client Communication
**Variables**: `client_name`, `incident_type`, `impact`

```markdown
# Client Incident Notification

Draft a professional client notification email for the following incident:

## Incident Details
- Client: {{client_name}}
- Incident Type: {{incident_type}}
- Impact: {{impact}}

## Internal Analysis
{{context}}

## Requirements
1. Use professional, clear language
2. Explain what happened without excessive technical jargon
3. State what actions we've taken
4. Outline next steps and expected timeline
5. Maintain a reassuring but honest tone
```

### Phishing Analysis

**Category**: Threat Analysis
**Variables**: `sender_email`, `subject`, `has_attachments`

```markdown
# Phishing Email Analysis

Analyze the following email for phishing indicators:

**From**: {{sender_email}}
**Subject**: {{subject}}
**Attachments**: {{has_attachments}}

## Email Content
{{context}}

## Analysis Required
1. Identify phishing indicators (spoofing, urgency, suspicious links)
2. Check sender reputation and domain analysis
3. Assess risk level (Critical/High/Medium/Low)
4. Recommend containment actions
5. Suggest user awareness points
```

---

## Next Steps / Phase 2 Enhancements

### Planned Features

1. **Approval Workflow**
   - Require approval for new prompts before they're visible
   - Designated approvers (admins)

2. **Versioning**
   - Track prompt changes over time
   - Ability to revert to previous versions

3. **Collections**
   - Organize prompts into curated collections
   - Share collections across teams

4. **Templates**
   - Pre-built prompt templates for common use cases
   - Import/export prompt definitions

5. **Advanced Analytics**
   - Token usage trends
   - Most-used prompts
   - User activity dashboards

6. **Integration**
   - Auto-populate context from Sentinel queries
   - Export results directly to ticketing systems

---

## Support

For issues or questions:
1. Check this setup guide
2. Review error logs in Azure Application Insights
3. Check GitHub Issues: [Repository Issues](https://github.com/rootghost99/threatdefender-tools/issues)

---

## Summary Checklist

Before using Prompt Gallery in production:

- [ ] Azure Storage Account created
- [ ] Azure Storage credentials configured
- [ ] Tables created (`Prompts`, `PromptRuns`)
- [ ] Azure OpenAI service configured (or reusing existing)
- [ ] Environment variables set in Azure Static Web App
- [ ] Application deployed to Azure
- [ ] Test prompt created and executed successfully
- [ ] Audit log verified
- [ ] Cost monitoring enabled
- [ ] Team trained on usage and security guidelines

---

**Implementation Date**: 2025-11-05
**Version**: 1.0 (Phase 1)
**Status**: Production Ready
