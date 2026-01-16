# AI Triage Chat - Setup Guide

This guide covers the configuration and setup of the AI Triage Chat feature for interactive Sentinel incident follow-up.

---

## Overview

AI Triage Chat enables security analysts to:
- Receive initial AI-generated incident analysis
- Ask follow-up questions about Sentinel incidents
- Get contextual KQL queries and recommendations
- Access chat sessions directly from Teams notifications

**Integration Flow:**
```
Sentinel Incident → Logic App → Creates Session → Teams Notification → Analyst Clicks Link → Chat UI
```

---

## Prerequisites

1. **Azure Cosmos DB** account
2. **Claude AI** access via Azure AI Foundry
3. **Azure Logic App** (for Sentinel integration)
4. **Microsoft Teams** (for notifications)

---

## Azure Resources Required

### 1. Azure Cosmos DB

**Purpose:** Store chat sessions with automatic 7-day expiration.

**Configuration:**
- **Database:** `TriageDB`
- **Container:** `Sessions`
- **Partition Key:** `/incidentId`
- **TTL:** Enabled (7 days = 604800 seconds)

#### Creating the Database

**Azure Portal:**
1. Go to [Azure Portal](https://portal.azure.com)
2. Create or navigate to your Cosmos DB account
3. Click **Data Explorer**
4. Click **New Database** → Name: `TriageDB`
5. Click **New Container**:
   - Database: `TriageDB`
   - Container ID: `Sessions`
   - Partition key: `/incidentId`
6. Enable TTL:
   - Container Settings → Time to Live → On (Default)
   - Default TTL: `604800` (7 days)

**Azure CLI:**
```bash
# Create database
az cosmosdb sql database create \
  --account-name <your-cosmos-account> \
  --resource-group <your-resource-group> \
  --name TriageDB

# Create container with TTL
az cosmosdb sql container create \
  --account-name <your-cosmos-account> \
  --resource-group <your-resource-group> \
  --database-name TriageDB \
  --name Sessions \
  --partition-key-path /incidentId \
  --default-ttl 604800
```

#### Getting Connection String

1. Azure Portal → Cosmos DB account → **Keys**
2. Copy **PRIMARY CONNECTION STRING**

Format:
```
AccountEndpoint=https://your-cosmos.documents.azure.com:443/;AccountKey=your-key-here==
```

---

### 2. Claude AI via Azure AI Foundry

**Purpose:** Power the conversational AI for incident analysis.

**Model:** `claude-sonnet-4-20250514` (recommended)

#### Setting Up Claude Access

1. Go to [Azure AI Foundry](https://ai.azure.com)
2. Create or select a project
3. Navigate to **Deployments**
4. Deploy an Anthropic Claude model:
   - Model: Claude Sonnet 4 (or available version)
   - Deployment name: Your choice
5. Note the endpoint and API key

**Endpoint Format:**
```
https://your-project.services.ai.azure.com/anthropic/v1/messages
```

---

## Environment Variables

Add these to your Azure Static Web App configuration or `api/local.settings.json`:

| Variable | Required | Description |
|----------|----------|-------------|
| `COSMOS_CONNECTION` | Yes | Full Cosmos DB connection string |
| `CLAUDE_API_ENDPOINT` | Yes | Azure AI Foundry Claude endpoint URL |
| `CLAUDE_API_KEY` | Yes | Claude API key |
| `CLAUDE_MODEL` | No | Model ID (default: `claude-sonnet-4-20250514`) |

**Example local.settings.json:**
```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",

    "COSMOS_CONNECTION": "AccountEndpoint=https://your-cosmos.documents.azure.com:443/;AccountKey=your-key==",

    "CLAUDE_API_ENDPOINT": "https://your-project.services.ai.azure.com/anthropic/v1/messages",
    "CLAUDE_API_KEY": "your-claude-api-key",
    "CLAUDE_MODEL": "claude-sonnet-4-20250514"
  }
}
```

---

## Logic App Integration

### Creating the Automation

The Logic App connects Microsoft Sentinel incidents to the Triage Chat.

**Trigger:** When a Microsoft Sentinel incident is created

**Actions:**
1. Parse incident data
2. Call AI for initial analysis
3. Create Triage Session via API
4. Send Teams notification with chat link

#### Logic App Designer Steps

1. **Trigger: Microsoft Sentinel Incident**
   - Configure Sentinel workspace connection

2. **HTTP Action: Create Triage Session**
   ```
   Method: POST
   URI: https://your-app.azurestaticapps.net/api/TriageSession
   Headers:
     Content-Type: application/json
   Body:
   {
     "action": "create",
     "incidentId": "@{triggerBody()?['properties']?['incidentNumber']}",
     "incidentTitle": "@{triggerBody()?['properties']?['title']}",
     "incidentSeverity": "@{triggerBody()?['properties']?['severity']}",
     "tenantName": "Your Tenant Name",
     "incidentContext": @{triggerBody()},
     "systemPrompt": "You are a security operations assistant helping analyze Microsoft Sentinel incidents..."
   }
   ```

3. **Parse JSON: Extract Session ID**
   - Parse the response to get `sessionId`

4. **Microsoft Teams: Post Adaptive Card**
   ```json
   {
     "type": "AdaptiveCard",
     "version": "1.4",
     "body": [
       {
         "type": "TextBlock",
         "text": "New Incident: @{triggerBody()?['properties']?['title']}",
         "weight": "bolder",
         "size": "medium"
       },
       {
         "type": "TextBlock",
         "text": "Severity: @{triggerBody()?['properties']?['severity']}"
       },
       {
         "type": "TextBlock",
         "text": "@{body('HTTP')?['initialAnalysis']?['summary']}",
         "wrap": true
       }
     ],
     "actions": [
       {
         "type": "Action.OpenUrl",
         "title": "Continue Chat",
         "url": "https://your-app.azurestaticapps.net/triage/@{body('HTTP')?['sessionId']}"
       }
     ]
   }
   ```

---

## Session Data Structure

Each triage session stores:

```json
{
  "id": "session-uuid",
  "incidentId": "12345",
  "incidentTitle": "Suspicious sign-in from unusual location",
  "incidentSeverity": "High",
  "tenantName": "Contoso",
  "systemPrompt": "You are a security analyst...",
  "incidentContext": { /* full incident JSON */ },
  "initialAnalysis": {
    "summary": "This incident involves...",
    "severity": "High",
    "confidence": 0.85,
    "mitreTechniques": ["T1078", "T1110"],
    "recommendedActions": [...]
  },
  "conversationHistory": [
    { "role": "assistant", "content": "..." },
    { "role": "user", "content": "..." }
  ],
  "createdAt": "2026-01-16T10:00:00.000Z",
  "lastUpdated": "2026-01-16T10:30:00.000Z",
  "messageCount": 5,
  "ttl": 604800
}
```

---

## Quick Actions

The chat UI displays dynamic quick action buttons based on incident type detection.

**Detection Logic:**
The incident title is analyzed for keywords to determine quick actions:

| Incident Type | Keywords | Quick Actions |
|---------------|----------|---------------|
| Email | phishing, spam, BEC, malicious email, suspicious email | Check clicked links, Pull mailbox logs, Check forwarding, List recipients |
| Identity | sign-in, impossible travel, MFA, password, authentication | Verify travel/VPN, Recent sign-ins, Risky sign-ins, CA policy hits |
| Malware | malware, ransomware, EDR, suspicious process, virus | Device isolated?, Process tree, Lateral movement, IOC spread |
| Data | exfiltration, DLP, sensitive, data leak | What data accessed?, User authorized?, DLP alerts, Revoke access |
| General | (fallback) | Critical steps, TP/FP assessment, Log recommendations, Executive summary |

---

## Frontend Component

The Triage Chat UI is located at:
- **Path:** `/triage/:sessionId`
- **Component:** `src/components/TriageChat.jsx`

**Features:**
- Initial analysis card (collapsible)
- Dynamic quick action buttons
- Chat message history
- Code block copy functionality
- Dark theme consistent with suite
- Real-time response streaming

---

## API Endpoints

### Get Session

```http
GET /api/TriageSession?sessionId=<id>
```

Returns session data including conversation history.

### Create Session

```http
POST /api/TriageSession

{
  "action": "create",
  "incidentId": "12345",
  "incidentTitle": "...",
  "incidentSeverity": "High",
  "tenantName": "Contoso",
  "incidentContext": {...},
  "systemPrompt": "..."
}
```

### Send Message

```http
POST /api/TriageSession

{
  "action": "message",
  "sessionId": "session-uuid",
  "message": "What KQL query can I use?"
}
```

---

## Testing the Integration

### 1. Test API Directly

```bash
# Create session
curl -X POST https://your-app.azurestaticapps.net/api/TriageSession \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create",
    "incidentId": "TEST-001",
    "incidentTitle": "Test Phishing Incident",
    "incidentSeverity": "Medium",
    "tenantName": "TestTenant",
    "incidentContext": {"test": true},
    "systemPrompt": "You are a security analyst assistant."
  }'

# Response includes sessionId - use it below

# Send message
curl -X POST https://your-app.azurestaticapps.net/api/TriageSession \
  -H "Content-Type: application/json" \
  -d '{
    "action": "message",
    "sessionId": "YOUR-SESSION-ID",
    "message": "What should I check first?"
  }'
```

### 2. Test Frontend

1. Navigate to `https://your-app.azurestaticapps.net/triage/YOUR-SESSION-ID`
2. Verify initial analysis displays
3. Click quick action buttons
4. Send custom messages
5. Verify code blocks have copy functionality

### 3. Test Full Flow

1. Create a test incident in Sentinel
2. Verify Logic App triggers
3. Check Teams for notification
4. Click "Continue Chat" link
5. Verify session loads with incident context

---

## Troubleshooting

### "Session not found"
- Verify session ID is correct
- Check if session expired (7-day TTL)
- Verify Cosmos DB connection string

### "Claude API error"
- Check `CLAUDE_API_ENDPOINT` URL format
- Verify API key is valid
- Check Azure AI Foundry deployment status

### "Initial analysis not showing"
- Logic App may have failed to create session
- Check Logic App run history for errors
- Verify API endpoint is accessible from Logic App

### "Quick actions not appearing"
- Incident title may not match detection keywords
- Check browser console for errors
- Verify session data includes `incidentTitle`

### "Messages not saving"
- Check Cosmos DB write permissions
- Verify partition key is correct
- Check Azure Function logs for errors

---

## Cost Considerations

| Service | Cost Factor | Estimate |
|---------|-------------|----------|
| Cosmos DB | Request Units + Storage | ~$25/month (serverless) |
| Claude AI | Token usage | $3-8 per 1M tokens |
| Logic Apps | Executions | ~$0.000025 per action |

**Optimization Tips:**
1. Set appropriate TTL (7 days is default)
2. Use system prompts efficiently
3. Consider message length limits
4. Monitor token usage in AI Foundry

---

## Security Considerations

1. **Session Access:** Sessions are accessible by session ID only (UUID)
2. **Data Retention:** 7-day automatic expiration via TTL
3. **Incident Data:** Full incident context stored - consider data classification
4. **Network Security:** Consider private endpoints for Cosmos DB
5. **API Security:** No authentication by default - consider adding if needed

---

## Related Documentation

- [AZURE_CONFIG.md](AZURE_CONFIG.md) - Environment variables reference
- [API_REFERENCE.md](API_REFERENCE.md) - Complete API documentation
- [ARCHITECTURE_SUMMARY.md](ARCHITECTURE_SUMMARY.md) - Technical architecture
