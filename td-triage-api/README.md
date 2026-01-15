# TD-Triage API

Azure Function App for AI-powered incident triage chat sessions. Works with your TD-Triage Logic App to provide interactive follow-up analysis for Sentinel incidents.

## Architecture

```
┌──────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  TD-Triage       │     │  td-triage-api  │     │  Claude API      │
│  Logic App       │────▶│  (Azure Func)   │────▶│  (AI Foundry)    │
│  (creates session)     │                 │     │                  │
└──────────────────┘     └────────┬────────┘     └──────────────────┘
                                  │
┌──────────────────┐              │
│  Ops Suite       │◀─────────────┘
│  (TriageChat)    │
└──────────────────┘              │
                                  ▼
                         ┌─────────────────┐
                         │   Cosmos DB     │
                         │   (Sessions)    │
                         └─────────────────┘
```

## Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/session` | Create new session (Logic App) |
| GET | `/api/session/{sessionId}` | Retrieve session data |
| POST | `/api/session/{sessionId}` | Send follow-up message |

## Session Document Schema

```json
{
  "id": "guid",
  "incidentId": "string (partition key)",
  "incidentTitle": "string",
  "incidentSeverity": "Critical|High|Medium|Low|Informational",
  "tenantName": "string",
  "systemPrompt": "string (optional custom prompt)",
  "incidentContext": "string (JSON)",
  "initialAnalysis": {
    "summary": "string",
    "severity": "string",
    "confidence": "number",
    "mitreTechniques": ["string"],
    "recommendedActions": ["string"]
  },
  "conversationHistory": [
    { "role": "user|assistant", "content": "string" }
  ],
  "createdAt": "ISO date",
  "lastUpdated": "ISO date",
  "messageCount": "number",
  "ttl": 604800
}
```

## Deployment

### Prerequisites

- Azure CLI installed and logged in
- Node.js 18+
- Azure Functions Core Tools v4

### Quick Deploy

1. Update variables in `deploy.sh`:
   - `RESOURCE_GROUP` - Your resource group name
   - `OPS_SUITE_URL` - Your Ops Suite static web app URL
   - Other naming preferences

2. Run the deployment script:
   ```bash
   ./deploy.sh
   ```

3. Deploy the function code:
   ```bash
   npm install
   func azure functionapp publish func-td-triage-api
   ```

### Manual Azure CLI Commands

If you prefer to run commands individually:

```bash
# Variables
RG="rg-threatdefender"
LOCATION="eastus"
COSMOS="cosmos-td-triage"
FUNC="func-td-triage-api"
KV="kv-td-triage"
STORAGE="sttdtriageapi"

# 1. Create Resource Group
az group create --name $RG --location $LOCATION

# 2. Create Cosmos DB Serverless
az cosmosdb create \
    --name $COSMOS \
    --resource-group $RG \
    --kind GlobalDocumentDB \
    --capabilities EnableServerless \
    --locations regionName=$LOCATION failoverPriority=0

# 3. Create Database and Container
az cosmosdb sql database create \
    --account-name $COSMOS \
    --resource-group $RG \
    --name TriageDB

az cosmosdb sql container create \
    --account-name $COSMOS \
    --resource-group $RG \
    --database-name TriageDB \
    --name Sessions \
    --partition-key-path "/incidentId" \
    --default-ttl 604800

# 4. Create Key Vault
az keyvault create \
    --name $KV \
    --resource-group $RG \
    --location $LOCATION

# 5. Store secrets
COSMOS_CONN=$(az cosmosdb keys list --name $COSMOS --resource-group $RG --type connection-strings --query "connectionStrings[0].connectionString" -o tsv)
az keyvault secret set --vault-name $KV --name "cosmos-connection" --value "$COSMOS_CONN"
az keyvault secret set --vault-name $KV --name "claude-key" --value "YOUR_CLAUDE_API_KEY"

# 6. Create Storage Account
az storage account create \
    --name $STORAGE \
    --resource-group $RG \
    --location $LOCATION \
    --sku Standard_LRS

# 7. Create Function App with Managed Identity
az functionapp create \
    --name $FUNC \
    --resource-group $RG \
    --storage-account $STORAGE \
    --consumption-plan-location $LOCATION \
    --runtime node \
    --runtime-version 18 \
    --functions-version 4 \
    --assign-identity '[system]'

# 8. Grant Key Vault access
PRINCIPAL=$(az functionapp identity show --name $FUNC --resource-group $RG --query principalId -o tsv)
az keyvault set-policy --name $KV --object-id $PRINCIPAL --secret-permissions get list

# 9. Configure app settings
KV_URI="https://${KV}.vault.azure.net"
az functionapp config appsettings set \
    --name $FUNC \
    --resource-group $RG \
    --settings \
        "COSMOS_CONNECTION=@Microsoft.KeyVault(SecretUri=${KV_URI}/secrets/cosmos-connection/)" \
        "CLAUDE_API_KEY=@Microsoft.KeyVault(SecretUri=${KV_URI}/secrets/claude-key/)" \
        "CLAUDE_API_ENDPOINT=https://th-aifoundry.services.ai.azure.com/anthropic/v1/messages" \
        "CLAUDE_MODEL=claude-sonnet-4-20250514"

# 10. Configure CORS
az functionapp cors add \
    --name $FUNC \
    --resource-group $RG \
    --allowed-origins "https://your-ops-suite.azurestaticapps.net" "http://localhost:3000"

# 11. Deploy code
npm install
func azure functionapp publish $FUNC
```

## Integration

### Logic App Integration

Update your TD-Triage Logic App to create sessions by calling:

```http
POST https://func-td-triage-api.azurewebsites.net/api/session
Content-Type: application/json

{
  "incidentId": "@{triggerBody()?['IncidentNumber']}",
  "incidentTitle": "@{triggerBody()?['IncidentTitle']}",
  "incidentSeverity": "@{triggerBody()?['Severity']}",
  "tenantName": "@{triggerBody()?['TenantName']}",
  "incidentContext": "@{string(triggerBody())}",
  "initialAnalysis": {
    "summary": "@{body('Call_Claude')?['summary']}",
    "severity": "@{body('Call_Claude')?['severity']}",
    "confidence": "@{body('Call_Claude')?['confidence']}",
    "mitreTechniques": "@{body('Call_Claude')?['mitreTechniques']}",
    "recommendedActions": "@{body('Call_Claude')?['recommendedActions']}"
  }
}
```

### React Component Integration

Add the TriageChat component to your Ops Suite app:

```jsx
import TriageChat from './components/TriageChat';

// In your route/page:
<TriageChat
  sessionId="your-session-guid"
  apiBaseUrl="https://func-td-triage-api.azurewebsites.net/api"
  darkMode={true}
/>
```

Or use URL-based session loading:
- Route: `/triage-chat/:sessionId`
- Query param: `?sessionId=your-session-guid`

## Local Development

1. Create a `local.settings.json`:
   ```json
   {
     "IsEncrypted": false,
     "Values": {
       "AzureWebJobsStorage": "UseDevelopmentStorage=true",
       "FUNCTIONS_WORKER_RUNTIME": "node",
       "COSMOS_CONNECTION": "your-cosmos-connection-string",
       "CLAUDE_API_KEY": "your-claude-api-key",
       "CLAUDE_API_ENDPOINT": "https://th-aifoundry.services.ai.azure.com/anthropic/v1/messages",
       "CLAUDE_MODEL": "claude-sonnet-4-20250514"
     }
   }
   ```

2. Start the function:
   ```bash
   npm install
   npm start
   ```

3. Test endpoints:
   ```bash
   # Create session
   curl -X POST http://localhost:7071/api/session \
     -H "Content-Type: application/json" \
     -d '{"incidentId": "12345", "incidentTitle": "Test Incident"}'

   # Get session
   curl http://localhost:7071/api/session/{sessionId}

   # Send message
   curl -X POST http://localhost:7071/api/session/{sessionId} \
     -H "Content-Type: application/json" \
     -d '{"message": "What are the critical next steps?"}'
   ```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `COSMOS_CONNECTION` | Cosmos DB connection string (Key Vault reference in prod) |
| `CLAUDE_API_KEY` | Claude API key for Azure AI Foundry |
| `CLAUDE_API_ENDPOINT` | Claude API endpoint URL |
| `CLAUDE_MODEL` | Claude model ID (default: claude-sonnet-4-20250514) |
