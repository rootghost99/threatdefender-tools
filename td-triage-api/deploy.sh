#!/bin/bash
# ============================================================
# TD-Triage API Deployment Script
# Creates Azure infrastructure and deploys the Function App
# ============================================================

set -e

# ============================================================
# CONFIGURATION - Update these values for your environment
# ============================================================

# Resource naming
RESOURCE_GROUP="rg-threatdefender"
LOCATION="eastus"
COSMOS_ACCOUNT_NAME="cosmos-td-triage"
FUNCTION_APP_NAME="func-td-triage-api"
STORAGE_ACCOUNT_NAME="sttdtriageapi"  # Must be globally unique, lowercase, no hyphens
KEY_VAULT_NAME="kv-td-triage"
APP_INSIGHTS_NAME="ai-td-triage"

# Ops Suite Static Web App URL (for CORS)
OPS_SUITE_URL="https://your-ops-suite.azurestaticapps.net"

# Cosmos DB settings
COSMOS_DATABASE="TriageDB"
COSMOS_CONTAINER="Sessions"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}TD-Triage API Deployment${NC}"
echo -e "${BLUE}============================================================${NC}"

# ============================================================
# Pre-flight checks
# ============================================================

echo -e "\n${YELLOW}[1/10] Checking Azure CLI login...${NC}"
if ! az account show &>/dev/null; then
    echo -e "${RED}Not logged in. Running az login...${NC}"
    az login
fi

SUBSCRIPTION=$(az account show --query name -o tsv)
echo -e "${GREEN}Using subscription: $SUBSCRIPTION${NC}"

# ============================================================
# Create Resource Group
# ============================================================

echo -e "\n${YELLOW}[2/10] Creating Resource Group...${NC}"
az group create \
    --name $RESOURCE_GROUP \
    --location $LOCATION \
    --output none

echo -e "${GREEN}Resource group '$RESOURCE_GROUP' ready${NC}"

# ============================================================
# Create Cosmos DB Serverless Account
# ============================================================

echo -e "\n${YELLOW}[3/10] Creating Cosmos DB Serverless Account...${NC}"
az cosmosdb create \
    --name $COSMOS_ACCOUNT_NAME \
    --resource-group $RESOURCE_GROUP \
    --kind GlobalDocumentDB \
    --capabilities EnableServerless \
    --default-consistency-level Session \
    --locations regionName=$LOCATION failoverPriority=0 isZoneRedundant=false \
    --output none

echo -e "${GREEN}Cosmos DB account '$COSMOS_ACCOUNT_NAME' created${NC}"

# Create Database
echo -e "\n${YELLOW}[4/10] Creating Cosmos DB Database and Container...${NC}"
az cosmosdb sql database create \
    --account-name $COSMOS_ACCOUNT_NAME \
    --resource-group $RESOURCE_GROUP \
    --name $COSMOS_DATABASE \
    --output none

# Create Container with partition key
az cosmosdb sql container create \
    --account-name $COSMOS_ACCOUNT_NAME \
    --resource-group $RESOURCE_GROUP \
    --database-name $COSMOS_DATABASE \
    --name $COSMOS_CONTAINER \
    --partition-key-path "/incidentId" \
    --default-ttl 604800 \
    --output none

echo -e "${GREEN}Database '$COSMOS_DATABASE' and container '$COSMOS_CONTAINER' created${NC}"

# Get Cosmos DB connection string
COSMOS_CONNECTION=$(az cosmosdb keys list \
    --name $COSMOS_ACCOUNT_NAME \
    --resource-group $RESOURCE_GROUP \
    --type connection-strings \
    --query "connectionStrings[0].connectionString" \
    --output tsv)

echo -e "${GREEN}Retrieved Cosmos DB connection string${NC}"

# ============================================================
# Create Key Vault
# ============================================================

echo -e "\n${YELLOW}[5/10] Creating Key Vault...${NC}"
az keyvault create \
    --name $KEY_VAULT_NAME \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --enable-rbac-authorization false \
    --output none

echo -e "${GREEN}Key Vault '$KEY_VAULT_NAME' created${NC}"

# Store Cosmos connection string in Key Vault
echo -e "Storing Cosmos DB connection string in Key Vault..."
az keyvault secret set \
    --vault-name $KEY_VAULT_NAME \
    --name "cosmos-connection" \
    --value "$COSMOS_CONNECTION" \
    --output none

# Prompt for Claude API key
echo -e "\n${YELLOW}Enter your Claude API key for Azure AI Foundry:${NC}"
read -s CLAUDE_API_KEY

az keyvault secret set \
    --vault-name $KEY_VAULT_NAME \
    --name "claude-key" \
    --value "$CLAUDE_API_KEY" \
    --output none

echo -e "${GREEN}Secrets stored in Key Vault${NC}"

# ============================================================
# Create Storage Account (required for Function App)
# ============================================================

echo -e "\n${YELLOW}[6/10] Creating Storage Account...${NC}"
az storage account create \
    --name $STORAGE_ACCOUNT_NAME \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --sku Standard_LRS \
    --kind StorageV2 \
    --output none

echo -e "${GREEN}Storage account '$STORAGE_ACCOUNT_NAME' created${NC}"

# ============================================================
# Create Application Insights
# ============================================================

echo -e "\n${YELLOW}[7/10] Creating Application Insights...${NC}"
az monitor app-insights component create \
    --app $APP_INSIGHTS_NAME \
    --location $LOCATION \
    --resource-group $RESOURCE_GROUP \
    --application-type Node.JS \
    --output none

APP_INSIGHTS_KEY=$(az monitor app-insights component show \
    --app $APP_INSIGHTS_NAME \
    --resource-group $RESOURCE_GROUP \
    --query instrumentationKey \
    --output tsv)

echo -e "${GREEN}Application Insights '$APP_INSIGHTS_NAME' created${NC}"

# ============================================================
# Create Function App with Managed Identity
# ============================================================

echo -e "\n${YELLOW}[8/10] Creating Function App...${NC}"
az functionapp create \
    --name $FUNCTION_APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --storage-account $STORAGE_ACCOUNT_NAME \
    --consumption-plan-location $LOCATION \
    --runtime node \
    --runtime-version 18 \
    --functions-version 4 \
    --app-insights $APP_INSIGHTS_NAME \
    --app-insights-key $APP_INSIGHTS_KEY \
    --assign-identity '[system]' \
    --output none

echo -e "${GREEN}Function App '$FUNCTION_APP_NAME' created with managed identity${NC}"

# Get Function App's managed identity principal ID
FUNCTION_PRINCIPAL_ID=$(az functionapp identity show \
    --name $FUNCTION_APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query principalId \
    --output tsv)

echo -e "Function App Principal ID: $FUNCTION_PRINCIPAL_ID"

# ============================================================
# Grant Key Vault Access to Function App
# ============================================================

echo -e "\n${YELLOW}[9/10] Granting Key Vault access to Function App...${NC}"
az keyvault set-policy \
    --name $KEY_VAULT_NAME \
    --object-id $FUNCTION_PRINCIPAL_ID \
    --secret-permissions get list \
    --output none

echo -e "${GREEN}Key Vault access granted to Function App${NC}"

# ============================================================
# Configure Function App Settings
# ============================================================

echo -e "\n${YELLOW}[10/10] Configuring Function App settings...${NC}"

# Get Key Vault URI
KV_URI="https://${KEY_VAULT_NAME}.vault.azure.net"

# Configure app settings with Key Vault references
az functionapp config appsettings set \
    --name $FUNCTION_APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --settings \
        "COSMOS_CONNECTION=@Microsoft.KeyVault(SecretUri=${KV_URI}/secrets/cosmos-connection/)" \
        "CLAUDE_API_KEY=@Microsoft.KeyVault(SecretUri=${KV_URI}/secrets/claude-key/)" \
        "CLAUDE_API_ENDPOINT=https://th-aifoundry.services.ai.azure.com/anthropic/v1/messages" \
        "CLAUDE_MODEL=claude-sonnet-4-20250514" \
    --output none

echo -e "${GREEN}Function App settings configured${NC}"

# Configure CORS
echo -e "\nConfiguring CORS for Ops Suite..."
az functionapp cors add \
    --name $FUNCTION_APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --allowed-origins "$OPS_SUITE_URL" "http://localhost:3000" \
    --output none

echo -e "${GREEN}CORS configured for $OPS_SUITE_URL${NC}"

# ============================================================
# Deploy Function App Code
# ============================================================

echo -e "\n${BLUE}============================================================${NC}"
echo -e "${BLUE}Infrastructure setup complete!${NC}"
echo -e "${BLUE}============================================================${NC}"

echo -e "\n${YELLOW}To deploy your function code, run:${NC}"
echo -e "  cd td-triage-api"
echo -e "  npm install"
echo -e "  func azure functionapp publish $FUNCTION_APP_NAME"

echo -e "\n${YELLOW}Or using Azure CLI:${NC}"
echo -e "  az functionapp deployment source config-zip \\"
echo -e "      --name $FUNCTION_APP_NAME \\"
echo -e "      --resource-group $RESOURCE_GROUP \\"
echo -e "      --src <path-to-zip-file>"

# ============================================================
# Output Summary
# ============================================================

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}Deployment Summary${NC}"
echo -e "${GREEN}============================================================${NC}"

FUNCTION_URL="https://${FUNCTION_APP_NAME}.azurewebsites.net"

echo -e "Resource Group:     $RESOURCE_GROUP"
echo -e "Location:           $LOCATION"
echo -e "Cosmos DB Account:  $COSMOS_ACCOUNT_NAME"
echo -e "Function App:       $FUNCTION_APP_NAME"
echo -e "Key Vault:          $KEY_VAULT_NAME"
echo -e "Storage Account:    $STORAGE_ACCOUNT_NAME"
echo -e ""
echo -e "${BLUE}API Endpoints:${NC}"
echo -e "  GET Session:  ${FUNCTION_URL}/api/session/{sessionId}"
echo -e "  POST Message: ${FUNCTION_URL}/api/session/{sessionId}"
echo -e "  POST Create:  ${FUNCTION_URL}/api/session"
echo -e ""
echo -e "${YELLOW}Update your Logic App to call:${NC}"
echo -e "  POST ${FUNCTION_URL}/api/session"
echo -e ""
echo -e "${YELLOW}Update your Ops Suite React app's apiBaseUrl:${NC}"
echo -e "  ${FUNCTION_URL}/api"

echo -e "\n${GREEN}Done!${NC}"
