// Diagnostic endpoint to test Azure Table Storage authentication
const { app } = require('@azure/functions');
const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');

console.log('[TableStorageDiagnostic] Module loading...');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

app.http('TableStorageDiagnostic', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'diagnostics/table-storage',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

    if (!account || !accountKey) {
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: {
          error: 'Azure Storage credentials not configured',
          account: account ? 'SET' : 'NOT SET',
          accountKey: accountKey ? `SET (${accountKey.length} chars)` : 'NOT SET'
        }
      };
    }

    try {
      context.log('Attempting Table Storage request with @azure/data-tables SDK...');

      const credential = new AzureNamedKeyCredential(account, accountKey);
      const tableClient = new TableClient(
        `https://${account}.table.core.windows.net`,
        tableName,
        credential
      );

      // Try to list entities
      const entities = tableClient.listEntities({
        queryOptions: { filter: "PartitionKey eq 'PROMPT'" }
      });

      let count = 0;
      let firstEntity = null;

      for await (const entity of entities) {
        if (count === 0) {
          firstEntity = {
            partitionKey: entity.partitionKey,
            rowKey: entity.rowKey,
            title: entity.title || 'N/A'
          };
        }
        count++;
        if (count >= 10) break; // Only count first 10 for performance
      }

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: {
          message: 'Table Storage Connection Test - SUCCESS',
          environment: {
            accountName: account,
            accountKeyLength: accountKey.length,
            tableName,
            sdkUsed: '@azure/data-tables'
          },
          testResults: {
            success: true,
            entitiesFound: count,
            firstEntitySample: firstEntity
          }
        }
      };
    } catch (error) {
      context.error('Table Storage test failed:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: {
          error: 'Test failed',
          message: error.message,
          statusCode: error.statusCode || 'N/A',
          details: error.details || 'No additional details'
        }
      };
    }
  }
});

console.log('✓ TableStorageDiagnostic endpoint registered: /api/diagnostics/table-storage');
