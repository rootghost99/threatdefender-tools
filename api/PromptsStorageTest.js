// Storage Connection Test - Diagnose why storage endpoints fail
const { app } = require('@azure/functions');

console.log('[PromptsStorageTest] Module loading...');

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

// Test endpoint that safely tests storage connection
app.http('PromptsStorageTest', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/storage-test',
  handler: async (request, context) => {
    context.log('[PromptsStorageTest] Handler called');

    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    const results = {
      timestamp: new Date().toISOString(),
      tests: []
    };

    // Test 1: Check environment variables
    try {
      const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
      const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
      const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

      results.tests.push({
        name: 'Environment Variables',
        status: 'PASS',
        details: {
          accountName: account ? `SET (${account})` : 'MISSING',
          accountKey: accountKey ? `SET (${accountKey.substring(0, 10)}...)` : 'MISSING',
          tableName: tableName
        }
      });
    } catch (error) {
      results.tests.push({
        name: 'Environment Variables',
        status: 'FAIL',
        error: error.message,
        stack: error.stack
      });
    }

    // Test 2: Try to import Azure SDK
    try {
      const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');
      results.tests.push({
        name: 'Azure SDK Import',
        status: 'PASS',
        details: 'Successfully imported @azure/data-tables'
      });
    } catch (error) {
      results.tests.push({
        name: 'Azure SDK Import',
        status: 'FAIL',
        error: error.message,
        stack: error.stack
      });
      // Can't continue if SDK doesn't load
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: results
      };
    }

    // Test 3: Try to create TableClient
    try {
      const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');
      const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
      const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
      const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

      if (!account || !accountKey) {
        throw new Error('Missing credentials');
      }

      const credential = new AzureNamedKeyCredential(account, accountKey);
      const tableClient = new TableClient(
        `https://${account}.table.core.windows.net`,
        tableName,
        credential
      );

      results.tests.push({
        name: 'TableClient Creation',
        status: 'PASS',
        details: {
          endpoint: `https://${account}.table.core.windows.net`,
          tableName: tableName
        }
      });

      // Test 4: Try to list entities
      try {
        context.log('[PromptsStorageTest] Attempting to list entities...');
        const entities = [];
        let count = 0;

        // Try to get just first 5 entities
        const iterator = tableClient.listEntities();
        for await (const entity of iterator) {
          count++;
          entities.push({
            partitionKey: entity.partitionKey,
            rowKey: entity.rowKey,
            title: entity.title
          });
          if (count >= 5) break; // Only get first 5
        }

        results.tests.push({
          name: 'Table Query',
          status: 'PASS',
          details: {
            entitiesFound: count,
            sample: entities
          }
        });
      } catch (error) {
        results.tests.push({
          name: 'Table Query',
          status: 'FAIL',
          error: error.message,
          errorCode: error.code,
          statusCode: error.statusCode,
          stack: error.stack
        });
      }
    } catch (error) {
      results.tests.push({
        name: 'TableClient Creation',
        status: 'FAIL',
        error: error.message,
        stack: error.stack
      });
    }

    // Determine overall status
    const failedTests = results.tests.filter(t => t.status === 'FAIL');
    const overallStatus = failedTests.length === 0 ? 'ALL_PASS' : 'SOME_FAILED';

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: {
        message: 'Storage connection diagnostic complete',
        overallStatus,
        results,
        summary: {
          total: results.tests.length,
          passed: results.tests.filter(t => t.status === 'PASS').length,
          failed: failedTests.length
        }
      }
    };
  }
});

console.log('[PromptsStorageTest] Route registered: GET /api/prompts/storage-test');
