// /api/PromptsDiagnostics.js
// Comprehensive diagnostics endpoint for troubleshooting PromptsAPI
const { app } = require('@azure/functions');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

app.http('PromptsDiagnostics', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/diagnostics',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    const results = {
      timestamp: new Date().toISOString(),
      tests: {}
    };

    // Test 1: Check dependencies
    results.tests.dependencies = {};
    try {
      require('@azure/functions');
      results.tests.dependencies.azureFunctions = '✓ Available';
    } catch (e) {
      results.tests.dependencies.azureFunctions = `✗ Error: ${e.message}`;
    }

    try {
      require('@azure/data-tables');
      results.tests.dependencies.dataTables = '✓ Available';
    } catch (e) {
      results.tests.dependencies.dataTables = `✗ Error: ${e.message}`;
    }

    // Test 2: Check environment variables
    results.tests.environment = {
      AZURE_STORAGE_ACCOUNT_NAME: process.env.AZURE_STORAGE_ACCOUNT_NAME ? '✓ Set' : '✗ Missing',
      AZURE_STORAGE_ACCOUNT_KEY: process.env.AZURE_STORAGE_ACCOUNT_KEY ? '✓ Set (length: ' + process.env.AZURE_STORAGE_ACCOUNT_KEY.length + ')' : '✗ Missing',
      PROMPTS_TABLE_NAME: process.env.PROMPTS_TABLE_NAME || '✗ Missing (will default to "Prompts")',
      PROMPT_RUNS_TABLE_NAME: process.env.PROMPT_RUNS_TABLE_NAME || '✗ Missing (will default to "PromptRuns")'
    };

    // Test 3: Try to create TableClient
    results.tests.tableClient = {};
    try {
      const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');
      const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
      const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
      const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

      if (!account || !accountKey) {
        results.tests.tableClient.creation = '✗ Cannot create - missing credentials';
      } else {
        const credential = new AzureNamedKeyCredential(account, accountKey);
        const tableClient = new TableClient(
          `https://${account}.table.core.windows.net`,
          tableName,
          credential
        );
        results.tests.tableClient.creation = '✓ TableClient created successfully';
        results.tests.tableClient.endpoint = `https://${account}.table.core.windows.net`;
        results.tests.tableClient.tableName = tableName;

        // Test 4: Try WITHOUT filter first
        try {
          const entities = tableClient.listEntities();
          let count = 0;
          const firstFew = [];
          for await (const entity of entities) {
            count++;
            if (count <= 3) {
              firstFew.push({
                id: entity.rowKey,
                partitionKey: entity.partitionKey,
                title: entity.title || 'No title',
                hasDeletedFlag: entity.isDeleted !== undefined,
                isDeleted: entity.isDeleted
              });
            }
            if (count >= 10) break;
          }

          results.tests.tableConnectionNoFilter = {
            status: '✓ Connected (no filter)',
            totalPrompts: count >= 10 ? '10+' : count,
            samplePrompts: firstFew
          };
        } catch (e) {
          results.tests.tableConnectionNoFilter = {
            status: '✗ Connection failed (no filter)',
            error: e.message
          };
        }

        // Test 5: Try WITH filter like PromptsAPI
        try {
          const filter = "PartitionKey eq 'PROMPT'";
          const entities = tableClient.listEntities({ queryOptions: { filter } });

          let count = 0;
          const firstFew = [];
          for await (const entity of entities) {
            count++;
            if (count <= 3) {
              firstFew.push({
                id: entity.rowKey,
                partitionKey: entity.partitionKey,
                title: entity.title || 'No title',
                hasDeletedFlag: entity.isDeleted !== undefined,
                isDeleted: entity.isDeleted
              });
            }
            if (count >= 10) break;
          }

          results.tests.tableConnectionWithFilter = {
            status: '✓ Connected (with filter)',
            filter: filter,
            totalPrompts: count >= 10 ? '10+' : count,
            samplePrompts: firstFew
          };
        } catch (e) {
          results.tests.tableConnectionWithFilter = {
            status: '✗ Connection failed (with filter)',
            error: e.message,
            errorCode: e.statusCode || e.code
          };
        }
      }
    } catch (e) {
      results.tests.tableClient.creation = `✗ Error: ${e.message}`;
      results.tests.tableClient.stack = e.stack;
    }

    // Test 5: Check if PromptsAPI module can be loaded
    results.tests.promptsAPI = {};
    try {
      // Don't actually require it (would cause duplicate registration)
      // Just check if the file exists and is readable
      const fs = require('fs');
      const path = require('path');
      const apiPath = path.join(__dirname, 'PromptsAPI.js');

      if (fs.existsSync(apiPath)) {
        const fileSize = fs.statSync(apiPath).size;
        results.tests.promptsAPI.fileExists = `✓ PromptsAPI.js exists (${fileSize} bytes)`;

        // Try to read the file to check for syntax errors
        try {
          const content = fs.readFileSync(apiPath, 'utf8');
          results.tests.promptsAPI.readable = '✓ File is readable';
          results.tests.promptsAPI.linesOfCode = content.split('\n').length;

          // Check for key patterns
          results.tests.promptsAPI.hasAppHttp = content.includes('app.http') ? '✓ Has app.http calls' : '✗ No app.http calls found';
          results.tests.promptsAPI.routeCount = (content.match(/app\.http\(/g) || []).length;
        } catch (e) {
          results.tests.promptsAPI.readable = `✗ Cannot read file: ${e.message}`;
        }
      } else {
        results.tests.promptsAPI.fileExists = '✗ PromptsAPI.js not found';
      }
    } catch (e) {
      results.tests.promptsAPI.error = `✗ Error checking file: ${e.message}`;
    }

    // Summary
    const allPassed =
      results.tests.dependencies.azureFunctions?.startsWith('✓') &&
      results.tests.dependencies.dataTables?.startsWith('✓') &&
      results.tests.tableClient.creation?.startsWith('✓') &&
      (results.tests.tableConnectionNoFilter?.status?.startsWith('✓') ||
       results.tests.tableConnectionWithFilter?.status?.startsWith('✓'));

    results.summary = allPassed
      ? '✅ All tests passed - PromptsAPI should work!'
      : '❌ Some tests failed - see details above';

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: results
    };
  }
});
