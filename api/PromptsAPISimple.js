// /api/PromptsAPISimple.js
// Simplified test endpoint to debug prompts listing
const { app } = require('@azure/functions');
const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

app.http('PromptsAPISimple', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/simple',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
      const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
      const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

      const credential = new AzureNamedKeyCredential(account, accountKey);
      const client = new TableClient(
        `https://${account}.table.core.windows.net`,
        tableName,
        credential
      );

      context.log('Fetching prompts without filter...');

      // NO FILTER - just get everything
      const prompts = [];
      const entities = client.listEntities();

      for await (const entity of entities) {
        context.log('Found entity:', entity.rowKey);

        // Return raw entity with minimal processing
        prompts.push({
          id: entity.rowKey,
          partitionKey: entity.partitionKey,
          title: entity.title,
          description: entity.description,
          isDeleted: entity.isDeleted,
          status: entity.status,
          createdAt: entity.createdAt,
          // Include ALL fields for debugging
          rawEntity: entity
        });

        if (prompts.length >= 10) break; // Limit to 10 for testing
      }

      context.log(`Found ${prompts.length} prompts`);

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: {
          count: prompts.length,
          prompts: prompts,
          message: 'Simple list without filters or processing'
        }
      };
    } catch (error) {
      context.error('Error:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message, stack: error.stack }
      };
    }
  }
});
