// /api/PromptsHealthCheck.js
// Simple health check endpoint that doesn't require database access
const { app } = require('@azure/functions');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

app.http('PromptsHealthCheck', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/health',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    context.log('Prompts API health check');

    // Check environment variables
    const envCheck = {
      hasStorageAccount: !!process.env.AZURE_STORAGE_ACCOUNT_NAME,
      hasStorageKey: !!process.env.AZURE_STORAGE_ACCOUNT_KEY,
      hasOpenAIEndpoint: !!process.env.AZURE_OPENAI_ENDPOINT,
      hasOpenAIKey: !!process.env.AZURE_OPENAI_API_KEY,
      promptsTableName: process.env.PROMPTS_TABLE_NAME || 'NOT SET',
      nodeVersion: process.version
    };

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: {
        status: 'ok',
        message: 'Prompts API is running',
        timestamp: new Date().toISOString(),
        environment: envCheck
      }
    };
  }
});
