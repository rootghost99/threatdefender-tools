// Diagnostic endpoint to show which modules loaded successfully
const { app } = require('@azure/functions');

const loadingResults = {
  timestamp: new Date().toISOString(),
  modules: {}
};

// Track PromptsAPI-REST loading
try {
  const testModule = require('./PromptsAPI-REST');
  loadingResults.modules['PromptsAPI-REST'] = {
    status: 'SUCCESS',
    message: 'Module loaded without errors',
    exports: Object.keys(testModule || {})
  };
} catch (error) {
  loadingResults.modules['PromptsAPI-REST'] = {
    status: 'FAILED',
    error: error.message,
    stack: error.stack,
    cause: error.cause?.message || 'No cause info'
  };
}

// Check dependencies
loadingResults.dependencies = {};
try {
  require('@azure/functions');
  loadingResults.dependencies['@azure/functions'] = 'Available';
} catch (e) {
  loadingResults.dependencies['@azure/functions'] = `Missing: ${e.message}`;
}

try {
  require('axios');
  loadingResults.dependencies['axios'] = 'Available';
} catch (e) {
  loadingResults.dependencies['axios'] = `Missing: ${e.message}`;
}

try {
  require('@azure/openai');
  loadingResults.dependencies['@azure/openai'] = 'Available';
} catch (e) {
  loadingResults.dependencies['@azure/openai'] = `Missing: ${e.message}`;
}

// Check environment
loadingResults.environment = {
  AZURE_STORAGE_ACCOUNT_NAME: process.env.AZURE_STORAGE_ACCOUNT_NAME ? 'SET' : 'NOT SET',
  AZURE_STORAGE_ACCOUNT_KEY: process.env.AZURE_STORAGE_ACCOUNT_KEY ? `SET (${process.env.AZURE_STORAGE_ACCOUNT_KEY.length} chars)` : 'NOT SET',
  PROMPTS_TABLE_NAME: process.env.PROMPTS_TABLE_NAME || 'NOT SET (defaults to "Prompts")'
};

app.http('LoadingDiagnostic', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'loading-diagnostic',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      };
    }

    context.log('Loading diagnostic requested');

    return {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      jsonBody: {
        message: 'Module loading diagnostic',
        ...loadingResults,
        note: 'This shows whether PromptsAPI and its dependencies loaded successfully'
      }
    };
  }
});

console.log('✓ LoadingDiagnostic endpoint registered');
