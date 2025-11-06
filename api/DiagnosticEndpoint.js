// Diagnostic endpoint to help debug deployment issues
const { app } = require('@azure/functions');

app.http('diagnostic', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'diagnostic',
  handler: async (request, context) => {
    const diagnosticInfo = {
      timestamp: new Date().toISOString(),
      message: 'Diagnostic endpoint is working',
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        functionWorkerRuntime: process.env.FUNCTIONS_WORKER_RUNTIME,
        azureWebJobsStorage: process.env.AzureWebJobsStorage ? 'SET' : 'NOT SET',
        storageAccountName: process.env.AZURE_STORAGE_ACCOUNT_NAME ? 'SET' : 'NOT SET',
        storageAccountKey: process.env.AZURE_STORAGE_ACCOUNT_KEY ? 'SET (length: ' + (process.env.AZURE_STORAGE_ACCOUNT_KEY?.length || 0) + ')' : 'NOT SET',
        promptsTableName: process.env.PROMPTS_TABLE_NAME || 'NOT SET (will default to Prompts)'
      },
      loadedModules: Object.keys(require.cache).filter(key => key.includes('/api/')).map(key => {
        const parts = key.split('/');
        return parts[parts.length - 1];
      }),
      availableFunctions: [
        'This diagnostic endpoint',
        'If PromptsAPI loaded: GET/POST/PUT/DELETE /api/prompts',
        'If other functions loaded, they should be listed in loadedModules'
      ]
    };

    return {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      jsonBody: diagnosticInfo
    };
  }
});

console.log('✓ DiagnosticEndpoint registered successfully');
