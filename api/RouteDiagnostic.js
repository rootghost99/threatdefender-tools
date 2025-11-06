// Route diagnostic - shows all registered Azure Functions routes
const { app } = require('@azure/functions');

console.log('[RouteDiagnostic] Module loading...');

app.http('RouteDiagnostic', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'diagnostics/routes',
  handler: async (request, context) => {
    context.log('[RouteDiagnostic] Route diagnostic endpoint called');

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

    try {
      // Get information about the app
      const appInfo = {
        message: 'Route Diagnostic Information',
        timestamp: new Date().toISOString(),
        note: 'This endpoint helps debug route registration issues',
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          azureFunctionsVersion: require('@azure/functions/package.json').version,
          env: {
            AZURE_STORAGE_ACCOUNT_NAME: process.env.AZURE_STORAGE_ACCOUNT_NAME ? 'SET' : 'NOT SET',
            AZURE_STORAGE_ACCOUNT_KEY: process.env.AZURE_STORAGE_ACCOUNT_KEY ? 'SET' : 'NOT SET',
            PROMPTS_TABLE_NAME: process.env.PROMPTS_TABLE_NAME || 'NOT SET'
          }
        },
        // List all loaded modules that contain 'Prompts'
        loadedModules: Object.keys(require.cache).filter(m =>
          m.includes('Prompts') || m.includes('prompts')
        ).map(m => m.replace(/^.*\/api\//, '/api/')),
        // Try to introspect the app object
        appType: typeof app,
        appMethods: Object.getOwnPropertyNames(Object.getPrototypeOf(app)),
        // Check if we can see other registered functions
        hints: [
          'If /api/prompts returns 404 with empty body, the route is not registered',
          'Check Azure Function App logs for route registration messages',
          'Verify PromptsAPI.js is being imported in index.js',
          'Test alternative routes: /api/prompts-minimal, /api/prompts/simple'
        ]
      };

      return {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        jsonBody: appInfo
      };
    } catch (error) {
      context.error('[RouteDiagnostic] Error:', error);
      return {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        jsonBody: {
          error: error.message,
          stack: error.stack
        }
      };
    }
  }
});

console.log('[RouteDiagnostic] Module loaded, route registered: /api/diagnostics/routes');
