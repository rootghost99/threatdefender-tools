// Minimal test version - no dependencies
const { app } = require('@azure/functions');

app.http('HybridAnalysisLookupTest', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    return {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
      },
      jsonBody: {
        test: 'Function is reachable',
        timestamp: new Date().toISOString(),
        method: request.method
      }
    };
  }
});
