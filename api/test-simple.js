// Ultra-simple test endpoint
const { app } = require('@azure/functions');

app.http('test-simple', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'test-simple',
  handler: async (request, context) => {
    context.log('Test endpoint called');
    return {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      jsonBody: {
        message: 'Test endpoint is working!',
        timestamp: new Date().toISOString(),
        nodeVersion: process.version
      }
    };
  }
});
