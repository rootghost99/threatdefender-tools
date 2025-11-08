// Minimal prompts endpoint for testing - NO external dependencies
const { app } = require('@azure/functions');

console.log('PromptsMinimal.js: Module loading started');

// Simple in-memory data for testing
const mockPrompts = [
  {
    id: 'test-1',
    title: 'Test Prompt 1',
    description: 'This is a test prompt from the minimal endpoint',
    category: 'Testing',
    tags: ['test', 'minimal'],
    status: 'active',
    createdAt: new Date().toISOString()
  },
  {
    id: 'test-2',
    title: 'Test Prompt 2',
    description: 'Another test prompt',
    category: 'Testing',
    tags: ['test'],
    status: 'active',
    createdAt: new Date().toISOString()
  }
];

app.http('PromptsMinimal-List', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts-minimal',
  handler: async (request, context) => {
    context.log('PromptsMinimal: GET /api/prompts-minimal called');

    if (request.method === 'OPTIONS') {
      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      };
    }

    try {
      context.log('PromptsMinimal: Returning mock data');
      return {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        jsonBody: {
          message: 'Minimal endpoint is working!',
          note: 'This is test data, not real prompts from storage',
          prompts: mockPrompts,
          count: mockPrompts.length,
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      context.error('PromptsMinimal: Error:', error);
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

console.log('PromptsMinimal.js: Module loaded successfully, route registered');
