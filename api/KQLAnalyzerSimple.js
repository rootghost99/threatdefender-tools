const { app } = require('@azure/functions');

// Simple test version without OpenAI to isolate the issue
app.http('KQLAnalyzerSimple', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
    route: 'kqlanalyzer-simple',
    handler: async (request, context) => {
        context.log('KQL Analyzer Simple function triggered');

        // Handle CORS preflight
        if (request.method === 'OPTIONS') {
            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type'
                }
            };
        }

        try {
            context.log('Parsing request body...');
            const body = await request.json();
            context.log('Body parsed successfully:', JSON.stringify(body).substring(0, 100));

            const { originalQuery, updatedQuery } = body;

            if (!originalQuery || !updatedQuery) {
                context.log('Missing required fields');
                return {
                    status: 400,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: {
                        error: 'Missing required fields',
                        details: 'Both originalQuery and updatedQuery are required'
                    }
                };
            }

            context.log('Returning mock response...');

            // Return mock response without calling OpenAI
            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    content: [{
                        text: `# Mock Analysis\n\nThis is a test response to verify the endpoint works.\n\n## Original Query\n${originalQuery.substring(0, 50)}...\n\n## Updated Query\n${updatedQuery.substring(0, 50)}...`
                    }]
                }
            };

        } catch (error) {
            context.log.error('Error in KQLAnalyzerSimple:', error);
            context.log.error('Error type:', error.constructor.name);
            context.log.error('Error message:', error.message);
            context.log.error('Error stack:', error.stack);

            return {
                status: 500,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    error: 'Test endpoint error',
                    details: error.message,
                    type: error.constructor.name
                }
            };
        }
    }
});

console.log('✓ KQLAnalyzerSimple endpoint registered: /api/kqlanalyzer-simple');
