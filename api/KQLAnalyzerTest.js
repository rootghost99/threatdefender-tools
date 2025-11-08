const { app } = require('@azure/functions');

app.http('KQLAnalyzerTest', {
    methods: ['GET', 'OPTIONS'],
    authLevel: 'anonymous',
    route: 'kqlanalyzer-test',
    handler: async (request, context) => {
        context.log('KQL Analyzer Test function triggered');

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

        const results = {
            functionLoaded: true,
            timestamp: new Date().toISOString(),
            environment: {},
            openaiClient: null
        };

        // Check environment variables
        results.environment = {
            AZURE_OPENAI_ENDPOINT: process.env.AZURE_OPENAI_ENDPOINT ? 'SET' : 'NOT SET',
            AZURE_OPENAI_API_KEY: process.env.AZURE_OPENAI_API_KEY ? `SET (${process.env.AZURE_OPENAI_API_KEY.length} chars)` : 'NOT SET',
            AZURE_OPENAI_DEPLOYMENT: process.env.AZURE_OPENAI_DEPLOYMENT || 'NOT SET (will default to gpt-4)'
        };

        // Try to load OpenAI module
        try {
            const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");
            results.openaiClient = {
                status: 'Module loaded successfully',
                clientCreation: 'Not attempted yet'
            };

            // Try to create client (but don't call API)
            if (process.env.AZURE_OPENAI_ENDPOINT && process.env.AZURE_OPENAI_API_KEY) {
                try {
                    const client = new OpenAIClient(
                        process.env.AZURE_OPENAI_ENDPOINT,
                        new AzureKeyCredential(process.env.AZURE_OPENAI_API_KEY)
                    );
                    results.openaiClient.clientCreation = 'SUCCESS - Client created';
                } catch (clientError) {
                    results.openaiClient.clientCreation = `FAILED - ${clientError.message}`;
                }
            } else {
                results.openaiClient.clientCreation = 'SKIPPED - Missing credentials';
            }
        } catch (moduleError) {
            results.openaiClient = {
                status: 'FAILED to load module',
                error: moduleError.message,
                stack: moduleError.stack
            };
        }

        return {
            status: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            jsonBody: results
        };
    }
});

console.log('✓ KQLAnalyzerTest endpoint registered: /api/kqlanalyzer-test');
