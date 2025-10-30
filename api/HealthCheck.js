const { app } = require('@azure/functions');
const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");

app.http('HealthCheck', {
    methods: ['GET', 'OPTIONS'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Health check triggered');

        // Handle CORS preflight
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

        const checks = {
            timestamp: new Date().toISOString(),
            status: 'healthy',
            checks: {}
        };

        // Check environment variables
        checks.checks.endpoint = {
            configured: !!process.env.AZURE_OPENAI_ENDPOINT,
            value: process.env.AZURE_OPENAI_ENDPOINT ? '✓ Set' : '✗ Missing'
        };

        checks.checks.apiKey = {
            configured: !!process.env.AZURE_OPENAI_KEY,
            value: process.env.AZURE_OPENAI_KEY ? '✓ Set' : '✗ Missing'
        };

        checks.checks.deployment = {
            configured: !!process.env.AZURE_OPENAI_DEPLOYMENT,
            value: process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4 (default)'
        };

        // Test Azure OpenAI connection
        if (checks.checks.endpoint.configured && checks.checks.apiKey.configured) {
            try {
                const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
                const apiKey = process.env.AZURE_OPENAI_KEY;
                const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

                const client = new OpenAIClient(endpoint, new AzureKeyCredential(apiKey));

                // Try a minimal test call
                const result = await client.getChatCompletions(deployment, [
                    { role: "user", content: "Test" }
                ], {
                    maxTokens: 5,
                    temperature: 0
                });

                checks.checks.azureOpenAI = {
                    status: 'connected',
                    message: '✓ Successfully connected to Azure OpenAI',
                    deployment: deployment,
                    model: result.model || 'Unknown'
                };
                checks.status = 'healthy';
            } catch (error) {
                checks.checks.azureOpenAI = {
                    status: 'error',
                    message: '✗ Failed to connect to Azure OpenAI',
                    error: error.message,
                    errorType: error.constructor.name
                };
                checks.status = 'unhealthy';
            }
        } else {
            checks.checks.azureOpenAI = {
                status: 'not_configured',
                message: '✗ Missing required environment variables'
            };
            checks.status = 'unhealthy';
        }

        return {
            status: checks.status === 'healthy' ? 200 : 500,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            jsonBody: checks
        };
    }
});
