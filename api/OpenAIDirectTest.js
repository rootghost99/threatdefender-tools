const { app } = require('@azure/functions');
const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");

app.http('OpenAIDirectTest', {
    methods: ['GET', 'OPTIONS'],
    authLevel: 'anonymous',
    route: 'openai-test',
    handler: async (request, context) => {
        context.log('OpenAI Direct Test triggered');

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

        const result = {
            step1_envCheck: null,
            step2_clientCreation: null,
            step3_apiCall: null,
            error: null
        };

        try {
            // Step 1: Check environment
            const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
            const apiKey = process.env.AZURE_OPENAI_API_KEY;
            const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

            result.step1_envCheck = {
                endpoint: endpoint ? `${endpoint.substring(0, 30)}...` : 'NOT SET',
                apiKey: apiKey ? `SET (${apiKey.length} chars)` : 'NOT SET',
                deployment: deployment
            };

            if (!endpoint || !apiKey) {
                result.error = 'Missing credentials';
                return {
                    status: 200,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: result
                };
            }

            // Step 2: Create client
            context.log('Creating OpenAI client...');
            const client = new OpenAIClient(endpoint, new AzureKeyCredential(apiKey));
            result.step2_clientCreation = 'SUCCESS';

            // Step 3: Make a simple API call
            context.log('Making API call to deployment:', deployment);

            try {
                const messages = [
                    { role: "system", content: "You are a helpful assistant." },
                    { role: "user", content: "Say 'test successful' in exactly two words." }
                ];

                context.log('Calling getChatCompletions...');
                const apiResult = await client.getChatCompletions(deployment, messages, {
                    maxTokens: 50,
                    temperature: 0.3
                });

                context.log('API call completed');

                result.step3_apiCall = {
                    status: 'SUCCESS',
                    responseText: apiResult.choices?.[0]?.message?.content || 'No content',
                    choicesLength: apiResult.choices?.length || 0
                };
            } catch (apiError) {
                context.error('API call failed:', apiError);
                result.step3_apiCall = {
                    status: 'FAILED',
                    errorMessage: apiError.message,
                    errorType: apiError.constructor?.name,
                    errorCode: apiError.code,
                    statusCode: apiError.statusCode,
                    responseStatus: apiError.response?.status,
                    responseData: apiError.response?.data
                };
            }

            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: result
            };

        } catch (error) {
            context.error('Unexpected error:', error);
            result.error = {
                message: error.message,
                type: error.constructor?.name,
                stack: error.stack
            };

            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: result
            };
        }
    }
});

console.log('✓ OpenAIDirectTest endpoint registered: /api/openai-test');
