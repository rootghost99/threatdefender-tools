const { app } = require('@azure/functions');

app.http('OpenAISafeTest', {
    methods: ['GET', 'OPTIONS'],
    authLevel: 'anonymous',
    route: 'openai-safe-test',
    handler: async (request, context) => {
        // Ultra-defensive test - catch EVERYTHING
        const safeLog = (msg, data) => {
            try {
                context.log(msg, data);
            } catch (e) {
                // Even logging can fail
            }
        };

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
            stage: 'starting',
            error: null
        };

        try {
            result.stage = 'checking-env';
            const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
            const apiKey = process.env.AZURE_OPENAI_API_KEY;
            const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

            result.env = {
                hasEndpoint: !!endpoint,
                hasApiKey: !!apiKey,
                deployment: deployment
            };

            if (!endpoint || !apiKey) {
                result.stage = 'env-missing';
                return {
                    status: 200,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: result
                };
            }

            result.stage = 'loading-openai-module';
            safeLog('Loading OpenAI module...');

            let OpenAIClient, AzureKeyCredential;
            try {
                const openai = require("@azure/openai");
                OpenAIClient = openai.OpenAIClient;
                AzureKeyCredential = openai.AzureKeyCredential;
                result.moduleLoaded = true;
            } catch (moduleError) {
                result.stage = 'module-load-failed';
                result.error = {
                    message: moduleError.message,
                    type: moduleError.constructor?.name
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

            result.stage = 'creating-client';
            safeLog('Creating OpenAI client...');

            let client;
            try {
                client = new OpenAIClient(endpoint, new AzureKeyCredential(apiKey));
                result.clientCreated = true;
            } catch (clientError) {
                result.stage = 'client-creation-failed';
                result.error = {
                    message: clientError.message,
                    type: clientError.constructor?.name
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

            result.stage = 'calling-api';
            safeLog('Calling OpenAI API...');

            try {
                const messages = [
                    { role: "user", content: "Say 'OK'" }
                ];

                const apiResult = await client.getChatCompletions(deployment, messages, {
                    maxTokens: 10,
                    temperature: 0
                });

                result.stage = 'api-success';
                result.apiResponse = {
                    hasChoices: !!apiResult.choices,
                    choicesCount: apiResult.choices?.length || 0,
                    responseText: apiResult.choices?.[0]?.message?.content || 'No content'
                };
            } catch (apiError) {
                result.stage = 'api-call-failed';
                result.error = {
                    message: apiError.message || 'Unknown error',
                    type: apiError.constructor?.name || 'Error',
                    code: apiError.code,
                    status: apiError.status || apiError.statusCode
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

        } catch (outerError) {
            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    stage: result.stage || 'unknown',
                    fatalError: {
                        message: outerError.message || 'Unknown error',
                        type: outerError.constructor?.name || 'Error',
                        stack: outerError.stack
                    }
                }
            };
        }
    }
});

console.log('✓ OpenAISafeTest endpoint registered: /api/openai-safe-test');
