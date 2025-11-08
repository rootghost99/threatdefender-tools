const { app } = require('@azure/functions');
const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");

app.http('KQLAnalyzer', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
    route: 'kqlanalyzer',
    handler: async (request, context) => {
        context.log('KQL Analyzer function triggered');

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

        context.log('Request received from origin:', request.headers.get('origin'));
        context.log('Request URL:', request.url);

        try {
            // Parse request body
            let body;
            try {
                body = await request.json();
            } catch (parseError) {
                context.log.error('Failed to parse request body:', parseError);
                return {
                    status: 400,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: {
                        error: 'Invalid JSON in request body',
                        details: parseError.message
                    }
                };
            }

            const { originalQuery, updatedQuery } = body;

            if (!originalQuery || !updatedQuery) {
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

            // Check environment variables
            const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
            const apiKey = process.env.AZURE_OPENAI_API_KEY;
            const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

            if (!endpoint || !apiKey) {
                context.log.error('Missing Azure OpenAI configuration');
                return {
                    status: 500,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: {
                        error: 'Azure OpenAI not configured',
                        details: `Missing ${!endpoint ? 'AZURE_OPENAI_ENDPOINT' : ''} ${!apiKey ? 'AZURE_OPENAI_API_KEY' : ''}`.trim()
                    }
                };
            }

            context.log('Creating OpenAI client...');
            const client = new OpenAIClient(endpoint, new AzureKeyCredential(apiKey));

            const isFPAnalysis = originalQuery.includes('False Positive Risk');
            
            let userPrompt = isFPAnalysis ? originalQuery : `Analyze the differences between these KQL queries:

ORIGINAL QUERY:
${originalQuery}

UPDATED QUERY:
${updatedQuery}

Provide analysis with:
1. Overview of Changes
2. Key Differences
3. Security Impact
4. Performance Considerations
5. Recommendations`;

            const messages = [
                { role: "system", content: "You are an expert Microsoft Sentinel security analyst." },
                { role: "user", content: userPrompt }
            ];

            context.log(`Calling Azure OpenAI deployment: ${deployment}`);
            context.log(`Endpoint: ${endpoint}`);

            let result;
            try {
                result = await client.getChatCompletions(deployment, messages, {
                    maxTokens: 2000,
                    temperature: 0.7
                });
                context.log('OpenAI call successful');
            } catch (openAIError) {
                context.log.error('OpenAI API call failed:', openAIError);
                context.log.error('OpenAI Error details:', {
                    message: openAIError.message,
                    code: openAIError.code,
                    statusCode: openAIError.statusCode
                });
                throw new Error(`Azure OpenAI API error: ${openAIError.message}`);
            }

            if (!result.choices || !result.choices[0] || !result.choices[0].message) {
                context.log.error('Invalid OpenAI response format:', result);
                throw new Error('Invalid response from Azure OpenAI');
            }

            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    content: [{
                        text: result.choices[0].message.content
                    }]
                }
            };

        } catch (error) {
            context.log.error('Error in KQLAnalyzer:', error);
            context.log.error('Error stack:', error.stack);
            context.log.error('Error type:', error.constructor.name);

            // Provide detailed error information
            let errorMessage = error.message || 'Unknown error occurred';
            let errorDetails = {
                message: errorMessage,
                type: error.constructor.name,
                code: error.code || 'UNKNOWN'
            };

            // Add status code if available (from OpenAI errors)
            if (error.statusCode) {
                errorDetails.statusCode = error.statusCode;
            }

            return {
                status: 500,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    error: 'Failed to generate analysis',
                    details: errorMessage,
                    errorInfo: errorDetails
                }
            };
        }
    }
});