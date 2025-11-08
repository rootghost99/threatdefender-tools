const { app } = require('@azure/functions');
const axios = require('axios');

app.http('KQLAnalyzer', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
    route: 'kqlanalyzer',
    handler: async (request, context) => {
        context.log('KQL Analyzer REST function triggered');

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

            // Use REST API directly instead of SDK to avoid crypto issues
            const apiVersion = '2024-02-01';
            const url = `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=${apiVersion}`;

            context.log(`Calling Azure OpenAI REST API: ${url}`);

            try {
                const response = await axios({
                    method: 'POST',
                    url: url,
                    headers: {
                        'api-key': apiKey,
                        'Content-Type': 'application/json'
                    },
                    data: {
                        messages: messages,
                        max_tokens: 2000,
                        temperature: 0.7
                    },
                    timeout: 25000,
                    validateStatus: () => true // Don't throw on any status
                });

                context.log('OpenAI REST API response status:', response.status);

                if (response.status !== 200) {
                    context.log.error('OpenAI API error response:', response.data);
                    return {
                        status: 500,
                        headers: {
                            'Access-Control-Allow-Origin': '*',
                            'Content-Type': 'application/json'
                        },
                        jsonBody: {
                            error: 'Azure OpenAI API call failed',
                            details: response.data?.error?.message || `API returned status ${response.status}`,
                            statusCode: response.status
                        }
                    };
                }

                const result = response.data;

                if (!result.choices || !result.choices[0] || !result.choices[0].message) {
                    context.log.error('Invalid OpenAI response format:', result);
                    return {
                        status: 500,
                        headers: {
                            'Access-Control-Allow-Origin': '*',
                            'Content-Type': 'application/json'
                        },
                        jsonBody: {
                            error: 'Invalid response from Azure OpenAI',
                            details: 'Response missing expected choices/message structure'
                        }
                    };
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

            } catch (apiError) {
                context.log.error('OpenAI REST API call failed:', apiError);
                return {
                    status: 500,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: {
                        error: 'Azure OpenAI API request failed',
                        details: apiError.message,
                        type: apiError.code || 'REQUEST_ERROR'
                    }
                };
            }

        } catch (error) {
            context.log.error('Error in KQLAnalyzerREST:', error);
            return {
                status: 500,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    error: 'Failed to generate analysis',
                    details: error.message
                }
            };
        }
    }
});

console.log('✓ KQLAnalyzer endpoint registered: /api/kqlanalyzer (using REST API)');
