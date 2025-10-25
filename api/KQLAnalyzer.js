const { app } = require('@azure/functions');
const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");

app.http('KQLAnalyzer', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
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

        try {
            const body = await request.json();
            const { originalQuery, updatedQuery } = body;

            if (!originalQuery || !updatedQuery) {
                return {
                    status: 400,
                    jsonBody: { error: 'Missing required fields' }
                };
            }

            const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
            const apiKey = process.env.AZURE_OPENAI_KEY;
            const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

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

            const result = await client.getChatCompletions(deployment, messages, {
                maxTokens: 2000,
                temperature: 0.7
            });

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
            context.log.error('Error:', error);
            return {
                status: 500,
                jsonBody: { error: 'Failed to generate analysis', details: error.message }
            };
        }
    }
});