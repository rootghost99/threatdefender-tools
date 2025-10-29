const { app } = require('@azure/functions');
const { OpenAIClient, AzureKeyCredential } = require("@azure/openai");

app.http('IRPlaybook', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('IR Playbook Generator triggered');

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
            const { originalQuery } = body;

            if (!originalQuery) {
                return {
                    status: 400,
                    jsonBody: { error: 'Missing originalQuery field' }
                };
            }

            const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
            const apiKey = process.env.AZURE_OPENAI_KEY;
            const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

            const client = new OpenAIClient(endpoint, new AzureKeyCredential(apiKey));

            const messages = [
                { 
                    role: "system", 
                    content: "You are an expert SOC analyst creating incident response playbooks for Microsoft security ecosystems."
                },
                { role: "user", content: originalQuery }
            ];

            const result = await client.getChatCompletions(deployment, messages, {
                maxTokens: 3000,
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
                jsonBody: { error: 'Failed to generate playbook', details: error.message }
            };
        }
    }
});