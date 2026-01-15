// /api/TriageSession.js
// Azure Functions (v4, Node 18+) - AI Triage Chat Session API
// Manages triage chat sessions with Cosmos DB and Claude API

const { app } = require('@azure/functions');
const { CosmosClient } = require('@azure/cosmos');

// Cosmos DB configuration
const COSMOS_DATABASE = 'TriageDB';
const COSMOS_CONTAINER = 'Sessions';

// Claude API configuration
const CLAUDE_ENDPOINT = process.env.CLAUDE_API_ENDPOINT || 'https://th-aifoundry.services.ai.azure.com/anthropic/v1/messages';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-4-20250514';

// Cosmos client singleton
let cosmosClient = null;
let container = null;

function getCosmosContainer() {
  if (!container) {
    const connectionString = process.env.COSMOS_CONNECTION;
    if (!connectionString) {
      throw new Error('COSMOS_CONNECTION environment variable not configured');
    }
    cosmosClient = new CosmosClient(connectionString);
    container = cosmosClient.database(COSMOS_DATABASE).container(COSMOS_CONTAINER);
  }
  return container;
}

// Call Claude API for follow-up analysis
async function callClaude(systemPrompt, messages, temperature = 0.3) {
  const apiKey = process.env.CLAUDE_API_KEY;
  if (!apiKey) {
    throw new Error('CLAUDE_API_KEY environment variable not configured');
  }

  const requestBody = {
    model: CLAUDE_MODEL,
    max_tokens: 4096,
    temperature,
    system: systemPrompt,
    messages: messages.map(msg => ({
      role: msg.role,
      content: msg.content
    }))
  };

  const response = await fetch(CLAUDE_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(requestBody)
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(`Claude API error ${response.status}: ${responseText}`);
  }

  const data = JSON.parse(responseText);
  return data.content?.[0]?.text || '';
}

// Build system prompt with incident context
function buildSystemPrompt(session) {
  if (session.systemPrompt) {
    return session.systemPrompt;
  }

  const { incidentTitle, incidentSeverity, tenantName, initialAnalysis, incidentContext } = session;

  let prompt = `You are an expert security analyst assisting with incident triage for Microsoft Sentinel.

INCIDENT CONTEXT:
- Title: ${incidentTitle || 'Unknown'}
- Severity: ${incidentSeverity || 'Unknown'}
- Tenant: ${tenantName || 'Unknown'}
`;

  if (initialAnalysis) {
    prompt += `
INITIAL ANALYSIS:
- Summary: ${initialAnalysis.summary || 'N/A'}
- AI Severity Assessment: ${initialAnalysis.severity || 'N/A'}
- Confidence: ${initialAnalysis.confidence || 'N/A'}%
`;

    if (initialAnalysis.mitreTechniques?.length > 0) {
      prompt += `- MITRE Techniques: ${initialAnalysis.mitreTechniques.join(', ')}\n`;
    }

    if (initialAnalysis.recommendedActions?.length > 0) {
      prompt += `- Recommended Actions:\n${initialAnalysis.recommendedActions.map(a => `  * ${a}`).join('\n')}\n`;
    }
  }

  if (incidentContext) {
    try {
      const context = typeof incidentContext === 'string' ? JSON.parse(incidentContext) : incidentContext;
      prompt += `
RAW INCIDENT DATA:
\`\`\`json
${JSON.stringify(context, null, 2)}
\`\`\`
`;
    } catch {
      prompt += `
RAW INCIDENT DATA:
${incidentContext}
`;
    }
  }

  prompt += `
YOUR ROLE:
- Answer follow-up questions about this incident
- Provide additional investigation guidance
- Help with KQL queries for Microsoft Sentinel
- Assess true positive vs false positive likelihood
- Recommend containment and remediation actions
- Provide executive summaries when requested

GUIDELINES:
- Be concise but thorough
- Reference specific details from the incident when relevant
- Provide actionable recommendations
- When suggesting KQL queries, format them for easy copy-paste
- Consider the Microsoft security ecosystem (Defender, Sentinel, Entra ID)
`;

  return prompt;
}

// Generate UUID v4
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// CORS headers
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// GET /api/TriageSession/{sessionId} - Retrieve session
app.http('GetTriageSession', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'TriageSession/{sessionId}',
  handler: async (request, context) => {
    const sessionId = request.params.sessionId;
    context.log(`GET TriageSession: ${sessionId}`);

    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS_HEADERS };
    }

    if (!sessionId) {
      return {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'Session ID is required' }
      };
    }

    try {
      const cosmosContainer = getCosmosContainer();

      // Query by session ID (we need to scan since we don't know the partition key)
      const { resources } = await cosmosContainer.items
        .query({
          query: 'SELECT * FROM c WHERE c.id = @sessionId',
          parameters: [{ name: '@sessionId', value: sessionId }]
        })
        .fetchAll();

      if (resources.length === 0) {
        return {
          status: 404,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Session not found' }
        };
      }

      const session = resources[0];

      return {
        status: 200,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { session }
      };
    } catch (error) {
      context.error('Error fetching session:', error.message);
      return {
        status: 500,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: `Failed to fetch session: ${error.message}` }
      };
    }
  }
});

// POST /api/TriageSession/{sessionId} - Send follow-up message
app.http('PostTriageMessage', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'TriageSession/{sessionId}',
  handler: async (request, context) => {
    const sessionId = request.params.sessionId;
    context.log(`POST TriageSession message: ${sessionId}`);

    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS_HEADERS };
    }

    if (!sessionId) {
      return {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'Session ID is required' }
      };
    }

    try {
      const body = await request.json().catch(() => ({}));
      const { message } = body;

      if (!message || !message.trim()) {
        return {
          status: 400,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Message is required' }
        };
      }

      const cosmosContainer = getCosmosContainer();

      // Fetch session
      const { resources } = await cosmosContainer.items
        .query({
          query: 'SELECT * FROM c WHERE c.id = @sessionId',
          parameters: [{ name: '@sessionId', value: sessionId }]
        })
        .fetchAll();

      if (resources.length === 0) {
        return {
          status: 404,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Session not found' }
        };
      }

      const session = resources[0];

      // Build conversation for Claude
      const systemPrompt = buildSystemPrompt(session);
      const conversationHistory = session.conversationHistory || [];
      const messagesForClaude = [
        ...conversationHistory,
        { role: 'user', content: message.trim() }
      ];

      // Call Claude API
      context.log('Calling Claude API for follow-up analysis');
      const assistantResponse = await callClaude(systemPrompt, messagesForClaude);

      // Update session
      const updatedHistory = [
        ...conversationHistory,
        { role: 'user', content: message.trim() },
        { role: 'assistant', content: assistantResponse }
      ];

      const updatedSession = {
        ...session,
        conversationHistory: updatedHistory,
        lastUpdated: new Date().toISOString(),
        messageCount: (session.messageCount || 0) + 2
      };

      // Save to Cosmos DB
      await cosmosContainer.items.upsert(updatedSession);

      return {
        status: 200,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: {
          response: assistantResponse,
          messageCount: updatedSession.messageCount
        }
      };
    } catch (error) {
      context.error('Error processing message:', error.message);
      return {
        status: 500,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: `Failed to process message: ${error.message}` }
      };
    }
  }
});

// POST /api/TriageSession - Create new session (called by Logic App)
app.http('CreateTriageSession', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'TriageSession',
  handler: async (request, context) => {
    context.log('POST create TriageSession');

    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS_HEADERS };
    }

    try {
      const body = await request.json().catch(() => ({}));
      const {
        incidentId,
        incidentTitle,
        incidentSeverity,
        tenantName,
        systemPrompt,
        incidentContext,
        initialAnalysis
      } = body;

      if (!incidentId) {
        return {
          status: 400,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { error: 'incidentId is required' }
        };
      }

      const sessionId = generateUUID();
      const now = new Date().toISOString();

      const session = {
        id: sessionId,
        incidentId: String(incidentId),
        incidentTitle: incidentTitle || null,
        incidentSeverity: incidentSeverity || null,
        tenantName: tenantName || null,
        systemPrompt: systemPrompt || null,
        incidentContext: incidentContext || null,
        initialAnalysis: initialAnalysis || null,
        conversationHistory: [],
        createdAt: now,
        lastUpdated: now,
        messageCount: 0,
        ttl: 604800 // 7 days
      };

      const cosmosContainer = getCosmosContainer();
      await cosmosContainer.items.create(session);

      context.log(`Session created: ${sessionId} for incident: ${incidentId}`);

      return {
        status: 201,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: {
          sessionId,
          incidentId: session.incidentId,
          createdAt: session.createdAt,
          chatUrl: `/triage-chat/${sessionId}`
        }
      };
    } catch (error) {
      context.error('Error creating session:', error.message);
      return {
        status: 500,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: `Failed to create session: ${error.message}` }
      };
    }
  }
});
