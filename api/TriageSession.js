// /api/TriageSession.js
// Azure Functions (v4, Node 18+) - AI Triage Chat Session API
// Uses direct Cosmos DB REST API to avoid SDK crypto issues in SWA environment

const { app } = require('@azure/functions');
const crypto = require('crypto');

// Cosmos DB configuration
const COSMOS_DATABASE = 'TriageDB';
const COSMOS_CONTAINER = 'Sessions';

// Claude API configuration
const CLAUDE_ENDPOINT = process.env.CLAUDE_API_ENDPOINT || 'https://th-aifoundry.services.ai.azure.com/anthropic/v1/messages';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-4-20250514';

// Parse Cosmos DB connection string
function parseConnectionString(connectionString) {
  if (!connectionString) {
    throw new Error('COSMOS_CONNECTION environment variable not configured');
  }

  const parts = {};
  connectionString.split(';').forEach(part => {
    const [key, ...valueParts] = part.split('=');
    if (key && valueParts.length > 0) {
      parts[key] = valueParts.join('=');
    }
  });

  const endpoint = parts['AccountEndpoint'];
  const key = parts['AccountKey'];

  if (!endpoint || !key) {
    throw new Error('Invalid COSMOS_CONNECTION: missing AccountEndpoint or AccountKey');
  }

  return { endpoint: endpoint.replace(/\/$/, ''), key };
}

// Generate Cosmos DB REST API authorization header
function generateCosmosAuthHeader(verb, resourceType, resourceLink, date, masterKey) {
  const text = `${verb.toLowerCase()}\n${resourceType.toLowerCase()}\n${resourceLink}\n${date.toLowerCase()}\n\n`;

  const body = Buffer.from(text, 'utf-8');
  const signature = crypto.createHmac('sha256', Buffer.from(masterKey, 'base64'))
    .update(body)
    .digest('base64');

  return encodeURIComponent(`type=master&ver=1.0&sig=${signature}`);
}

// Make Cosmos DB REST API request
async function cosmosRequest(method, resourceType, resourceLink, body = null) {
  const { endpoint, key } = parseConnectionString(process.env.COSMOS_CONNECTION);
  const date = new Date().toUTCString();
  const auth = generateCosmosAuthHeader(method, resourceType, resourceLink, date, key);

  const url = `${endpoint}/${resourceLink}`;

  const headers = {
    'Authorization': auth,
    'x-ms-date': date,
    'x-ms-version': '2018-12-31',
    'Content-Type': 'application/json'
  };

  // Add partition key header for document operations
  if (resourceType === 'docs' && body && body.incidentId) {
    headers['x-ms-documentdb-partitionkey'] = JSON.stringify([body.incidentId]);
  }

  const options = {
    method,
    headers
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  const responseText = await response.text();

  if (!response.ok && response.status !== 404) {
    throw new Error(`Cosmos DB error ${response.status}: ${responseText}`);
  }

  return {
    status: response.status,
    data: responseText ? JSON.parse(responseText) : null
  };
}

// Query documents in Cosmos DB
async function queryDocuments(query, parameters = []) {
  const { endpoint, key } = parseConnectionString(process.env.COSMOS_CONNECTION);
  const date = new Date().toUTCString();
  const resourceLink = `dbs/${COSMOS_DATABASE}/colls/${COSMOS_CONTAINER}`;
  const auth = generateCosmosAuthHeader('POST', 'docs', resourceLink, date, key);

  const url = `${endpoint}/${resourceLink}/docs`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': auth,
      'x-ms-date': date,
      'x-ms-version': '2018-12-31',
      'Content-Type': 'application/query+json',
      'x-ms-documentdb-isquery': 'true',
      'x-ms-documentdb-query-enablecrosspartition': 'true'
    },
    body: JSON.stringify({ query, parameters })
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(`Cosmos DB query error ${response.status}: ${responseText}`);
  }

  const data = JSON.parse(responseText);
  return data.Documents || [];
}

// Create document in Cosmos DB
async function createDocument(document) {
  const resourceLink = `dbs/${COSMOS_DATABASE}/colls/${COSMOS_CONTAINER}`;
  const { endpoint, key } = parseConnectionString(process.env.COSMOS_CONNECTION);
  const date = new Date().toUTCString();
  const auth = generateCosmosAuthHeader('POST', 'docs', resourceLink, date, key);

  const url = `${endpoint}/${resourceLink}/docs`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': auth,
      'x-ms-date': date,
      'x-ms-version': '2018-12-31',
      'Content-Type': 'application/json',
      'x-ms-documentdb-partitionkey': JSON.stringify([document.incidentId])
    },
    body: JSON.stringify(document)
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(`Cosmos DB create error ${response.status}: ${responseText}`);
  }

  return JSON.parse(responseText);
}

// Upsert document in Cosmos DB
async function upsertDocument(document) {
  const resourceLink = `dbs/${COSMOS_DATABASE}/colls/${COSMOS_CONTAINER}`;
  const { endpoint, key } = parseConnectionString(process.env.COSMOS_CONNECTION);
  const date = new Date().toUTCString();
  const auth = generateCosmosAuthHeader('POST', 'docs', resourceLink, date, key);

  const url = `${endpoint}/${resourceLink}/docs`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': auth,
      'x-ms-date': date,
      'x-ms-version': '2018-12-31',
      'Content-Type': 'application/json',
      'x-ms-documentdb-partitionkey': JSON.stringify([document.incidentId]),
      'x-ms-documentdb-is-upsert': 'true'
    },
    body: JSON.stringify(document)
  });

  const responseText = await response.text();

  if (!response.ok) {
    throw new Error(`Cosmos DB upsert error ${response.status}: ${responseText}`);
  }

  return JSON.parse(responseText);
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

// Single function to handle all TriageSession operations
// GET /api/TriageSession?sessionId=xxx - Retrieve session
// POST /api/TriageSession?sessionId=xxx - Send follow-up message
// POST /api/TriageSession (no sessionId) - Create new session
app.http('TriageSession', {
  methods: ['GET', 'POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log(`TriageSession: ${request.method}`);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS_HEADERS };
    }

    // Get sessionId from query params
    const url = new URL(request.url);
    const sessionId = url.searchParams.get('sessionId');

    try {
      // GET - Retrieve session
      if (request.method === 'GET') {
        if (!sessionId) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'sessionId query parameter is required' }
          };
        }

        context.log(`GET session: ${sessionId}`);

        const resources = await queryDocuments(
          'SELECT * FROM c WHERE c.id = @sessionId',
          [{ name: '@sessionId', value: sessionId }]
        );

        if (resources.length === 0) {
          return {
            status: 404,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'Session not found' }
          };
        }

        return {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { session: resources[0] }
        };
      }

      // POST with sessionId - Send follow-up message
      if (request.method === 'POST' && sessionId) {
        context.log(`POST message to session: ${sessionId}`);

        const body = await request.json().catch(() => ({}));
        const { message } = body;

        if (!message || !message.trim()) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'Message is required' }
          };
        }

        // Fetch session
        const resources = await queryDocuments(
          'SELECT * FROM c WHERE c.id = @sessionId',
          [{ name: '@sessionId', value: sessionId }]
        );

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
        await upsertDocument(updatedSession);

        return {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: {
            response: assistantResponse,
            messageCount: updatedSession.messageCount
          }
        };
      }

      // POST without sessionId - Create new session
      if (request.method === 'POST' && !sessionId) {
        context.log('POST create new session');

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

        const newSessionId = generateUUID();
        const now = new Date().toISOString();

        const session = {
          id: newSessionId,
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

        await createDocument(session);

        context.log(`Session created: ${newSessionId} for incident: ${incidentId}`);

        return {
          status: 201,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: {
            sessionId: newSessionId,
            incidentId: session.incidentId,
            createdAt: session.createdAt,
            chatUrl: `/triage-chat/${newSessionId}`
          }
        };
      }

      return {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'Invalid request' }
      };

    } catch (error) {
      context.error('TriageSession error:', error.message);
      return {
        status: 500,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: `Operation failed: ${error.message}` }
      };
    }
  }
});
