// POST /api/session
// Create a new triage chat session (typically called by TD-Triage Logic App)

const { app } = require('@azure/functions');
const { upsertSession } = require('../shared/cosmosClient');
const { v4: uuidv4 } = require('uuid');

app.http('createSession', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'session',
  handler: async (request, context) => {
    context.log('POST create session request');

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      // Parse request body
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

      // Validate required fields
      if (!incidentId) {
        return {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          jsonBody: { error: 'incidentId is required' }
        };
      }

      // Generate session ID
      const sessionId = uuidv4();
      const now = new Date().toISOString();

      // Create session document
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

      // Save to Cosmos DB
      await upsertSession(session);

      context.log(`Session created: ${sessionId} for incident: ${incidentId}`);

      return {
        status: 201,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        jsonBody: {
          sessionId,
          incidentId: session.incidentId,
          createdAt: session.createdAt,
          message: 'Session created successfully'
        }
      };
    } catch (error) {
      context.error('Error creating session:', error.message);
      return {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        jsonBody: { error: `Failed to create session: ${error.message}` }
      };
    }
  }
});
