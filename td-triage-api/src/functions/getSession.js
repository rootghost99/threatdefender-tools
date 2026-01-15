// GET /api/session/{sessionId}
// Retrieves a triage chat session by ID

const { app } = require('@azure/functions');
const { getSessionById } = require('../shared/cosmosClient');

app.http('getSession', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'session/{sessionId}',
  handler: async (request, context) => {
    const sessionId = request.params.sessionId;
    context.log(`GET session request for: ${sessionId}`);

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
      // Validate sessionId format (GUID)
      const guidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
      if (!sessionId || !guidRegex.test(sessionId)) {
        return {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Invalid session ID format. Expected GUID.' }
        };
      }

      const session = await getSessionById(sessionId);

      if (!session) {
        return {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Session not found' }
        };
      }

      context.log(`Session found: ${session.id}, incident: ${session.incidentId}`);

      // Return session data (excluding sensitive fields if needed)
      return {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        jsonBody: {
          session: {
            id: session.id,
            incidentId: session.incidentId,
            incidentTitle: session.incidentTitle,
            incidentSeverity: session.incidentSeverity,
            tenantName: session.tenantName,
            initialAnalysis: session.initialAnalysis,
            conversationHistory: session.conversationHistory || [],
            createdAt: session.createdAt,
            lastUpdated: session.lastUpdated,
            messageCount: session.messageCount || 0
          }
        }
      };
    } catch (error) {
      context.error('Error retrieving session:', error.message);
      return {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        jsonBody: { error: `Failed to retrieve session: ${error.message}` }
      };
    }
  }
});
