// POST /api/session/{sessionId}
// Send a follow-up message and get AI response

const { app } = require('@azure/functions');
const { getSessionById, upsertSession } = require('../shared/cosmosClient');
const { callClaude, buildSystemPrompt } = require('../shared/claudeClient');

app.http('postSession', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'session/{sessionId}',
  handler: async (request, context) => {
    const sessionId = request.params.sessionId;
    context.log(`POST session request for: ${sessionId}`);

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

      // Parse request body
      const body = await request.json().catch(() => ({}));
      const { message, temperature } = body;

      if (!message || typeof message !== 'string' || message.trim().length === 0) {
        return {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Message is required and must be a non-empty string.' }
        };
      }

      // Get existing session
      let session = await getSessionById(sessionId);

      if (!session) {
        return {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          jsonBody: { error: 'Session not found. Sessions must be created by the TD-Triage Logic App.' }
        };
      }

      context.log(`Found session for incident: ${session.incidentId}`);

      // Build conversation history for Claude
      const conversationHistory = session.conversationHistory || [];

      // Add user message
      const userMessage = { role: 'user', content: message.trim() };
      conversationHistory.push(userMessage);

      // Build system prompt with session context
      const systemPrompt = buildSystemPrompt(session);

      // Call Claude API
      context.log('Calling Claude API for follow-up response...');
      const claudeResponse = await callClaude({
        systemPrompt,
        messages: conversationHistory,
        temperature: typeof temperature === 'number' ? Math.min(1, Math.max(0, temperature)) : 0.3
      });

      // Add assistant response to history
      const assistantMessage = { role: 'assistant', content: claudeResponse.content };
      conversationHistory.push(assistantMessage);

      // Update session
      session.conversationHistory = conversationHistory;
      session.lastUpdated = new Date().toISOString();
      session.messageCount = conversationHistory.length;

      // Save updated session
      await upsertSession(session);

      context.log(`Session updated, message count: ${session.messageCount}`);

      return {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        jsonBody: {
          response: claudeResponse.content,
          messageCount: session.messageCount,
          usage: claudeResponse.usage,
          model: claudeResponse.model
        }
      };
    } catch (error) {
      context.error('Error processing message:', error.message);

      // Check for specific error types
      if (error.message.includes('Claude API error')) {
        return {
          status: 502,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          jsonBody: { error: `AI service error: ${error.message}` }
        };
      }

      return {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        jsonBody: { error: `Failed to process message: ${error.message}` }
      };
    }
  }
});
