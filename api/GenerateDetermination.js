// /api/GenerateDetermination.js
// Azure Functions (v4, Node 18+) - Determination Generator API
// Calls Claude via Azure AI Foundry to generate client-facing determination summaries

const { app } = require('@azure/functions');

const SYSTEM_PROMPT = `You are a Tier 2 SOC analyst at a Managed Security Service Provider called eGroup | Enabling Technologies, operating under the ThreatDefender MSSP service. You write client-facing determination summaries for security incidents that have been investigated and resolved.

Given the detection type, determination outcome, client name, internal investigation notes and AI Triage notes write a brief, professional, client-facing summary suitable for a ConnectWise service ticket discussion note.

Rules:
- Write in first-person plural ("we reviewed," "our analysis confirmed")
- Keep it to 3-5 sentences max
- Include: what was detected, what was investigated, the determination and why, and any action taken
- Avoid internal jargon, internal tool names, or overly technical detail the client would not recognize
- Do not include recommendations unless the investigation revealed something the client should act on
- If the determination is "Benign Positive" or "False Positive", make it clear why the activity is safe/expected
- If the determination is "True Positive", include the remediation actions taken
- Use a professional but approachable tone
- Do not use markdown formatting, bullet points, or headers. Write in plain paragraph form.
- Include the IP address where available in the communication
- For any IP address, if our notes show threat intelligence, please include that in the communication`;

function buildUserPrompt({ clientName, detectionType, determination, internalNotes, aiTriageNotes }) {
  let prompt = `Client: ${clientName}
Detection Type: ${detectionType}
Determination: ${determination}

Internal Analyst Notes:
${internalNotes}`;

  if (aiTriageNotes) {
    prompt += `

AI Triage Notes:
${aiTriageNotes}`;
  }

  return prompt;
}

app.http('GenerateDetermination', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'generate-determination',
  handler: async (request, context) => {
    context.log('GenerateDetermination function triggered');

    // CORS preflight
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

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json'
    };

    try {
      const body = await request.json();
      const { detectionType, determination, clientName, internalNotes, aiTriageNotes, screenshots } = body || {};

      // Validate required fields
      if (!detectionType || !determination || !clientName || !internalNotes) {
        return {
          status: 400,
          headers: corsHeaders,
          jsonBody: {
            error: 'Missing required fields. Please provide detectionType, determination, clientName, and internalNotes.'
          }
        };
      }

      // Get Claude API configuration from app settings
      const claudeKey = process.env.CLAUDE_API_KEY;
      const claudeEndpoint = process.env.CLAUDE_API_ENDPOINT;
      const claudeModel = process.env.CLAUDE_MODEL;

      if (!claudeKey || !claudeEndpoint) {
        context.log('Missing Claude API configuration: CLAUDE_API_KEY or CLAUDE_API_ENDPOINT');
        return {
          status: 500,
          headers: corsHeaders,
          jsonBody: { error: 'Claude API is not configured. Contact your administrator.' }
        };
      }

      const userPrompt = buildUserPrompt({ clientName, detectionType, determination, internalNotes, aiTriageNotes });

      context.log('Calling Claude API for determination generation');

      // Build the user message content — multimodal if screenshots are attached
      let userContent;
      const validScreenshots = Array.isArray(screenshots)
        ? screenshots.filter(s => s.data && s.mediaType)
        : [];

      if (validScreenshots.length > 0) {
        context.log(`Including ${validScreenshots.length} screenshot(s) in request`);
        userContent = [];
        for (const s of validScreenshots) {
          userContent.push({
            type: 'image',
            source: {
              type: 'base64',
              media_type: s.mediaType,
              data: s.data
            }
          });
        }
        userContent.push({ type: 'text', text: userPrompt });
      } else {
        userContent = userPrompt;
      }

      // Use the endpoint as-is — CLAUDE_API_ENDPOINT should be the full URL
      const url = claudeEndpoint.replace(/\/+$/, '');
      const requestBody = {
        model: claudeModel || 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        temperature: 0.4,
        system: SYSTEM_PROMPT,
        messages: [
          { role: 'user', content: userContent }
        ]
      };

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'x-api-key': claudeKey,
          'anthropic-version': '2023-06-01',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        const errorText = await response.text();
        context.log(`Claude API error (${response.status}): ${errorText}`);
        return {
          status: 502,
          headers: corsHeaders,
          jsonBody: { error: `AI service returned an error (${response.status}). Please try again.` }
        };
      }

      const data = await response.json();
      const result = data.content?.[0]?.text;

      if (!result) {
        context.log('Claude API returned empty response:', JSON.stringify(data));
        return {
          status: 502,
          headers: corsHeaders,
          jsonBody: { error: 'AI service returned an empty response. Please try again.' }
        };
      }

      context.log('Determination generated successfully');

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: { result: result.trim() }
      };

    } catch (err) {
      context.log('GenerateDetermination error:', err.message, err.stack);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: 'An unexpected error occurred. Please try again later.' }
      };
    }
  }
});
