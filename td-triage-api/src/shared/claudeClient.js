// Claude API client for Azure AI Foundry
// Calls Claude via the Anthropic-compatible endpoint

const DEFAULT_MODEL = 'claude-sonnet-4-20250514';
const DEFAULT_MAX_TOKENS = 4096;

/**
 * Call Claude API for follow-up analysis
 * @param {Object} params - Request parameters
 * @param {string} params.systemPrompt - System prompt for context
 * @param {Array} params.messages - Conversation history [{role, content}]
 * @param {number} params.maxTokens - Maximum tokens in response
 * @param {number} params.temperature - Temperature for response generation
 * @returns {Object} Claude API response with content
 */
async function callClaude({ systemPrompt, messages, maxTokens = DEFAULT_MAX_TOKENS, temperature = 0.3 }) {
  const endpoint = process.env.CLAUDE_API_ENDPOINT;
  const apiKey = process.env.CLAUDE_API_KEY;
  const model = process.env.CLAUDE_MODEL || DEFAULT_MODEL;

  if (!endpoint) {
    throw new Error('CLAUDE_API_ENDPOINT environment variable not configured');
  }
  if (!apiKey) {
    throw new Error('CLAUDE_API_KEY environment variable not configured');
  }

  const requestBody = {
    model,
    max_tokens: maxTokens,
    temperature,
    system: systemPrompt,
    messages: messages.map(msg => ({
      role: msg.role,
      content: msg.content
    }))
  };

  const response = await fetch(endpoint, {
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

  // Extract text content from response
  const content = data.content?.[0]?.text || '';

  return {
    content,
    model: data.model,
    usage: data.usage,
    stopReason: data.stop_reason
  };
}

/**
 * Build a triage-specific system prompt with incident context
 * @param {Object} session - The session document with incident details
 * @returns {string} Formatted system prompt
 */
function buildSystemPrompt(session) {
  // Use custom system prompt if provided, otherwise build default
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

module.exports = {
  callClaude,
  buildSystemPrompt
};
