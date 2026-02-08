// /api/PromptRunAPI.js
const { app } = require('@azure/functions');
const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');
const { OpenAIClient, AzureKeyCredential } = require('@azure/openai');

// Initialize clients
let tableClient = null;
let openAIClient = null;

function getTableClient() {
  if (!tableClient) {
    const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const tableName = process.env.PROMPT_RUNS_TABLE_NAME || 'PromptRuns';

    if (!account || !accountKey) {
      throw new Error('Azure Storage credentials not configured.');
    }

    const credential = new AzureNamedKeyCredential(account, accountKey);
    tableClient = new TableClient(
      `https://${account}.table.core.windows.net`,
      tableName,
      credential
    );
  }
  return tableClient;
}

function getPromptsTableClient() {
  const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

  if (!account || !accountKey) {
    throw new Error('Azure Storage credentials not configured.');
  }

  const credential = new AzureNamedKeyCredential(account, accountKey);
  return new TableClient(
    `https://${account}.table.core.windows.net`,
    tableName,
    credential
  );
}

function getOpenAIClient() {
  if (!openAIClient) {
    const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
    const apiKey = process.env.AZURE_OPENAI_API_KEY;

    if (!endpoint || !apiKey) {
      throw new Error('Azure OpenAI credentials not configured.');
    }

    openAIClient = new OpenAIClient(endpoint, new AzureKeyCredential(apiKey));
  }
  return openAIClient;
}

function generateId() {
  const crypto = require('crypto');
  return `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
}

function getUserFromRequest(request) {
  const clientPrincipal = request.headers.get('x-ms-client-principal');
  if (clientPrincipal) {
    try {
      const decoded = Buffer.from(clientPrincipal, 'base64').toString('utf8');
      const user = JSON.parse(decoded);
      return user.userDetails || 'authenticated-user';
    } catch (e) {
      return 'authenticated-user';
    }
  }
  return 'system';
}

// Variable substitution
function substituteVariables(text, variables) {
  if (!text || !variables) return text;

  let result = text;
  for (const [key, value] of Object.entries(variables)) {
    // Support multiple placeholder formats: {{key}}, {key}, [key]
    const patterns = [
      new RegExp(`\\{\\{${key}\\}\\}`, 'gi'),
      new RegExp(`\\{${key}\\}`, 'gi'),
      new RegExp(`\\[${key}\\]`, 'gi')
    ];
    patterns.forEach(pattern => {
      result = result.replace(pattern, String(value || ''));
    });
  }
  return result;
}

// Validate required variables
function validateVariables(promptVariables, providedVariables) {
  const missing = [];
  if (promptVariables && Array.isArray(promptVariables)) {
    for (const varDef of promptVariables) {
      if (varDef.required && !providedVariables[varDef.name]) {
        missing.push(varDef.name);
      }
    }
  }
  return missing;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// POST /api/prompts/{id}/run - Execute a prompt
app.http('PromptRunAPI-Execute', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/{id}/run',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const promptId = request.params.id;
      const body = await request.json();
      const user = getUserFromRequest(request);
      const now = new Date().toISOString();

      context.log(`Running prompt: ${promptId} by ${user}`);

      // Get prompt from storage
      const promptsClient = getPromptsTableClient();
      const promptEntity = await promptsClient.getEntity('PROMPT', promptId);

      if (promptEntity.isDeleted) {
        return {
          status: 404,
          headers: corsHeaders,
          jsonBody: { error: 'Prompt not found' }
        };
      }

      const prompt = {
        id: promptEntity.rowKey,
        title: promptEntity.title,
        variables: promptEntity.variables ? JSON.parse(promptEntity.variables) : [],
        systemGuidance: promptEntity.systemGuidance || '',
        userInstructions: promptEntity.userInstructions,
        modelSettings: promptEntity.modelSettings ? JSON.parse(promptEntity.modelSettings) : {}
      };

      // Validate required variables
      const missingVars = validateVariables(prompt.variables, body.variables || {});
      if (missingVars.length > 0) {
        return {
          status: 400,
          headers: corsHeaders,
          jsonBody: { error: `Missing required variables: ${missingVars.join(', ')}` }
        };
      }

      // Substitute variables in system guidance and user instructions
      const systemMessage = substituteVariables(prompt.systemGuidance, body.variables || {});
      const userMessage = substituteVariables(prompt.userInstructions, body.variables || {});

      // Add pasted context if provided
      let finalUserMessage = userMessage;
      if (body.context) {
        finalUserMessage = `# Context\n\n${body.context}\n\n---\n\n${userMessage}`;
      }

      context.log('Calling Azure OpenAI...');

      // Call Azure OpenAI
      const client = getOpenAIClient();
      const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';
      const temperature = prompt.modelSettings.temperature || 0.7;
      const maxTokens = prompt.modelSettings.maxTokens || 2000;

      const messages = [];
      if (systemMessage) {
        messages.push({ role: 'system', content: systemMessage });
      }
      messages.push({ role: 'user', content: finalUserMessage });

      const result = await client.getChatCompletions(deployment, messages, {
        temperature,
        maxTokens
      });

      const output = result.choices[0]?.message?.content || '';
      const usage = result.usage || {};

      context.log(`OpenAI response received. Tokens: ${usage.totalTokens || 0}`);

      // Store the run
      const runId = generateId();
      const runEntity = {
        partitionKey: 'PROMPT_RUN',
        rowKey: runId,
        promptId,
        promptTitle: prompt.title,
        submittedBy: user,
        submittedAt: now,
        contextSummary: body.context ? body.context.substring(0, 500) : '', // Store first 500 chars
        variables: JSON.stringify(body.variables || {}),
        provider: 'Azure OpenAI',
        deployment,
        output: output.substring(0, 10000), // Store first 10k chars in table
        outputLength: output.length,
        promptTokens: usage.promptTokens || 0,
        completionTokens: usage.completionTokens || 0,
        totalTokens: usage.totalTokens || 0,
        status: 'completed',
        temperature,
        maxTokens
      };

      const runsClient = getTableClient();
      await runsClient.createEntity(runEntity);

      context.log(`Prompt run stored: ${runId}`);

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: {
          runId,
          output,
          usage: {
            promptTokens: usage.promptTokens || 0,
            completionTokens: usage.completionTokens || 0,
            totalTokens: usage.totalTokens || 0
          },
          submittedAt: now
        }
      };
    } catch (error) {
      context.error('Error running prompt:', error);

      if (error.statusCode === 404) {
        return {
          status: 404,
          headers: corsHeaders,
          jsonBody: { error: 'Prompt not found' }
        };
      }

      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message }
      };
    }
  }
});

// GET /api/prompt-runs - List all runs (for audit/admin)
app.http('PromptRunAPI-List', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompt-runs',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      context.log('Listing prompt runs');
      const client = getTableClient();

      // Query parameters for filtering
      const url = new URL(request.url);
      const promptId = url.searchParams.get('promptId');
      const user = url.searchParams.get('user');
      const limit = parseInt(url.searchParams.get('limit') || '100');

      // Build query filter (escape single quotes to prevent OData injection)
      let filter = "PartitionKey eq 'PROMPT_RUN'";
      if (promptId) {
        const safePromptId = promptId.replace(/'/g, "''");
        filter += ` and promptId eq '${safePromptId}'`;
      }
      if (user) {
        const safeUser = user.replace(/'/g, "''");
        filter += ` and submittedBy eq '${safeUser}'`;
      }

      const runs = [];
      const entities = client.listEntities({ queryOptions: { filter } });

      for await (const entity of entities) {
        runs.push({
          runId: entity.rowKey,
          promptId: entity.promptId,
          promptTitle: entity.promptTitle || '',
          submittedBy: entity.submittedBy || '',
          submittedAt: entity.submittedAt || '',
          contextSummary: entity.contextSummary || '',
          variables: entity.variables ? JSON.parse(entity.variables) : {},
          provider: entity.provider || 'Azure OpenAI',
          deployment: entity.deployment || '',
          outputLength: entity.outputLength || 0,
          promptTokens: entity.promptTokens || 0,
          completionTokens: entity.completionTokens || 0,
          totalTokens: entity.totalTokens || 0,
          status: entity.status || 'completed',
          temperature: entity.temperature || 0,
          maxTokens: entity.maxTokens || 0
        });

        if (runs.length >= limit) break;
      }

      // Sort by submission date (newest first)
      runs.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: { runs, count: runs.length }
      };
    } catch (error) {
      context.error('Error listing prompt runs:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message }
      };
    }
  }
});

// GET /api/prompt-runs/{id} - Get single run with full output
app.http('PromptRunAPI-Get', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompt-runs/{id}',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const id = request.params.id;
      context.log(`Getting prompt run: ${id}`);

      const client = getTableClient();
      const entity = await client.getEntity('PROMPT_RUN', id);

      const run = {
        runId: entity.rowKey,
        promptId: entity.promptId,
        promptTitle: entity.promptTitle || '',
        submittedBy: entity.submittedBy || '',
        submittedAt: entity.submittedAt || '',
        contextSummary: entity.contextSummary || '',
        variables: entity.variables ? JSON.parse(entity.variables) : {},
        provider: entity.provider || 'Azure OpenAI',
        deployment: entity.deployment || '',
        output: entity.output || '',
        outputLength: entity.outputLength || 0,
        promptTokens: entity.promptTokens || 0,
        completionTokens: entity.completionTokens || 0,
        totalTokens: entity.totalTokens || 0,
        status: entity.status || 'completed',
        temperature: entity.temperature || 0,
        maxTokens: entity.maxTokens || 0
      };

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: run
      };
    } catch (error) {
      context.error('Error getting prompt run:', error);
      if (error.statusCode === 404) {
        return {
          status: 404,
          headers: corsHeaders,
          jsonBody: { error: 'Run not found' }
        };
      }
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message }
      };
    }
  }
});
