// PromptsAPI using Azure Table Storage SDK (properly handles authentication)
const { app } = require('@azure/functions');
const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');
const { OpenAIClient, AzureKeyCredential } = require('@azure/openai');

console.log('[PromptsAPI-REST] Module loading...');

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// Table Storage clients (lazy initialization)
let promptsTableClient = null;
let runsTableClient = null;
let openAIClient = null;

function getTableClient(tableName) {
  const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;

  if (!account || !accountKey) {
    throw new Error('Azure Storage credentials not configured');
  }

  const credential = new AzureNamedKeyCredential(account, accountKey);
  return new TableClient(
    `https://${account}.table.core.windows.net`,
    tableName,
    credential
  );
}

function getPromptsTableClient() {
  if (!promptsTableClient) {
    const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
    promptsTableClient = getTableClient(tableName);
  }
  return promptsTableClient;
}

function getRunsTableClient() {
  if (!runsTableClient) {
    const tableName = process.env.PROMPT_RUNS_TABLE_NAME || 'PromptRuns';
    runsTableClient = getTableClient(tableName);
  }
  return runsTableClient;
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

// Helper functions for prompt execution
function generateId() {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
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

// UNIFIED HANDLER
app.http('PromptsAPI-Unified', {
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/{*path}',
  handler: async (request, context) => {
    context.log('[PromptsAPI-REST] Request:', request.method, request.url);

    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const method = request.method;
      const path = request.params.path || '';
      const pathParts = path.split('/').filter(p => p);

      context.log('Method:', method, 'Path:', path, 'Parts:', pathParts);

      // Route to appropriate handler
      if (pathParts.length === 0) {
        if (method === 'GET') {
          return await listPrompts(request, context);
        } else if (method === 'POST') {
          return await createPrompt(request, context);
        }
      } else if (pathParts.length === 1) {
        const id = pathParts[0];
        if (method === 'GET') {
          return await getPrompt(request, context, id);
        } else if (method === 'PUT') {
          return await updatePrompt(request, context, id);
        } else if (method === 'DELETE') {
          return await deletePrompt(request, context, id);
        }
      } else if (pathParts.length === 2 && pathParts[1] === 'run') {
        // /api/prompts/{id}/run
        const id = pathParts[0];
        if (method === 'POST') {
          return await runPrompt(request, context, id);
        }
      }

      return {
        status: 405,
        headers: corsHeaders,
        jsonBody: { error: 'Method not allowed' }
      };
    } catch (error) {
      context.error('[PromptsAPI-REST] Error:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message }
      };
    }
  }
});

// LIST prompts
async function listPrompts(request, context) {
  const tableClient = getPromptsTableClient();
  const prompts = [];

  try {
    const entities = tableClient.listEntities({
      queryOptions: { filter: "PartitionKey eq 'PROMPT'" }
    });

    for await (const entity of entities) {
      if (entity.isDeleted === true) continue;

      let tags = [];
      let variables = [];
      let modelSettings = {};

      try { tags = entity.tags ? JSON.parse(entity.tags) : []; } catch (e) {}
      try { variables = entity.variables ? JSON.parse(entity.variables) : []; } catch (e) {}
      try { modelSettings = entity.modelSettings ? JSON.parse(entity.modelSettings) : {}; } catch (e) {}

      prompts.push({
        id: entity.rowKey,
        title: entity.title || '',
        description: entity.description || '',
        category: entity.category || 'General',
        tags,
        collection: entity.collection || '',
        variables,
        systemGuidance: entity.systemGuidance || '',
        userInstructions: entity.userInstructions || '',
        modelSettings,
        status: entity.status || 'active',
        createdBy: entity.createdBy || 'system',
        createdAt: entity.createdAt || new Date().toISOString(),
        updatedBy: entity.updatedBy || '',
        updatedAt: entity.updatedAt || ''
      });
    }

    prompts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: { prompts, count: prompts.length }
    };
  } catch (error) {
    context.error('[listPrompts] Error:', error);
    throw error;
  }
}

// GET single prompt
async function getPrompt(request, context, id) {
  const tableClient = getPromptsTableClient();

  try {
    const entity = await tableClient.getEntity('PROMPT', id);

    if (entity.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }

    let tags = [];
    let variables = [];
    let modelSettings = {};

    try { tags = entity.tags ? JSON.parse(entity.tags) : []; } catch (e) {}
    try { variables = entity.variables ? JSON.parse(entity.variables) : []; } catch (e) {}
    try { modelSettings = entity.modelSettings ? JSON.parse(entity.modelSettings) : {}; } catch (e) {}

    const prompt = {
      id: entity.rowKey,
      title: entity.title || '',
      description: entity.description || '',
      category: entity.category || 'General',
      tags,
      collection: entity.collection || '',
      variables,
      systemGuidance: entity.systemGuidance || '',
      userInstructions: entity.userInstructions || '',
      modelSettings,
      status: entity.status || 'active',
      createdBy: entity.createdBy || 'system',
      createdAt: entity.createdAt || new Date().toISOString(),
      updatedBy: entity.updatedBy || '',
      updatedAt: entity.updatedAt || ''
    };

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: prompt
    };
  } catch (error) {
    if (error.statusCode === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }
    context.error('[getPrompt] Error:', error);
    throw error;
  }
}

// CREATE prompt
async function createPrompt(request, context) {
  const tableClient = getPromptsTableClient();
  const body = await request.json();
  const user = getUserFromRequest(request);
  const now = new Date().toISOString();
  const id = generateId();

  if (!body.title || !body.userInstructions) {
    return {
      status: 400,
      headers: corsHeaders,
      jsonBody: { error: 'Title and user instructions are required' }
    };
  }

  const entity = {
    partitionKey: 'PROMPT',
    rowKey: id,
    title: body.title,
    description: body.description || '',
    category: body.category || 'General',
    tags: JSON.stringify(body.tags || []),
    collection: body.collection || '',
    variables: JSON.stringify(body.variables || []),
    systemGuidance: body.systemGuidance || '',
    userInstructions: body.userInstructions,
    modelSettings: JSON.stringify(body.modelSettings || { temperature: 0.7, maxTokens: 2000 }),
    status: 'active',
    createdBy: user,
    createdAt: now,
    updatedBy: '',
    updatedAt: '',
    isDeleted: false
  };

  try {
    await tableClient.createEntity(entity);

    const prompt = {
      id,
      title: entity.title,
      description: entity.description,
      category: entity.category,
      tags: JSON.parse(entity.tags),
      collection: entity.collection,
      variables: JSON.parse(entity.variables),
      systemGuidance: entity.systemGuidance,
      userInstructions: entity.userInstructions,
      modelSettings: JSON.parse(entity.modelSettings),
      status: entity.status,
      createdBy: entity.createdBy,
      createdAt: entity.createdAt,
      updatedBy: entity.updatedBy,
      updatedAt: entity.updatedAt
    };

    return {
      status: 201,
      headers: corsHeaders,
      jsonBody: { message: 'Prompt created', prompt }
    };
  } catch (error) {
    context.error('[createPrompt] Error:', error);
    throw error;
  }
}

// UPDATE prompt
async function updatePrompt(request, context, id) {
  const tableClient = getPromptsTableClient();
  const body = await request.json();
  const user = getUserFromRequest(request);
  const now = new Date().toISOString();

  try {
    // First get existing
    const existing = await tableClient.getEntity('PROMPT', id);

    if (existing.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }

    const updated = {
      ...existing,
      title: body.title !== undefined ? body.title : existing.title,
      description: body.description !== undefined ? body.description : existing.description,
      category: body.category !== undefined ? body.category : existing.category,
      tags: body.tags !== undefined ? JSON.stringify(body.tags) : existing.tags,
      collection: body.collection !== undefined ? body.collection : existing.collection,
      variables: body.variables !== undefined ? JSON.stringify(body.variables) : existing.variables,
      systemGuidance: body.systemGuidance !== undefined ? body.systemGuidance : existing.systemGuidance,
      userInstructions: body.userInstructions !== undefined ? body.userInstructions : existing.userInstructions,
      modelSettings: body.modelSettings !== undefined ? JSON.stringify(body.modelSettings) : existing.modelSettings,
      status: body.status !== undefined ? body.status : existing.status,
      updatedBy: user,
      updatedAt: now
    };

    await tableClient.updateEntity(updated, 'Merge');

    const prompt = {
      id,
      title: updated.title,
      description: updated.description,
      category: updated.category,
      tags: JSON.parse(updated.tags),
      collection: updated.collection,
      variables: JSON.parse(updated.variables),
      systemGuidance: updated.systemGuidance,
      userInstructions: updated.userInstructions,
      modelSettings: JSON.parse(updated.modelSettings),
      status: updated.status,
      createdBy: updated.createdBy,
      createdAt: updated.createdAt,
      updatedBy: updated.updatedBy,
      updatedAt: updated.updatedAt
    };

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: { message: 'Prompt updated', prompt }
    };
  } catch (error) {
    if (error.statusCode === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }
    context.error('[updatePrompt] Error:', error);
    throw error;
  }
}

// DELETE prompt (soft delete)
async function deletePrompt(request, context, id) {
  const tableClient = getPromptsTableClient();
  const user = getUserFromRequest(request);
  const now = new Date().toISOString();

  try {
    const existing = await tableClient.getEntity('PROMPT', id);

    if (existing.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }

    const updated = {
      ...existing,
      isDeleted: true,
      status: 'deleted',
      updatedBy: user,
      updatedAt: now
    };

    await tableClient.updateEntity(updated, 'Merge');

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: { message: 'Prompt deleted successfully' }
    };
  } catch (error) {
    if (error.statusCode === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }
    context.error('[deletePrompt] Error:', error);
    throw error;
  }
}

// RUN prompt (POST /api/prompts/{id}/run)
async function runPrompt(request, context, id) {
  context.log('[PromptsAPI-REST] RUN prompt:', id);

  try {
    const tableClient = getPromptsTableClient();
    const runsTableClient = getRunsTableClient();
    const body = await request.json();
    const user = getUserFromRequest(request);
    const now = new Date().toISOString();

    context.log(`Running prompt: ${id} by ${user}`);

    // Get prompt from storage
    const promptEntity = await tableClient.getEntity('PROMPT', id);

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
    const openAI = getOpenAIClient();
    const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';
    const temperature = prompt.modelSettings.temperature || 0.7;
    const maxTokens = prompt.modelSettings.maxTokens || 2000;

    const messages = [];
    if (systemMessage) {
      messages.push({ role: 'system', content: systemMessage });
    }
    messages.push({ role: 'user', content: finalUserMessage });

    const result = await openAI.getChatCompletions(deployment, messages, {
      temperature,
      maxTokens
    });

    const output = result.choices[0]?.message?.content || '';
    const usage = result.usage || {};

    context.log(`OpenAI response received. Tokens: ${usage.totalTokens || 0}`);

    // Store the run in PromptRuns table
    const runId = generateId();

    const runEntity = {
      partitionKey: 'PROMPT_RUN',
      rowKey: runId,
      promptId: id,
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

    // Store run (using different table)
    try {
      await runsTableClient.createEntity(runEntity);
      context.log(`Prompt run stored: ${runId}`);
    } catch (storeError) {
      context.warn(`Failed to store run history:`, storeError);
      // Don't fail the request if history storage fails
    }

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

console.log('[PromptsAPI-REST] Module loaded successfully (using @azure/data-tables SDK)');
