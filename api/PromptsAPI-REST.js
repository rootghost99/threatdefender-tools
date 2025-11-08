// PromptsAPI using direct Azure Table Storage REST API (bypasses SDK crypto issues)
const { app } = require('@azure/functions');
const axios = require('axios');
const crypto = require('crypto');
const { OpenAIClient, AzureKeyCredential } = require('@azure/openai');

console.log('[PromptsAPI-REST] Module loading...');

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// OpenAI client (lazy initialization)
let openAIClient = null;

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

// Generate Account SAS token for Azure Storage
// Account SAS works across all services (Blob, Queue, Table, File)
function generateTableSAS(accountName, accountKey, tableName) {
  const version = '2019-02-02';
  const now = new Date();

  // Format: yyyy-MM-ddTHH:mm:ssZ
  const start = new Date(now.getTime() - 5 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const expiry = new Date(now.getTime() + 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

  // Account SAS string-to-sign format:
  // accountname + "\n" +
  // signedpermissions + "\n" +
  // signedservice + "\n" +
  // signedresourcetype + "\n" +
  // signedstart + "\n" +
  // signedexpiry + "\n" +
  // signedIP + "\n" +
  // signedProtocol + "\n" +
  // signedversion + "\n" +
  // (no signature field in string-to-sign)
  const stringToSign = [
    accountName,
    'raud',     // signedpermissions: read, add, update, delete
    't',        // signedservice: 't' for table service
    'sco',      // signedresourcetype: service, container, object
    start,      // signedstart
    expiry,     // signedexpiry
    '',         // signedIP
    '',         // signedProtocol
    version,    // signedversion
    ''          // extra newline at the end
  ].join('\n');

  const signature = crypto
    .createHmac('sha256', Buffer.from(accountKey, 'base64'))
    .update(stringToSign, 'utf-8')
    .digest('base64');

  const sasParams = new URLSearchParams({
    sv: version,        // signed version
    ss: 't',            // signed services (table)
    srt: 'sco',         // signed resource types (service, container, object)
    sp: 'raud',         // signed permissions
    st: start,          // signed start time
    se: expiry,         // signed expiry time
    sig: signature      // signature
  });

  return sasParams.toString();
}

// Make REST API call using SAS token authentication
async function callTableAPI(method, path, body = null, context) {
  const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

  if (!account || !accountKey) {
    throw new Error('Azure Storage credentials not configured');
  }

  // Generate SAS token
  const sasToken = generateTableSAS(account, accountKey, tableName);

  // Add SAS token to URL
  const separator = path.includes('?') ? '&' : '?';
  const url = `https://${account}.table.core.windows.net${path}${separator}${sasToken}`;

  // When using SAS tokens, don't include x-ms-date or x-ms-version headers
  // These are only for SharedKey authentication
  const headers = {
    'Accept': 'application/json;odata=nometadata',
    'DataServiceVersion': '3.0'
  };

  if (body) {
    const bodyStr = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(bodyStr).toString();
  }

  context.log(`[REST-SAS] ${method} ${path}`);
  context.log(`[REST-SAS] Full URL: ${url.substring(0, 100)}...`);
  context.log(`[REST-SAS] Headers:`, JSON.stringify(headers));

  try {
    const response = await axios({
      method,
      url,
      headers,
      data: body,
      validateStatus: () => true
    });

    context.log(`[REST-SAS] Response status: ${response.status}`);
    if (response.status !== 200 && response.status !== 201 && response.status !== 204) {
      context.log(`[REST-SAS] Error response:`, JSON.stringify(response.data));
    }

    return response;
  } catch (error) {
    context.error(`[REST-SAS] ${method} ${path} failed:`, error.message);
    throw error;
  }
}

// Generate unique ID
function generateId() {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substr(2, 9);
  return `${timestamp}-${random}`;
}

// Get user from request
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
  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
  const response = await callTableAPI('GET', `/${tableName}()`, null, context);

  if (response.status !== 200) {
    throw new Error(`Query failed: ${response.status}`);
  }

  const entities = response.data.value || [];
  const prompts = [];

  for (const entity of entities) {
    if (entity.isDeleted === true) continue;

    let tags = [];
    let variables = [];
    let modelSettings = {};

    try { tags = entity.tags ? JSON.parse(entity.tags) : []; } catch (e) {}
    try { variables = entity.variables ? JSON.parse(entity.variables) : []; } catch (e) {}
    try { modelSettings = entity.modelSettings ? JSON.parse(entity.modelSettings) : {}; } catch (e) {}

    prompts.push({
      id: entity.RowKey,
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
}

// GET single prompt
async function getPrompt(request, context, id) {
  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
  const response = await callTableAPI('GET', `/${tableName}(PartitionKey='PROMPT',RowKey='${id}')`, null, context);

  if (response.status === 404) {
    return {
      status: 404,
      headers: corsHeaders,
      jsonBody: { error: 'Prompt not found' }
    };
  }

  if (response.status !== 200) {
    throw new Error(`Get failed: ${response.status}`);
  }

  const entity = response.data;

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
    id: entity.RowKey,
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
}

// CREATE prompt
async function createPrompt(request, context) {
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
    PartitionKey: 'PROMPT',
    RowKey: id,
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

  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
  const response = await callTableAPI('POST', `/${tableName}`, entity, context);

  if (response.status !== 201 && response.status !== 204) {
    throw new Error(`Create failed: ${response.status}`);
  }

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
}

// UPDATE prompt
async function updatePrompt(request, context, id) {
  const body = await request.json();
  const user = getUserFromRequest(request);
  const now = new Date().toISOString();

  // First get existing
  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
  const getResp = await callTableAPI('GET', `/${tableName}(PartitionKey='PROMPT',RowKey='${id}')`, null, context);

  if (getResp.status === 404) {
    return {
      status: 404,
      headers: corsHeaders,
      jsonBody: { error: 'Prompt not found' }
    };
  }

  const existing = getResp.data;

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

  const putResp = await callTableAPI('PUT', `/${tableName}(PartitionKey='PROMPT',RowKey='${id}')`, updated, context);

  if (putResp.status !== 204) {
    throw new Error(`Update failed: ${putResp.status}`);
  }

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
}

// DELETE prompt (soft delete)
async function deletePrompt(request, context, id) {
  const user = getUserFromRequest(request);
  const now = new Date().toISOString();

  const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
  const getResp = await callTableAPI('GET', `/${tableName}(PartitionKey='PROMPT',RowKey='${id}')`, null, context);

  if (getResp.status === 404) {
    return {
      status: 404,
      headers: corsHeaders,
      jsonBody: { error: 'Prompt not found' }
    };
  }

  const existing = getResp.data;

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

  const putResp = await callTableAPI('PUT', `/${tableName}(PartitionKey='PROMPT',RowKey='${id}')`, updated, context);

  if (putResp.status !== 204) {
    throw new Error(`Delete failed: ${putResp.status}`);
  }

  return {
    status: 200,
    headers: corsHeaders,
    jsonBody: { message: 'Prompt deleted successfully' }
  };
}

// RUN prompt (POST /api/prompts/{id}/run)
async function runPrompt(request, context, id) {
  context.log('[PromptsAPI-REST] RUN prompt:', id);

  try {
    const body = await request.json();
    const user = getUserFromRequest(request);
    const now = new Date().toISOString();

    context.log(`Running prompt: ${id} by ${user}`);

    // Get prompt from storage
    const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';
    const getResp = await callTableAPI('GET', `/${tableName}(PartitionKey='PROMPT',RowKey='${id}')`, null, context);

    if (getResp.status === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }

    if (getResp.status !== 200) {
      throw new Error(`Failed to fetch prompt: ${getResp.status}`);
    }

    const promptEntity = getResp.data;

    if (promptEntity.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Prompt not found' }
      };
    }

    const prompt = {
      id: promptEntity.RowKey,
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
    const runsTableName = process.env.PROMPT_RUNS_TABLE_NAME || 'PromptRuns';

    const runEntity = {
      PartitionKey: 'PROMPT_RUN',
      RowKey: runId,
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
    const storeResp = await callTableAPI('POST', `/${runsTableName}`, runEntity, context);

    if (storeResp.status !== 201 && storeResp.status !== 204) {
      context.warn(`Failed to store run history: ${storeResp.status}`);
      // Don't fail the request if history storage fails
    } else {
      context.log(`Prompt run stored: ${runId}`);
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

    if (error.response?.status === 404) {
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

console.log('[PromptsAPI-REST] Module loaded successfully (using SAS token authentication)');
