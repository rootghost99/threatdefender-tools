// PromptsAPI using direct Azure Table Storage REST API (bypasses SDK crypto issues)
const { app } = require('@azure/functions');
const axios = require('axios');
const crypto = require('crypto');

console.log('[PromptsAPI-REST] Module loading...');

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// Helper to generate SharedKey authentication for Azure Table Storage
// Uses SharedKey (not SharedKeyLite) with canonicalized headers
function getStorageAuth(method, url, headers, accountName, accountKey) {
  const urlObj = new URL(url);

  // Canonicalized resource: /{account}{path}
  const canonicalResource = `/${accountName}${urlObj.pathname}`;

  // Canonicalized headers: all x-ms-* headers, sorted, lowercase, with newlines
  const canonicalHeaders = Object.keys(headers)
    .filter(k => k.toLowerCase().startsWith('x-ms-'))
    .map(k => k.toLowerCase())
    .sort()
    .map(k => {
      const originalKey = Object.keys(headers).find(h => h.toLowerCase() === k);
      return `${k}:${headers[originalKey]}`;
    })
    .join('\n');

  // String to sign for SharedKey:
  // VERB + "\n" + Content-MD5 + "\n" + Content-Type + "\n" + Date + "\n" + CanonicalizedHeaders + "\n" + CanonicalizedResource
  // NOTE: If x-ms-date is present, Date should be empty string
  const stringToSign = [
    method,
    headers['Content-MD5'] || '',
    headers['Content-Type'] || '',
    headers['x-ms-date'] ? '' : (headers['Date'] || ''), // Empty if x-ms-date present
    canonicalHeaders,
    canonicalResource
  ].join('\n');

  const signature = crypto
    .createHmac('sha256', Buffer.from(accountKey, 'base64'))
    .update(stringToSign, 'utf-8')
    .digest('base64');

  return `SharedKey ${accountName}:${signature}`;
}

// Make REST API call to Azure Table Storage
async function callTableAPI(method, path, body = null, context) {
  const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;

  if (!account || !accountKey) {
    throw new Error('Azure Storage credentials not configured');
  }

  const url = `https://${account}.table.core.windows.net${path}`;
  const dateStr = new Date().toUTCString();

  const headers = {
    'x-ms-date': dateStr,
    'x-ms-version': '2019-02-02',
    'Accept': 'application/json;odata=nometadata',
    'DataServiceVersion': '3.0;NetFx'
  };

  if (body) {
    const bodyStr = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(bodyStr).toString();
  }

  headers['Authorization'] = getStorageAuth(method, url, headers, account, accountKey);

  context.log(`[REST] ${method} ${path}`);

  try {
    const response = await axios({
      method,
      url,
      headers,
      data: body,
      validateStatus: () => true
    });

    return response;
  } catch (error) {
    context.error(`[REST] ${method} ${path} failed:`, error.message);
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

console.log('[PromptsAPI-REST] Module loaded successfully (using REST API, no SDK)');
