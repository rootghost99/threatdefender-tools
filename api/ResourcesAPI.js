// Resources API - Handles CRUD operations for cybersecurity tools/links
const { app } = require('@azure/functions');
const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');

console.log('[ResourcesAPI] Module loading...');

// Lazy-load Table Client
let tableClient = null;

function getTableClient() {
  if (!tableClient) {
    const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const tableName = process.env.RESOURCES_TABLE_NAME || 'Resources';

    if (!account || !accountKey) {
      throw new Error('Azure Storage credentials not configured');
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

// Helper functions
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
  return 'anonymous';
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// UNIFIED HANDLER - Handles all /api/resources/* routes
app.http('ResourcesAPI', {
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'resources/{id?}',
  handler: async (request, context) => {
    context.log('[ResourcesAPI] Request:', request.method, request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const method = request.method;
      const id = request.params.id;

      context.log('Method:', method, 'ID:', id);

      // Route to appropriate handler
      if (!id) {
        // /api/resources
        if (method === 'GET') {
          return await listResources(request, context);
        } else if (method === 'POST') {
          return await createResource(request, context);
        }
      } else {
        // /api/resources/{id}
        if (method === 'GET') {
          return await getResource(request, context, id);
        } else if (method === 'PUT') {
          return await updateResource(request, context, id);
        } else if (method === 'DELETE') {
          return await deleteResource(request, context, id);
        }
      }

      // Method not allowed
      return {
        status: 405,
        headers: corsHeaders,
        jsonBody: { error: 'Method not allowed' }
      };
    } catch (error) {
      context.error('[ResourcesAPI] Error:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: 'An internal error occurred. Please try again later.' }
      };
    }
  }
});

// LIST resources (GET /api/resources)
async function listResources(request, context) {
  context.log('[ResourcesAPI] LIST resources');

  try {
    const client = getTableClient();
    const url = new URL(request.url);
    const search = url.searchParams.get('search');

    context.log('Query params:', { search });

    const resources = [];
    const entities = client.listEntities();

    for await (const entity of entities) {
      // Skip deleted resources
      if (entity.isDeleted === true) continue;

      const resource = {
        id: entity.rowKey,
        siteName: entity.siteName || '',
        url: entity.url || '',
        notes: entity.notes || '',
        createdBy: entity.createdBy || 'anonymous',
        createdAt: entity.createdAt || new Date().toISOString(),
        lastUpdatedBy: entity.lastUpdatedBy || entity.createdBy || 'anonymous',
        updatedAt: entity.updatedAt || entity.createdAt || new Date().toISOString()
      };

      // Filter by search term if provided
      if (search) {
        const s = search.toLowerCase();
        const matches =
          (resource.siteName && resource.siteName.toLowerCase().includes(s)) ||
          (resource.url && resource.url.toLowerCase().includes(s)) ||
          (resource.notes && resource.notes.toLowerCase().includes(s));
        if (!matches) continue;
      }

      resources.push(resource);
    }

    // Sort by site name alphabetically
    resources.sort((a, b) => (a.siteName || '').localeCompare(b.siteName || ''));

    context.log(`Returning ${resources.length} resources`);

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: { resources, count: resources.length }
    };
  } catch (error) {
    context.error('Error listing resources:', error);
    return {
      status: 500,
      headers: corsHeaders,
      jsonBody: { error: error.message }
    };
  }
}

// GET single resource (GET /api/resources/{id})
async function getResource(request, context, id) {
  context.log('[ResourcesAPI] GET resource:', id);

  try {
    const client = getTableClient();
    const entity = await client.getEntity('RESOURCE', id);

    if (entity.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Resource not found' }
      };
    }

    const resource = {
      id: entity.rowKey,
      siteName: entity.siteName || '',
      url: entity.url || '',
      notes: entity.notes || '',
      createdBy: entity.createdBy || 'anonymous',
      createdAt: entity.createdAt || new Date().toISOString(),
      lastUpdatedBy: entity.lastUpdatedBy || entity.createdBy || 'anonymous',
      updatedAt: entity.updatedAt || entity.createdAt || new Date().toISOString()
    };

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: resource
    };
  } catch (error) {
    context.error('Error getting resource:', error);
    if (error.statusCode === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Resource not found' }
      };
    }
    return {
      status: 500,
      headers: corsHeaders,
      jsonBody: { error: error.message }
    };
  }
}

// CREATE resource (POST /api/resources)
async function createResource(request, context) {
  context.log('[ResourcesAPI] CREATE resource');

  try {
    const body = await request.json();
    const user = getUserFromRequest(request);
    const now = new Date().toISOString();
    const id = generateId();

    // Validate required fields
    if (!body.siteName || !body.url) {
      return {
        status: 400,
        headers: corsHeaders,
        jsonBody: { error: 'Site name and URL are required' }
      };
    }

    const entity = {
      partitionKey: 'RESOURCE',
      rowKey: id,
      siteName: body.siteName,
      url: body.url,
      notes: body.notes || '',
      createdBy: user,
      createdAt: now,
      lastUpdatedBy: user,
      updatedAt: now,
      isDeleted: false
    };

    const client = getTableClient();
    await client.createEntity(entity);

    context.log(`Resource created: ${id}`);

    const resource = {
      id,
      siteName: entity.siteName,
      url: entity.url,
      notes: entity.notes,
      createdBy: entity.createdBy,
      createdAt: entity.createdAt,
      lastUpdatedBy: entity.lastUpdatedBy,
      updatedAt: entity.updatedAt
    };

    return {
      status: 201,
      headers: corsHeaders,
      jsonBody: { message: 'Resource created', resource }
    };
  } catch (error) {
    context.error('Error creating resource:', error);
    return {
      status: 500,
      headers: corsHeaders,
      jsonBody: { error: error.message }
    };
  }
}

// UPDATE resource (PUT /api/resources/{id})
async function updateResource(request, context, id) {
  context.log('[ResourcesAPI] UPDATE resource:', id);

  try {
    const body = await request.json();
    const user = getUserFromRequest(request);
    const now = new Date().toISOString();

    const client = getTableClient();
    const existing = await client.getEntity('RESOURCE', id);

    if (existing.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Resource not found' }
      };
    }

    const updated = {
      ...existing,
      siteName: body.siteName !== undefined ? body.siteName : existing.siteName,
      url: body.url !== undefined ? body.url : existing.url,
      notes: body.notes !== undefined ? body.notes : existing.notes,
      lastUpdatedBy: user,
      updatedAt: now
    };

    await client.updateEntity(updated, 'Replace');

    context.log(`Resource updated: ${id}`);

    const resource = {
      id,
      siteName: updated.siteName,
      url: updated.url,
      notes: updated.notes,
      createdBy: updated.createdBy,
      createdAt: updated.createdAt,
      lastUpdatedBy: updated.lastUpdatedBy,
      updatedAt: updated.updatedAt
    };

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: { message: 'Resource updated', resource }
    };
  } catch (error) {
    context.error('Error updating resource:', error);
    if (error.statusCode === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Resource not found' }
      };
    }
    return {
      status: 500,
      headers: corsHeaders,
      jsonBody: { error: error.message }
    };
  }
}

// DELETE resource (DELETE /api/resources/{id})
async function deleteResource(request, context, id) {
  context.log('[ResourcesAPI] DELETE resource:', id);

  try {
    const user = getUserFromRequest(request);
    const now = new Date().toISOString();

    const client = getTableClient();
    const existing = await client.getEntity('RESOURCE', id);

    if (existing.isDeleted) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Resource not found' }
      };
    }

    const updated = {
      ...existing,
      isDeleted: true,
      lastUpdatedBy: user,
      updatedAt: now
    };

    await client.updateEntity(updated, 'Replace');

    context.log(`Resource deleted: ${id}`);

    return {
      status: 200,
      headers: corsHeaders,
      jsonBody: { message: 'Resource deleted successfully' }
    };
  } catch (error) {
    context.error('Error deleting resource:', error);
    if (error.statusCode === 404) {
      return {
        status: 404,
        headers: corsHeaders,
        jsonBody: { error: 'Resource not found' }
      };
    }
    return {
      status: 500,
      headers: corsHeaders,
      jsonBody: { error: error.message }
    };
  }
}

console.log('[ResourcesAPI] Module loaded successfully');
