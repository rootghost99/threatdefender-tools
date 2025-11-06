// /api/PromptsAPI.js
const { app } = require('@azure/functions');
const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');

console.log('========================================');
console.log('[PromptsAPI] Module loading started');
console.log('[PromptsAPI] @azure/functions version:', require('@azure/functions/package.json').version);
console.log('========================================');

// Initialize Table Client
let tableClient = null;

function getTableClient() {
  if (!tableClient) {
    const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

    if (!account || !accountKey) {
      throw new Error('Azure Storage credentials not configured. Set AZURE_STORAGE_ACCOUNT_NAME and AZURE_STORAGE_ACCOUNT_KEY.');
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

// Helper to generate unique ID
function generateId() {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Helper to get user from Static Web Apps auth
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

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// GET /api/prompts - List all prompts
app.http('PromptsAPI-List', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts',
  handler: async (request, context) => {
    context.log('========================================');
    context.log('[PromptsAPI-List] HANDLER CALLED');
    context.log('[PromptsAPI-List] Method:', request.method);
    context.log('[PromptsAPI-List] URL:', request.url);
    context.log('========================================');

    if (request.method === 'OPTIONS') {
      context.log('[PromptsAPI-List] Responding to OPTIONS request');
      return { status: 200, headers: corsHeaders };
    }

    try {
      context.log('[PromptsAPI-List] Listing prompts - START');
      const client = getTableClient();

      // Query parameters for filtering
      const url = new URL(request.url);
      const category = url.searchParams.get('category');
      const tag = url.searchParams.get('tag');
      const search = url.searchParams.get('search');

      context.log('Query params:', { category, tag, search });

      // REMOVED PARTITION KEY FILTER - Get all entities and filter in code
      // This ensures we get all prompts regardless of how they were created
      const prompts = [];
      const entities = client.listEntities();

      let entityCount = 0;
      let deletedCount = 0;

      for await (const entity of entities) {
        entityCount++;
        context.log(`Processing entity ${entityCount}: ${entity.rowKey}`);

        // Skip deleted prompts (but include those without isDeleted field)
        if (entity.isDeleted === true) {
          deletedCount++;
          context.log(`  Skipping deleted prompt: ${entity.rowKey}`);
          continue;
        }

        // Parse JSON fields with error handling
        let tags = [];
        let variables = [];
        let modelSettings = {};

        try {
          tags = entity.tags ? JSON.parse(entity.tags) : [];
        } catch (e) {
          context.warn(`Failed to parse tags for prompt ${entity.rowKey}: ${e.message}`);
          tags = [];
        }

        try {
          variables = entity.variables ? JSON.parse(entity.variables) : [];
        } catch (e) {
          context.warn(`Failed to parse variables for prompt ${entity.rowKey}: ${e.message}`);
          variables = [];
        }

        try {
          modelSettings = entity.modelSettings ? JSON.parse(entity.modelSettings) : {};
        } catch (e) {
          context.warn(`Failed to parse modelSettings for prompt ${entity.rowKey}: ${e.message}`);
          modelSettings = {};
        }

        const prompt = {
          id: entity.rowKey,
          title: entity.title || '',
          description: entity.description || '',
          category: entity.category || 'General',
          tags: tags,
          collection: entity.collection || '',
          variables: variables,
          systemGuidance: entity.systemGuidance || '',
          userInstructions: entity.userInstructions || '',
          modelSettings: modelSettings,
          status: entity.status || 'active',
          createdBy: entity.createdBy || 'system',
          createdAt: entity.createdAt || new Date().toISOString(),
          updatedBy: entity.updatedBy || '',
          updatedAt: entity.updatedAt || ''
        };

        // Client-side filtering for tag and search
        if (tag && prompt.tags && !prompt.tags.includes(tag)) continue;
        if (search) {
          const s = search.toLowerCase();
          const matches =
            (prompt.title && prompt.title.toLowerCase().includes(s)) ||
            (prompt.description && prompt.description.toLowerCase().includes(s)) ||
            (prompt.tags && prompt.tags.some(t => t && t.toLowerCase().includes(s)));
          if (!matches) continue;
        }

        prompts.push(prompt);
        context.log(`  Added prompt: ${prompt.title}`);
      }

      context.log(`Processed ${entityCount} total entities, ${deletedCount} deleted, ${prompts.length} active`);

      // Sort by creation date (newest first)
      try {
        prompts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      } catch (e) {
        context.warn(`Failed to sort prompts: ${e.message}`);
      }

      context.log(`Returning ${prompts.length} prompts`);

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: { prompts, count: prompts.length }
      };
    } catch (error) {
      context.error('Error listing prompts:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message }
      };
    }
  }
});

// GET /api/prompts/{id} - Get single prompt
app.http('PromptsAPI-Get', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/{id}',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const id = request.params.id;
      context.log(`Getting prompt: ${id}`);

      const client = getTableClient();
      const entity = await client.getEntity('PROMPT', id);

      if (entity.isDeleted) {
        return {
          status: 404,
          headers: corsHeaders,
          jsonBody: { error: 'Prompt not found' }
        };
      }

      // Parse JSON fields with error handling
      let tags = [];
      let variables = [];
      let modelSettings = {};

      try {
        tags = entity.tags ? JSON.parse(entity.tags) : [];
      } catch (e) {
        context.warn(`Failed to parse tags for prompt ${id}: ${e.message}`);
      }

      try {
        variables = entity.variables ? JSON.parse(entity.variables) : [];
      } catch (e) {
        context.warn(`Failed to parse variables for prompt ${id}: ${e.message}`);
      }

      try {
        modelSettings = entity.modelSettings ? JSON.parse(entity.modelSettings) : {};
      } catch (e) {
        context.warn(`Failed to parse modelSettings for prompt ${id}: ${e.message}`);
      }

      const prompt = {
        id: entity.rowKey,
        title: entity.title || '',
        description: entity.description || '',
        category: entity.category || 'General',
        tags: tags,
        collection: entity.collection || '',
        variables: variables,
        systemGuidance: entity.systemGuidance || '',
        userInstructions: entity.userInstructions || '',
        modelSettings: modelSettings,
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
      context.error('Error getting prompt:', error);
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

// POST /api/prompts - Create new prompt
app.http('PromptsAPI-Create', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const body = await request.json();
      const user = getUserFromRequest(request);
      const now = new Date().toISOString();
      const id = generateId();

      context.log(`Creating prompt: ${body.title} by ${user}`);

      // Validate required fields
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

      const client = getTableClient();
      await client.createEntity(entity);

      context.log(`Prompt created successfully: ${id}`);

      // Return created prompt
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
      context.error('Error creating prompt:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: { error: error.message }
      };
    }
  }
});

// PUT /api/prompts/{id} - Update prompt
app.http('PromptsAPI-Update', {
  methods: ['PUT', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/{id}',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const id = request.params.id;
      const body = await request.json();
      const user = getUserFromRequest(request);
      const now = new Date().toISOString();

      context.log(`Updating prompt: ${id} by ${user}`);

      const client = getTableClient();

      // Get existing entity
      const existing = await client.getEntity('PROMPT', id);

      if (existing.isDeleted) {
        return {
          status: 404,
          headers: corsHeaders,
          jsonBody: { error: 'Prompt not found' }
        };
      }

      // Update fields
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

      await client.updateEntity(updated, 'Replace');

      context.log(`Prompt updated successfully: ${id}`);

      // Return updated prompt
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
      context.error('Error updating prompt:', error);
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

// DELETE /api/prompts/{id} - Soft delete prompt
app.http('PromptsAPI-Delete', {
  methods: ['DELETE', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'prompts/{id}',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    try {
      const id = request.params.id;
      const user = getUserFromRequest(request);
      const now = new Date().toISOString();

      context.log(`Deleting prompt: ${id} by ${user}`);

      const client = getTableClient();

      // Get existing entity
      const existing = await client.getEntity('PROMPT', id);

      if (existing.isDeleted) {
        return {
          status: 404,
          headers: corsHeaders,
          jsonBody: { error: 'Prompt not found' }
        };
      }

      // Soft delete
      const updated = {
        ...existing,
        isDeleted: true,
        status: 'deleted',
        updatedBy: user,
        updatedAt: now
      };

      await client.updateEntity(updated, 'Replace');

      context.log(`Prompt deleted successfully: ${id}`);

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: { message: 'Prompt deleted successfully' }
      };
    } catch (error) {
      context.error('Error deleting prompt:', error);
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

console.log('========================================');
console.log('[PromptsAPI] All 5 routes registered:');
console.log('  - GET    /api/prompts         (PromptsAPI-List)');
console.log('  - GET    /api/prompts/{id}    (PromptsAPI-Get)');
console.log('  - POST   /api/prompts         (PromptsAPI-Create)');
console.log('  - PUT    /api/prompts/{id}    (PromptsAPI-Update)');
console.log('  - DELETE /api/prompts/{id}    (PromptsAPI-Delete)');
console.log('[PromptsAPI] Module loaded successfully');
console.log('========================================');
