// Shared Cosmos DB client for session storage
const { CosmosClient } = require('@azure/cosmos');

let client = null;
let container = null;

const DATABASE_ID = 'TriageDB';
const CONTAINER_ID = 'Sessions';

/**
 * Initialize or return cached Cosmos DB container
 * Uses connection string from environment (Key Vault reference in production)
 */
async function getContainer() {
  if (container) {
    return container;
  }

  const connectionString = process.env.COSMOS_CONNECTION;
  if (!connectionString) {
    throw new Error('COSMOS_CONNECTION environment variable not configured');
  }

  client = new CosmosClient(connectionString);

  // Get or create database
  const { database } = await client.databases.createIfNotExists({
    id: DATABASE_ID
  });

  // Get or create container with partition key
  const { container: cosmosContainer } = await database.containers.createIfNotExists({
    id: CONTAINER_ID,
    partitionKey: { paths: ['/incidentId'] },
    defaultTtl: 604800 // 7 days TTL
  });

  container = cosmosContainer;
  return container;
}

/**
 * Get a session by ID
 * @param {string} sessionId - The session GUID
 * @param {string} incidentId - The incident ID (partition key)
 * @returns {Object|null} Session document or null if not found
 */
async function getSession(sessionId, incidentId) {
  const cosmosContainer = await getContainer();

  try {
    const { resource } = await cosmosContainer.item(sessionId, incidentId).read();
    return resource;
  } catch (error) {
    if (error.code === 404) {
      return null;
    }
    throw error;
  }
}

/**
 * Get a session by ID without knowing the partition key
 * Uses a cross-partition query (less efficient but necessary for GET by sessionId only)
 * @param {string} sessionId - The session GUID
 * @returns {Object|null} Session document or null if not found
 */
async function getSessionById(sessionId) {
  const cosmosContainer = await getContainer();

  const querySpec = {
    query: 'SELECT * FROM c WHERE c.id = @sessionId',
    parameters: [{ name: '@sessionId', value: sessionId }]
  };

  const { resources } = await cosmosContainer.items.query(querySpec).fetchAll();
  return resources.length > 0 ? resources[0] : null;
}

/**
 * Create or update a session
 * @param {Object} session - The session document
 * @returns {Object} The created/updated session
 */
async function upsertSession(session) {
  const cosmosContainer = await getContainer();

  const { resource } = await cosmosContainer.items.upsert(session);
  return resource;
}

/**
 * List sessions for an incident
 * @param {string} incidentId - The incident ID
 * @param {number} limit - Maximum number of sessions to return
 * @returns {Array} Array of session documents
 */
async function listSessionsByIncident(incidentId, limit = 10) {
  const cosmosContainer = await getContainer();

  const querySpec = {
    query: 'SELECT * FROM c WHERE c.incidentId = @incidentId ORDER BY c.createdAt DESC OFFSET 0 LIMIT @limit',
    parameters: [
      { name: '@incidentId', value: incidentId },
      { name: '@limit', value: limit }
    ]
  };

  const { resources } = await cosmosContainer.items.query(querySpec).fetchAll();
  return resources;
}

module.exports = {
  getContainer,
  getSession,
  getSessionById,
  upsertSession,
  listSessionsByIncident
};
