// /api/ConnectWise.js
// Azure Functions (v4, Node 18+) - ConnectWise Manage Integration API
// Provides endpoints for ticket management, time entries, and internal notes

const { app } = require('@azure/functions');

// ConnectWise API configuration
const CW_API_URL = process.env.CW_API_URL || 'https://na.myconnectwise.net/v4_6_release/apis/3.0';
const CW_COMPANY_ID = process.env.CW_COMPANY_ID;
const CW_PUBLIC_KEY = process.env.CW_PUBLIC_KEY;
const CW_PRIVATE_KEY = process.env.CW_PRIVATE_KEY;
const CW_CLIENT_ID = process.env.CW_CLIENT_ID;

// CORS headers
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

// Generate ConnectWise Basic Auth header
function getCWAuthHeader() {
  if (!CW_COMPANY_ID || !CW_PUBLIC_KEY || !CW_PRIVATE_KEY) {
    throw new Error('ConnectWise credentials not configured. Set CW_COMPANY_ID, CW_PUBLIC_KEY, and CW_PRIVATE_KEY environment variables.');
  }

  const credentials = `${CW_COMPANY_ID}+${CW_PUBLIC_KEY}:${CW_PRIVATE_KEY}`;
  const encoded = Buffer.from(credentials).toString('base64');
  return `Basic ${encoded}`;
}

// Make ConnectWise API request
async function cwRequest(method, endpoint, body = null) {
  if (!CW_CLIENT_ID) {
    throw new Error('CW_CLIENT_ID environment variable not configured');
  }

  const url = `${CW_API_URL}${endpoint}`;

  const headers = {
    'Authorization': getCWAuthHeader(),
    'clientId': CW_CLIENT_ID,
    'Content-Type': 'application/json'
  };

  const options = {
    method,
    headers
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  const responseText = await response.text();

  if (!response.ok) {
    const errorMsg = responseText || `HTTP ${response.status}`;
    throw new Error(`ConnectWise API error: ${errorMsg}`);
  }

  return responseText ? JSON.parse(responseText) : null;
}

// GET /api/ConnectWise/ticket?ticketId=xxx - Get ticket details
async function getTicket(ticketId, context) {
  context.log(`Getting ticket: ${ticketId}`);

  const ticket = await cwRequest('GET', `/service/tickets/${ticketId}`);

  return {
    id: ticket.id,
    summary: ticket.summary,
    status: ticket.status,
    type: ticket.type,
    priority: ticket.priority,
    company: ticket.company,
    contact: ticket.contact,
    board: ticket.board,
    dateEntered: ticket.dateEntered,
    lastUpdated: ticket.lastUpdated
  };
}

// POST /api/ConnectWise/note - Add internal note to ticket
async function addNote(ticketId, noteText, isInternal = true, context) {
  context.log(`Adding ${isInternal ? 'internal' : 'external'} note to ticket: ${ticketId}`);

  const noteBody = {
    text: noteText,
    internalAnalysisFlag: isInternal,
    detailDescriptionFlag: !isInternal
  };

  const result = await cwRequest('POST', `/service/tickets/${ticketId}/notes`, noteBody);

  return {
    id: result.id,
    ticketId: result.ticketId,
    text: result.text,
    internalAnalysisFlag: result.internalAnalysisFlag,
    dateCreated: result.dateCreated,
    createdBy: result.createdBy
  };
}

// POST /api/ConnectWise/time - Add time entry to ticket
async function addTimeEntry(ticketId, minutes, notes, memberId, context) {
  context.log(`Adding ${minutes} minutes to ticket: ${ticketId}`);

  // Calculate time start/end based on minutes
  const now = new Date();
  const timeEnd = now.toISOString();
  const timeStart = new Date(now.getTime() - (minutes * 60 * 1000)).toISOString();

  const timeBody = {
    chargeToId: parseInt(ticketId, 10),
    chargeToType: 'ServiceTicket',
    timeStart: timeStart,
    timeEnd: timeEnd,
    notes: notes || `Time logged via ThreatDefender triage (${minutes} min)`,
    addToDetailDescriptionFlag: false,
    addToInternalAnalysisFlag: true
  };

  // Add member if provided
  if (memberId) {
    timeBody.member = { identifier: memberId };
  }

  const result = await cwRequest('POST', '/time/entries', timeBody);

  return {
    id: result.id,
    ticketId: ticketId,
    actualHours: result.actualHours,
    timeStart: result.timeStart,
    timeEnd: result.timeEnd,
    notes: result.notes,
    member: result.member
  };
}

// PATCH /api/ConnectWise/ticket - Update ticket status/type
async function updateTicket(ticketId, updates, context) {
  context.log(`Updating ticket: ${ticketId}`, updates);

  // Build patch operations array
  const patchOps = [];

  if (updates.status) {
    patchOps.push({
      op: 'replace',
      path: 'status',
      value: { name: updates.status }
    });
  }

  if (updates.type) {
    patchOps.push({
      op: 'replace',
      path: 'type',
      value: { name: updates.type }
    });
  }

  if (patchOps.length === 0) {
    throw new Error('No valid updates provided. Specify status or type.');
  }

  const result = await cwRequest('PATCH', `/service/tickets/${ticketId}`, patchOps);

  return {
    id: result.id,
    summary: result.summary,
    status: result.status,
    type: result.type,
    lastUpdated: result.lastUpdated
  };
}

// Main handler for ConnectWise operations
app.http('ConnectWise', {
  methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'ConnectWise/{action?}',
  handler: async (request, context) => {
    const action = request.params.action?.toLowerCase();
    context.log(`ConnectWise: ${request.method} /${action || ''}`);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: CORS_HEADERS };
    }

    try {
      // Parse query params
      const url = new URL(request.url);
      const ticketId = url.searchParams.get('ticketId');

      // GET /api/ConnectWise/ticket?ticketId=xxx
      if (request.method === 'GET' && action === 'ticket') {
        if (!ticketId) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'ticketId query parameter is required' }
          };
        }

        const ticket = await getTicket(ticketId, context);
        return {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { ticket }
        };
      }

      // POST /api/ConnectWise/note
      if (request.method === 'POST' && action === 'note') {
        const body = await request.json().catch(() => ({}));
        const { ticketId: bodyTicketId, text, internal = true } = body;

        const targetTicketId = bodyTicketId || ticketId;
        if (!targetTicketId) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'ticketId is required' }
          };
        }

        if (!text || !text.trim()) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'Note text is required' }
          };
        }

        const note = await addNote(targetTicketId, text.trim(), internal, context);
        return {
          status: 201,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { success: true, note }
        };
      }

      // POST /api/ConnectWise/time
      if (request.method === 'POST' && action === 'time') {
        const body = await request.json().catch(() => ({}));
        const { ticketId: bodyTicketId, minutes, notes, memberId } = body;

        const targetTicketId = bodyTicketId || ticketId;
        if (!targetTicketId) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'ticketId is required' }
          };
        }

        if (!minutes || typeof minutes !== 'number' || minutes <= 0) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'Valid minutes value is required (positive number)' }
          };
        }

        const timeEntry = await addTimeEntry(targetTicketId, minutes, notes, memberId, context);
        return {
          status: 201,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { success: true, timeEntry }
        };
      }

      // PATCH /api/ConnectWise/ticket
      if (request.method === 'PATCH' && action === 'ticket') {
        const body = await request.json().catch(() => ({}));
        const { ticketId: bodyTicketId, status, type } = body;

        const targetTicketId = bodyTicketId || ticketId;
        if (!targetTicketId) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'ticketId is required' }
          };
        }

        if (!status && !type) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'At least one of status or type is required' }
          };
        }

        const ticket = await updateTicket(targetTicketId, { status, type }, context);
        return {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { success: true, ticket }
        };
      }

      // POST /api/ConnectWise/classify - Convenience endpoint: update type + status + add note
      if (request.method === 'POST' && action === 'classify') {
        const body = await request.json().catch(() => ({}));
        const { ticketId: bodyTicketId, status, type, notes } = body;

        const targetTicketId = bodyTicketId || ticketId;
        if (!targetTicketId) {
          return {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
            jsonBody: { error: 'ticketId is required' }
          };
        }

        const results = { ticketId: targetTicketId };

        // Update ticket if status or type provided
        if (status || type) {
          results.ticket = await updateTicket(targetTicketId, { status, type }, context);
        }

        // Add note if provided
        if (notes && notes.trim()) {
          results.note = await addNote(targetTicketId, notes.trim(), true, context);
        }

        return {
          status: 200,
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
          jsonBody: { success: true, ...results }
        };
      }

      // Unknown action
      return {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: {
          error: 'Invalid action',
          validActions: ['ticket (GET)', 'note (POST)', 'time (POST)', 'ticket (PATCH)', 'classify (POST)']
        }
      };

    } catch (error) {
      context.error('ConnectWise error:', error.message);
      return {
        status: 500,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: `ConnectWise operation failed: ${error.message}` }
      };
    }
  }
});
