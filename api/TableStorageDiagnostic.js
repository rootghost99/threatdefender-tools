// Diagnostic endpoint to test Azure Table Storage authentication
const { app } = require('@azure/functions');
const axios = require('axios');
const crypto = require('crypto');

console.log('[TableStorageDiagnostic] Module loading...');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

// Account SAS generation (same as PromptsAPI-REST)
function generateTableSAS(accountName, accountKey, tableName) {
  const version = '2019-02-02';
  const now = new Date();

  const start = new Date(now.getTime() - 5 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const expiry = new Date(now.getTime() + 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

  const stringToSign = [
    accountName,
    'raud',     // signedpermissions
    't',        // signedservice (table)
    'sco',      // signedresourcetype
    start,
    expiry,
    '',         // signedIP
    '',         // signedProtocol
    version,
    ''
  ].join('\n');

  const signature = crypto
    .createHmac('sha256', Buffer.from(accountKey, 'base64'))
    .update(stringToSign, 'utf-8')
    .digest('base64');

  return {
    sasParams: new URLSearchParams({
      sv: version,
      ss: 't',
      srt: 'sco',
      sp: 'raud',
      st: start,
      se: expiry,
      sig: signature
    }).toString(),
    debugInfo: {
      sasType: 'Account SAS',
      version,
      accountName,
      signedService: 't (table)',
      signedResourceType: 'sco (service, container, object)',
      permissions: 'raud',
      start,
      expiry,
      stringToSign: stringToSign.split('\n').map((line, i) => `Line ${i}: "${line}"`),
      signatureGenerated: signature
    }
  };
}

app.http('TableStorageDiagnostic', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'diagnostics/table-storage',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 200, headers: corsHeaders };
    }

    const account = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const tableName = process.env.PROMPTS_TABLE_NAME || 'Prompts';

    if (!account || !accountKey) {
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: {
          error: 'Azure Storage credentials not configured',
          account: account ? 'SET' : 'NOT SET',
          accountKey: accountKey ? `SET (${accountKey.length} chars)` : 'NOT SET'
        }
      };
    }

    try {
      const { sasParams, debugInfo } = generateTableSAS(account, accountKey, tableName);

      const path = `/${tableName}()`;
      const url = `https://${account}.table.core.windows.net${path}?${sasParams}`;

      // When using SAS tokens, don't include x-ms-date or x-ms-version headers
      // These are only for SharedKey authentication
      const headers = {
        'Accept': 'application/json;odata=nometadata',
        'DataServiceVersion': '3.0'
      };

      context.log('Attempting Table Storage request with SAS token...');

      const response = await axios({
        method: 'GET',
        url,
        headers,
        validateStatus: () => true
      });

      return {
        status: 200,
        headers: corsHeaders,
        jsonBody: {
          message: 'Table Storage Connection Test',
          environment: {
            accountName: account,
            accountKeyLength: accountKey.length,
            tableName
          },
          sasTokenDebug: debugInfo,
          requestDetails: {
            method: 'GET',
            url: url.substring(0, 150) + '...',
            headers
          },
          azureResponse: {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
            dataPreview: response.status === 200
              ? `Success! Got ${response.data?.value?.length || 0} entities`
              : JSON.stringify(response.data).substring(0, 500)
          }
        }
      };
    } catch (error) {
      context.error('Table Storage test failed:', error);
      return {
        status: 500,
        headers: corsHeaders,
        jsonBody: {
          error: 'Test failed',
          message: error.message,
          stack: error.stack
        }
      };
    }
  }
});

console.log('✓ TableStorageDiagnostic endpoint registered: /api/diagnostics/table-storage');
