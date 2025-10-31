// Simple test - just try to call Hybrid Analysis API
const { app } = require('@azure/functions');
const axios = require('axios');

app.http('HybridAnalysisRawTest', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const hash = body?.indicator || '3b68c4688b8935e71c73d7372ad5bbb56c2456814e508f88d8a6feb3157273d0';
      const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;

      context.log('Attempting Hybrid Analysis API call...');
      context.log('Hash:', hash);
      context.log('API Key (first 8):', apiKey?.substring(0, 8));

      try {
        // Try different encoding methods
        context.log('=== Testing encoding methods ===');

        // Method 1: Direct string (no encoding)
        const method1 = `hash=${hash}`;
        context.log('Method 1 (direct string):', method1);

        // Method 2: URLSearchParams
        const params2 = new URLSearchParams();
        params2.append('hash', hash);
        const method2 = params2.toString();
        context.log('Method 2 (URLSearchParams):', method2);

        // Method 3: Using axios's built-in URLSearchParams support
        const method3 = new URLSearchParams({ hash: hash });
        context.log('Method 3 (URLSearchParams from object):', method3.toString());

        context.log('=== Attempting API call with direct string ===');

        const response = await axios({
          method: 'post',
          url: 'https://www.hybrid-analysis.com/api/v2/search/hash',
          data: method1,
          headers: {
            'api-key': apiKey,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Falcon Sandbox',
            'Content-Length': Buffer.byteLength(method1)
          },
          timeout: 15000
        });

        return {
          status: 200,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
          },
          jsonBody: {
            success: true,
            responseStatus: response.status,
            responseHeaders: response.headers,
            dataType: typeof response.data,
            dataIsArray: Array.isArray(response.data),
            dataLength: response.data?.length,
            rawData: response.data
          }
        };

      } catch (apiError) {
        context.log('Hybrid Analysis API Error:', apiError.message);

        return {
          status: 200,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
          },
          jsonBody: {
            success: false,
            error: apiError.message,
            errorType: apiError.constructor?.name,
            responseStatus: apiError.response?.status,
            responseData: apiError.response?.data,
            isAxiosError: apiError.isAxiosError,
            code: apiError.code
          }
        };
      }

    } catch (error) {
      return {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          error: error.message,
          stack: error.stack
        }
      };
    }
  }
});
