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
        // Use URLSearchParams for proper form-urlencoded data
        const params = new URLSearchParams();
        params.append('hash', hash);

        context.log('Request body:', params.toString());

        const response = await axios.post(
          'https://www.hybrid-analysis.com/api/v2/search/hash',
          params,
          {
            headers: {
              'api-key': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Falcon Sandbox'
            },
            timeout: 15000
          }
        );

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
