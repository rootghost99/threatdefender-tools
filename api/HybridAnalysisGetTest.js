// Test the GET endpoint and return raw response
const { app } = require('@azure/functions');
const axios = require('axios');

app.http('HybridAnalysisGetTest', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const hash = body?.indicator || '3b68c4688b8935e71c73d7372ad5bbb56c2456814e508f88d8a6feb3157273d0';
      const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;

      context.log('Testing GET endpoint with hash:', hash);

      const url = `https://hybrid-analysis.com/api/v2/search/hash?hash=${encodeURIComponent(hash)}`;

      try {
        const response = await axios.get(url, {
          headers: {
            'api-key': apiKey,
            'User-Agent': 'Falcon Sandbox'
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
            apiStatus: response.status,
            apiHeaders: response.headers,
            dataType: typeof response.data,
            isArray: Array.isArray(response.data),
            dataKeys: response.data ? Object.keys(response.data) : null,
            dataLength: Array.isArray(response.data) ? response.data.length : 'N/A',
            rawData: response.data,
            // Try to identify structure
            possibleStructures: {
              isDirectArray: Array.isArray(response.data),
              hasDataProperty: response.data?.data !== undefined,
              hasResultProperty: response.data?.result !== undefined,
              hasResultsProperty: response.data?.results !== undefined,
            }
          }
        };

      } catch (apiError) {
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
            apiStatus: apiError.response?.status,
            apiStatusText: apiError.response?.statusText,
            apiData: apiError.response?.data,
            apiHeaders: apiError.response?.headers
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
