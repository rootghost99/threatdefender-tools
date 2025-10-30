// Diagnostic version - checks each step
const { app } = require('@azure/functions');

app.http('HybridAnalysisDiag', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    const diagnostics = {
      step1_functionCalled: true,
      step2_envCheck: null,
      step3_bodyParse: null,
      step4_indicator: null,
      errors: []
    };

    try {
      // Check environment variable
      const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;
      diagnostics.step2_envCheck = {
        isSet: !!apiKey,
        firstChars: apiKey ? apiKey.substring(0, 8) + '...' : 'NOT SET'
      };

      // Try to parse body
      try {
        const body = await request.json();
        diagnostics.step3_bodyParse = 'Success';
        diagnostics.step4_indicator = body?.indicator || 'Missing';
      } catch (e) {
        diagnostics.step3_bodyParse = 'Failed: ' + e.message;
        diagnostics.errors.push(e.message);
      }

      // Check if axios is available
      try {
        const axios = require('axios');
        diagnostics.axiosAvailable = true;
        diagnostics.axiosVersion = axios.VERSION || 'Unknown';
      } catch (e) {
        diagnostics.axiosAvailable = false;
        diagnostics.errors.push('Axios not available: ' + e.message);
      }

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          success: true,
          diagnostics,
          timestamp: new Date().toISOString()
        }
      };

    } catch (error) {
      return {
        status: 500,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          success: false,
          error: error.message,
          stack: error.stack,
          diagnostics
        }
      };
    }
  }
});
