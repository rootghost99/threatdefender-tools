// Test different axios configurations for form-urlencoded
const { app } = require('@azure/functions');
const axios = require('axios');

app.http('HybridAnalysisTest2', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const hash = body?.indicator || '3b68c4688b8935e71c73d7372ad5bbb56c2456814e508f88d8a6feb3157273d0';
      const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;

      context.log('Testing with hash:', hash);

      const results = [];

      // Test 1: Direct URLSearchParams object
      try {
        context.log('Test 1: Direct URLSearchParams object');
        const params1 = new URLSearchParams();
        params1.append('hash', hash);

        const response1 = await axios.post(
          'https://www.hybrid-analysis.com/api/v2/search/hash',
          params1,  // Pass object directly
          {
            headers: {
              'api-key': apiKey,
              'User-Agent': 'Falcon Sandbox'
              // Let axios set Content-Type automatically
            },
            timeout: 15000
          }
        );
        results.push({ test: 1, success: true, status: response1.status, dataLength: response1.data?.length });
      } catch (e) {
        results.push({ test: 1, success: false, error: e.message, responseData: e.response?.data });
      }

      // Test 2: String with explicit Content-Type
      try {
        context.log('Test 2: String with explicit Content-Type');
        const data2 = `hash=${hash}`;

        const response2 = await axios.post(
          'https://www.hybrid-analysis.com/api/v2/search/hash',
          data2,
          {
            headers: {
              'api-key': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Falcon Sandbox'
            },
            timeout: 15000
          }
        );
        results.push({ test: 2, success: true, status: response2.status, dataLength: response2.data?.length });
      } catch (e) {
        results.push({ test: 2, success: false, error: e.message, responseData: e.response?.data });
      }

      // Test 3: Object (let axios serialize)
      try {
        context.log('Test 3: Plain object');
        const data3 = { hash: hash };

        const response3 = await axios.post(
          'https://www.hybrid-analysis.com/api/v2/search/hash',
          data3,
          {
            headers: {
              'api-key': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Falcon Sandbox'
            },
            timeout: 15000
          }
        );
        results.push({ test: 3, success: true, status: response3.status, dataLength: response3.data?.length });
      } catch (e) {
        results.push({ test: 3, success: false, error: e.message, responseData: e.response?.data });
      }

      // Test 4: Using axios config with params
      try {
        context.log('Test 4: Using axios data with transformRequest');
        const params4 = new URLSearchParams();
        params4.append('hash', hash);

        const response4 = await axios({
          method: 'POST',
          url: 'https://www.hybrid-analysis.com/api/v2/search/hash',
          data: params4,
          headers: {
            'api-key': apiKey,
            'User-Agent': 'Falcon Sandbox'
          },
          timeout: 15000,
          transformRequest: [(data, headers) => {
            context.log('Transform - data type:', data.constructor.name);
            context.log('Transform - data toString:', data.toString());
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            return data.toString();
          }]
        });
        results.push({ test: 4, success: true, status: response4.status, dataLength: response4.data?.length });
      } catch (e) {
        results.push({ test: 4, success: false, error: e.message, responseData: e.response?.data });
      }

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: { results }
      };

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
