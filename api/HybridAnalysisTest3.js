// Test with querystring and qs libraries
const { app } = require('@azure/functions');
const axios = require('axios');
const querystring = require('querystring');

app.http('HybridAnalysisTest3', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const hash = body?.indicator || '3b68c4688b8935e71c73d7372ad5bbb56c2456814e508f88d8a6feb3157273d0';
      const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;

      context.log('Testing with hash:', hash);
      context.log('Hash length:', hash.length);
      context.log('API Key exists:', !!apiKey);
      context.log('API Key first 10 chars:', apiKey?.substring(0, 10));

      const results = [];

      // Test 1: Using native querystring module
      try {
        context.log('=== Test 1: Native querystring module ===');
        const data1 = querystring.stringify({ hash: hash });
        context.log('Encoded data:', data1);
        context.log('Data length:', data1.length);

        const response1 = await axios.post(
          'https://www.hybrid-analysis.com/api/v2/search/hash',
          data1,
          {
            headers: {
              'api-key': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Falcon Sandbox'
            },
            timeout: 15000
          }
        );
        context.log('Test 1 SUCCESS - Status:', response1.status);
        results.push({
          test: 1,
          method: 'querystring.stringify',
          success: true,
          status: response1.status,
          dataLength: response1.data?.length
        });
      } catch (e) {
        context.log('Test 1 FAILED:', e.message);
        context.log('Response status:', e.response?.status);
        context.log('Response data:', JSON.stringify(e.response?.data));
        results.push({
          test: 1,
          method: 'querystring.stringify',
          success: false,
          error: e.message,
          status: e.response?.status,
          responseData: e.response?.data
        });
      }

      // Test 2: Manual encoding with encodeURIComponent
      try {
        context.log('=== Test 2: Manual encoding ===');
        const data2 = `hash=${encodeURIComponent(hash)}`;
        context.log('Encoded data:', data2);
        context.log('Data length:', data2.length);

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
        context.log('Test 2 SUCCESS - Status:', response2.status);
        results.push({
          test: 2,
          method: 'encodeURIComponent',
          success: true,
          status: response2.status,
          dataLength: response2.data?.length
        });
      } catch (e) {
        context.log('Test 2 FAILED:', e.message);
        context.log('Response data:', JSON.stringify(e.response?.data));
        results.push({
          test: 2,
          method: 'encodeURIComponent',
          success: false,
          error: e.message,
          status: e.response?.status,
          responseData: e.response?.data
        });
      }

      // Test 3: Try with different field name (maybe it's 'hashes' plural?)
      try {
        context.log('=== Test 3: Try field name "hashes" ===');
        const data3 = querystring.stringify({ hashes: hash });
        context.log('Encoded data:', data3);

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
        context.log('Test 3 SUCCESS - Status:', response3.status);
        results.push({
          test: 3,
          method: 'field:hashes',
          success: true,
          status: response3.status,
          dataLength: response3.data?.length
        });
      } catch (e) {
        context.log('Test 3 FAILED:', e.message);
        context.log('Response data:', JSON.stringify(e.response?.data));
        results.push({
          test: 3,
          method: 'field:hashes',
          success: false,
          error: e.message,
          status: e.response?.status,
          responseData: e.response?.data
        });
      }

      // Test 4: Try with array syntax (hash[])
      try {
        context.log('=== Test 4: Array syntax hash[] ===');
        const data4 = `hash[]=${hash}`;
        context.log('Encoded data:', data4);

        const response4 = await axios.post(
          'https://www.hybrid-analysis.com/api/v2/search/hash',
          data4,
          {
            headers: {
              'api-key': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Falcon Sandbox'
            },
            timeout: 15000
          }
        );
        context.log('Test 4 SUCCESS - Status:', response4.status);
        results.push({
          test: 4,
          method: 'field:hash[]',
          success: true,
          status: response4.status,
          dataLength: response4.data?.length
        });
      } catch (e) {
        context.log('Test 4 FAILED:', e.message);
        context.log('Response data:', JSON.stringify(e.response?.data));
        results.push({
          test: 4,
          method: 'field:hash[]',
          success: false,
          error: e.message,
          status: e.response?.status,
          responseData: e.response?.data
        });
      }

      // Test 5: Check if API key is working with a simple GET request
      try {
        context.log('=== Test 5: Verify API key with system heartbeat ===');
        const response5 = await axios.get(
          'https://www.hybrid-analysis.com/api/v2/system/heartbeat',
          {
            headers: {
              'api-key': apiKey,
              'User-Agent': 'Falcon Sandbox'
            },
            timeout: 15000
          }
        );
        context.log('Test 5 SUCCESS - API Key is valid');
        results.push({
          test: 5,
          method: 'API key validation',
          success: true,
          status: response5.status,
          data: response5.data
        });
      } catch (e) {
        context.log('Test 5 FAILED - API key might be invalid');
        context.log('Response data:', JSON.stringify(e.response?.data));
        results.push({
          test: 5,
          method: 'API key validation',
          success: false,
          error: e.message,
          status: e.response?.status,
          responseData: e.response?.data
        });
      }

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          testHash: hash,
          hashLength: hash.length,
          results
        }
      };

    } catch (error) {
      context.log('OUTER ERROR:', error);
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
