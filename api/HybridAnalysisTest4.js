// Test using native Node.js https module instead of axios
const { app } = require('@azure/functions');
const https = require('https');

app.http('HybridAnalysisTest4', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const hash = body?.indicator || '3b68c4688b8935e71c73d7372ad5bbb56c2456814e508f88d8a6feb3157273d0';
      const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;

      context.log('Testing with native https module');
      context.log('Hash:', hash);
      context.log('API Key first 10 chars:', apiKey?.substring(0, 10));

      // Prepare form data
      const formData = `hash=${hash}`;
      context.log('Form data to send:', formData);
      context.log('Form data length:', formData.length);
      context.log('Form data bytes:', Buffer.byteLength(formData, 'utf8'));

      // Make request using native https
      const result = await new Promise((resolve, reject) => {
        const options = {
          hostname: 'www.hybrid-analysis.com',
          port: 443,
          path: '/api/v2/search/hash',
          method: 'POST',
          headers: {
            'api-key': apiKey,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(formData, 'utf8'),
            'User-Agent': 'Falcon Sandbox'
          }
        };

        context.log('Request options:', JSON.stringify(options, null, 2));

        const req = https.request(options, (res) => {
          context.log('Response status:', res.statusCode);
          context.log('Response headers:', JSON.stringify(res.headers));

          let data = '';

          res.on('data', (chunk) => {
            data += chunk;
          });

          res.on('end', () => {
            context.log('Response body:', data);

            try {
              const parsed = JSON.parse(data);
              resolve({
                success: res.statusCode === 200,
                statusCode: res.statusCode,
                headers: res.headers,
                body: parsed
              });
            } catch (e) {
              resolve({
                success: false,
                statusCode: res.statusCode,
                headers: res.headers,
                body: data,
                parseError: e.message
              });
            }
          });
        });

        req.on('error', (error) => {
          context.log('Request error:', error);
          reject(error);
        });

        // Write the form data
        context.log('Writing form data to request body...');
        req.write(formData);
        req.end();
      });

      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json'
        },
        jsonBody: {
          test: 'Native HTTPS module',
          formDataSent: formData,
          formDataLength: formData.length,
          result: result
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
