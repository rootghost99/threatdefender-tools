const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'http://localhost:7071',
      changeOrigin: true,
      logLevel: 'debug',
      onError: (err, req, res) => {
        console.error('[Proxy Error]', err.message);
        console.log('[Proxy] Make sure Azure Functions is running on port 7071');
        console.log('[Proxy] Run: cd api && npm install && npm start');
        res.status(500).json({
          error: 'API Server not available',
          message: 'Please start the Azure Functions backend: cd api && npm start',
          details: err.message
        });
      }
    })
  );
};
