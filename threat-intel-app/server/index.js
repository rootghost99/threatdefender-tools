const express = require('express');
const cors = require('cors');
const path = require('path');
const { queryThreatIntel } = require('./services/threatIntel');
const { queryHybridAnalysis } = require('./services/hybridAnalysis');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '..', 'src', 'build')));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API key status endpoint
app.get('/api/status', (req, res) => {
  const apiKeys = {
    virusTotal: !!process.env.VIRUSTOTAL_API_KEY,
    abuseIPDB: !!process.env.ABUSEIPDB_API_KEY,
    urlScan: !!process.env.URLSCAN_API_KEY,
    greyNoise: !!process.env.GREYNOISE_API_KEY,
    shodan: !!process.env.SHODAN_API_KEY,
    alienVault: !!process.env.ALIENVAULT_OTX_API_KEY,
    mxToolbox: !!process.env.MXTOOLBOX_API_KEY,
    hybridAnalysis: !!process.env.HYBRID_ANALYSIS_API_KEY
  };

  res.json({
    status: 'ok',
    configuredApis: apiKeys,
    arinRdap: true // Always available (no API key needed)
  });
});

// Threat Intel Lookup endpoint
app.post('/api/ThreatIntelLookup', async (req, res) => {
  try {
    const { indicator } = req.body;

    if (!indicator) {
      return res.status(400).json({ error: 'Missing indicator field' });
    }

    console.log(`[ThreatIntel] Looking up: ${indicator}`);
    const results = await queryThreatIntel(indicator);
    console.log(`[ThreatIntel] Lookup complete for: ${indicator}`);

    res.json(results);
  } catch (error) {
    console.error('[ThreatIntel] Error:', error.message);
    res.status(500).json({
      error: 'Failed to perform lookup',
      details: error.message
    });
  }
});

// Hybrid Analysis Lookup endpoint
app.post('/api/HybridAnalysisLookup', async (req, res) => {
  try {
    const { indicator } = req.body;

    if (!indicator) {
      return res.status(400).json({ error: 'Missing indicator field' });
    }

    console.log(`[HybridAnalysis] Looking up: ${indicator}`);
    const results = await queryHybridAnalysis(indicator);
    console.log(`[HybridAnalysis] Lookup complete for: ${indicator}`);

    res.json(results);
  } catch (error) {
    console.error('[HybridAnalysis] Error:', error.message);
    res.status(500).json({
      error: 'Failed to perform Hybrid Analysis lookup',
      details: error.message
    });
  }
});

// Catch-all for SPA routing in production
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'src', 'build', 'index.html'));
  });
}

// Start server
app.listen(PORT, () => {
  console.log(`Threat Intel Checker server running on port ${PORT}`);
  // Signal to parent process that server is ready
  if (process.send) {
    process.send('ready');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Server shutting down...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Server shutting down...');
  process.exit(0);
});
