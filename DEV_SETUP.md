# ThreatDefender Operations Suite - Development Setup Guide

Complete guide for setting up the local development environment.

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Node.js | 18.x or later | Runtime for both frontend and backend |
| npm | 9.x or later | Package management |
| Azure Functions Core Tools | v4.x | Backend API runtime |
| Git | Latest | Version control |

### Optional Software

| Software | Purpose |
|----------|---------|
| Azurite | Local Azure Storage emulator |
| Azure Storage Explorer | GUI for managing storage |
| VS Code | Recommended IDE |

---

## Installing Prerequisites

### Node.js

**macOS:**
```bash
brew install node@18
```

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Windows:**
Download from https://nodejs.org/

**Verify Installation:**
```bash
node --version  # Should show v18.x.x
npm --version   # Should show 9.x.x or later
```

---

### Azure Functions Core Tools

**macOS:**
```bash
brew tap azure/functions
brew install azure-functions-core-tools@4
```

**Linux (Ubuntu/Debian):**
```bash
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-$(lsb_release -cs)-prod $(lsb_release -cs) main" > /etc/apt/sources.list.d/dotnetdev.list'
sudo apt-get update
sudo apt-get install azure-functions-core-tools-4
```

**Windows:**
```bash
npm install -g azure-functions-core-tools@4 --unsafe-perm true
```

Or download from: https://aka.ms/azfunc-install

**Verify Installation:**
```bash
func --version  # Should show 4.x.x
```

---

### Azurite (Optional - Local Storage Emulator)

```bash
npm install -g azurite
```

---

## Project Setup

### 1. Clone Repository

```bash
git clone <repository-url>
cd threatdefender-tools
```

### 2. Install Dependencies

```bash
# Install frontend dependencies
npm install

# Install backend dependencies
cd api
npm install
cd ..
```

### 3. Configure Environment Variables

Create or edit `api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AzureWebJobsStorage": "",

    "AZURE_OPENAI_ENDPOINT": "https://your-openai.openai.azure.com/",
    "AZURE_OPENAI_API_KEY": "your-openai-api-key",
    "AZURE_OPENAI_DEPLOYMENT": "gpt-4",

    "AZURE_STORAGE_ACCOUNT_NAME": "your-storage-account",
    "AZURE_STORAGE_ACCOUNT_KEY": "your-storage-key",
    "PROMPTS_TABLE_NAME": "Prompts",
    "PROMPT_RUNS_TABLE_NAME": "PromptRuns",

    "COSMOS_CONNECTION": "AccountEndpoint=https://your-cosmos.documents.azure.com:443/;AccountKey=your-key==",

    "CLAUDE_API_ENDPOINT": "https://your-service.services.ai.azure.com/anthropic/v1/messages",
    "CLAUDE_API_KEY": "your-claude-api-key",
    "CLAUDE_MODEL": "claude-sonnet-4-20250514",

    "VIRUSTOTAL_API_KEY": "your-virustotal-key",
    "ABUSEIPDB_API_KEY": "your-abuseipdb-key",
    "GREYNOISE_API_KEY": "your-greynoise-key",
    "SHODAN_API_KEY": "your-shodan-key",
    "ALIENVAULT_OTX_API_KEY": "your-alienvault-key",
    "URLSCAN_API_KEY": "your-urlscan-key",
    "MXTOOLBOX_API_KEY": "your-mxtoolbox-key",
    "HYBRID_ANALYSIS_API_KEY": "your-hybrid-analysis-key"
  }
}
```

**Important:** This file is git-ignored. Never commit API keys.

See [AZURE_CONFIG.md](AZURE_CONFIG.md) for detailed configuration reference.

---

## Running the Application

### Option 1: Full Stack (Recommended)

**Terminal 1 - Start Backend:**
```bash
cd api
npm start
```

Backend runs on: http://localhost:7071

**Terminal 2 - Start Frontend:**
```bash
npm start
```

Frontend runs on: http://localhost:3000

The frontend automatically proxies `/api/*` requests to the backend.

---

### Option 2: Frontend Only

```bash
npm start
```

**Note:** API features won't work without the backend running.

---

### Option 3: Using Local Storage Emulator

1. **Start Azurite:**
```bash
azurite --silent --location /tmp/azurite
```

2. **Update local.settings.json:**
```json
{
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "AZURE_STORAGE_ACCOUNT_NAME": "devstoreaccount1",
    "AZURE_STORAGE_ACCOUNT_KEY": "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
  }
}
```

3. **Start backend and frontend as usual**

---

## Project Structure

```
threatdefender-tools/
├── src/                          # React frontend
│   ├── components/               # UI components
│   │   ├── AlertTriageAssistant.jsx
│   │   ├── ThreatIntelLookup.jsx
│   │   ├── KQLDiffViewer.jsx
│   │   ├── PromptGallery.jsx
│   │   ├── PromptDetail.jsx
│   │   ├── PromptEditor.jsx
│   │   ├── PromptAdmin.jsx
│   │   ├── EmailPostureCheck.jsx
│   │   ├── EmailHeaderAnalyzer.jsx
│   │   ├── SOCHandoffTool.jsx
│   │   ├── TriageChat.jsx
│   │   ├── Navigation.jsx
│   │   └── Resources.jsx
│   ├── contexts/                 # React contexts
│   │   ├── AuthContext.jsx
│   │   └── NavigationContext.jsx
│   ├── data/                     # Static data
│   │   └── socPromptTemplates.js
│   ├── App.js                    # Main routing
│   ├── index.js                  # Entry point
│   └── setupProxy.js             # Dev proxy config
├── api/                          # Azure Functions backend
│   ├── PromptsAPI-REST.js        # Prompt CRUD + execution
│   ├── PromptRunAPI.js           # Execution tracking
│   ├── ThreatIntelLookup.js      # Threat intel aggregation
│   ├── HybridAnalysisLookup.js   # Malware sandbox
│   ├── KQLAnalyzer.js            # KQL diff analysis
│   ├── AlertTriage.js            # IR playbook generation
│   ├── EmailPosture.js           # Email security check
│   ├── EmailHeaderAnalyzer.js    # Header parsing
│   ├── TriageSession.js          # Chat sessions
│   ├── ResourcesAPI.js           # Reference docs
│   ├── index.js                  # Function router
│   ├── host.json                 # Functions config
│   ├── package.json              # Backend dependencies
│   └── local.settings.json       # Local env vars (git-ignored)
├── public/                       # Static assets
├── threat-intel-app/             # Standalone Windows app
├── package.json                  # Frontend dependencies
├── tailwind.config.js            # Tailwind config
└── *.md                          # Documentation
```

---

## Development Workflow

### Making Frontend Changes

1. Edit files in `src/`
2. Changes hot-reload automatically
3. Check browser console for errors

### Making Backend Changes

1. Edit files in `api/`
2. **Restart the backend** (changes don't hot-reload)
3. Check terminal for errors

### Adding New Dependencies

**Frontend:**
```bash
npm install <package-name>
```

**Backend:**
```bash
cd api
npm install <package-name>
```

---

## Feature-Specific Configuration

### Minimum Configuration by Feature

| Feature | Required Variables |
|---------|-------------------|
| KQL Diff Viewer | None (diff only) |
| KQL AI Analysis | `AZURE_OPENAI_*` |
| Alert Triage | `AZURE_OPENAI_*` |
| Prompt Gallery (browse) | `AZURE_STORAGE_*` |
| Prompt Execution | `AZURE_OPENAI_*`, `AZURE_STORAGE_*` |
| Threat Intel | Any TI API key (optional) |
| Email Posture | None (MXToolbox optional) |
| SOC Handoff | None (offline) |
| AI Triage Chat | `COSMOS_*`, `CLAUDE_*` |

---

## Testing Features

### Threat Intel Lookup
1. Navigate to http://localhost:3000/threat-intel
2. Enter an IP: `8.8.8.8`
3. Click Search
4. Results should appear from configured sources

### Prompt Gallery
1. Navigate to http://localhost:3000/prompts
2. Click "New Prompt"
3. Create a simple prompt
4. Run the prompt

### KQL Diff Viewer
1. Navigate to http://localhost:3000/kql-diff
2. Paste KQL in both editors
3. Click Compare
4. Run AI Analysis (requires OpenAI)

### Email Posture
1. Navigate to http://localhost:3000/email-posture
2. Enter a domain: `google.com`
3. Click Check
4. Review results

---

## Common Issues and Solutions

### "Failed to fetch prompts (404)"

**Cause:** Backend not running or not accessible.

**Solutions:**
1. Ensure backend is running: `cd api && npm start`
2. Check backend is on port 7071
3. Check `api/local.settings.json` exists

### "Azure Storage credentials not configured"

**Cause:** Missing or incorrect storage variables.

**Solutions:**
1. Verify `AZURE_STORAGE_ACCOUNT_NAME` is set
2. Verify `AZURE_STORAGE_ACCOUNT_KEY` is set
3. Check for typos

### "crypto is not defined"

**Cause:** SDK compatibility issue (already fixed in codebase).

**Solution:** This should not occur with current code. If it does, check that OpenAI calls use REST API, not SDK.

### "CORS error"

**Cause:** Frontend trying to call API directly instead of through proxy.

**Solutions:**
1. Ensure frontend is on port 3000
2. Ensure backend is on port 7071
3. Check `src/setupProxy.js` exists

### "Port 3000 already in use"

**Solution:**
```bash
# Find process using port
lsof -i :3000

# Kill process
kill -9 <PID>
```

### "Port 7071 already in use"

**Solution:**
```bash
# Find process using port
lsof -i :7071

# Kill process
kill -9 <PID>
```

### Backend won't start

**Solutions:**
1. Verify Azure Functions Core Tools installed: `func --version`
2. Verify dependencies installed: `cd api && npm install`
3. Check `local.settings.json` syntax (valid JSON)

---

## VS Code Extensions (Recommended)

| Extension | Purpose |
|-----------|---------|
| Azure Functions | Debug and deploy functions |
| ES7+ React/Redux | React snippets |
| Tailwind CSS IntelliSense | CSS class autocomplete |
| Prettier | Code formatting |
| ESLint | Linting |

---

## Debugging

### Frontend Debugging

1. Open Chrome DevTools (F12)
2. Use React Developer Tools extension
3. Check Console tab for errors
4. Check Network tab for API calls

### Backend Debugging

**VS Code:**
1. Open project in VS Code
2. Set breakpoints in `api/*.js`
3. Press F5 to start debugging
4. Backend starts with debugger attached

**Console Logging:**
```javascript
context.log('Debug message:', variable);
```

Check terminal output for logs.

---

## Building for Production

### Frontend Build

```bash
npm run build
```

Creates optimized build in `/build` directory.

### Deployment

The GitHub Actions workflow automatically deploys to Azure Static Web Apps when pushing to main branch.

Manual deployment via Azure CLI:
```bash
az staticwebapp deploy --app-name <your-app-name> --source ./build
```

---

## Related Documentation

- [AZURE_CONFIG.md](AZURE_CONFIG.md) - Complete environment variables reference
- [API_REFERENCE.md](API_REFERENCE.md) - API endpoint documentation
- [ARCHITECTURE_SUMMARY.md](ARCHITECTURE_SUMMARY.md) - Technical architecture
- [TROUBLESHOOTING_PROMPTS.md](TROUBLESHOOTING_PROMPTS.md) - Prompt Gallery issues
