# ThreatDefender Tools - Local Development Setup

This application consists of a React frontend and Azure Functions backend API. To run it locally, you'll need to start both services.

## Prerequisites

1. **Node.js** (v18 or later)
2. **Azure Functions Core Tools** (for running the backend API)

## Installing Azure Functions Core Tools

### macOS
```bash
brew tap azure/functions
brew install azure-functions-core-tools@4
```

### Linux
```bash
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install azure-functions-core-tools-4
```

### Windows
Download and install from: https://aka.ms/azfunc-install

## Quick Start

### Option 1: Run Frontend Only (Limited Functionality)
```bash
npm install
npm start
```
The app will run on `http://localhost:3000` but API features won't work.

### Option 2: Run with Backend API (Full Functionality)

1. **Install dependencies for both frontend and backend:**
```bash
# Install frontend dependencies
npm install

# Install backend dependencies
cd api
npm install
cd ..
```

2. **Start the backend API (in one terminal):**
```bash
cd api
npm start
```
The API will run on `http://localhost:7071`

3. **Start the frontend (in another terminal):**
```bash
npm start
```
The app will run on `http://localhost:3000` and proxy API requests to `localhost:7071`

## Features Requiring Backend API

The following features require the backend API to be running:
- **Prompt Gallery** - Browse, create, edit prompts
- **Threat Intel Lookup** - Query threat intelligence
- **IR Playbook Generator** - Generate incident response playbooks
- **Email Posture Check** - Analyze email security posture

## Configuration

### Backend Configuration (api/local.settings.json)
The backend API requires Azure Storage credentials. Create or update `api/local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "node",
    "AZURE_STORAGE_ACCOUNT_NAME": "your-storage-account",
    "AZURE_STORAGE_ACCOUNT_KEY": "your-storage-key",
    "PROMPTS_TABLE_NAME": "Prompts",
    "AZURE_OPENAI_ENDPOINT": "your-openai-endpoint",
    "AZURE_OPENAI_API_KEY": "your-openai-key"
  }
}
```

**For development without Azure Storage**, you can use Azure Storage Emulator (Azurite):
```bash
npm install -g azurite
azurite --silent --location /tmp/azurite
```

## Troubleshooting

### "Failed to fetch prompts (404)" Error
This means the backend API is not running. Make sure:
1. Azure Functions Core Tools is installed: `func --version`
2. Backend is running: `cd api && npm start`
3. Backend is on port 7071 (check terminal output)

### Backend Won't Start
- Check that all dependencies are installed: `cd api && npm install`
- Verify Azure Functions Core Tools is installed: `func --version`
- Check `api/local.settings.json` exists and is properly formatted

### Proxy Errors
The frontend proxies `/api/*` requests to `http://localhost:7071`. If you see proxy errors:
- Ensure the backend is running on port 7071
- Check terminal for proxy error messages
- Restart both frontend and backend

## Development Workflow

1. Start backend: `cd api && npm start` (keep running)
2. Start frontend: `npm start` (in separate terminal)
3. Open browser to `http://localhost:3000`
4. Make changes to frontend code (hot reload enabled)
5. Make changes to backend code (restart backend after changes)

## Deployment

This app is designed for Azure Static Web Apps. See deployment documentation for production setup.
