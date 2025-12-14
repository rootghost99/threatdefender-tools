# Threat Intel Checker

A standalone Windows application for querying threat intelligence sources.

## Features

- **Multi-Source Queries**: Query 9+ threat intelligence sources in parallel
- **Auto-Detection**: Automatically detects indicator type (IP, Domain, URL, Hash)
- **Secure Storage**: API keys stored securely with encryption
- **Dark/Light Mode**: Toggle between dark and light themes
- **Offline-Ready**: All processing done locally (API calls only to TI sources)

## Supported Threat Intelligence Sources

| Source | Indicators | API Key Required |
|--------|------------|------------------|
| VirusTotal | IP, Domain, URL, SHA-1, SHA-256 | Yes |
| AbuseIPDB | IP | Yes |
| URLScan.io | URL, Domain | Yes |
| GreyNoise | IP | Yes |
| Shodan | IP | Yes |
| AlienVault OTX | IP, Domain, URL, SHA-1, SHA-256 | Yes |
| MXToolbox | IP | Yes |
| Hybrid Analysis | SHA-1, SHA-256, MD5, URL | Yes |
| ARIN RDAP | IP | No |

## Installation

### From Installer (Recommended)

1. Download the latest `.exe` installer from the releases
2. Run the installer and follow the prompts
3. Launch "Threat Intel Checker" from the Start Menu or Desktop

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd threat-intel-app

# Install dependencies
npm install
cd src && npm install && cd ..

# Run in development mode
npm run dev

# Build for Windows
npm run build:win
```

## Configuration

1. Launch the application
2. Click the ⚙️ Settings button in the header
3. Enter your API keys for each service you want to use
4. Click "Save API Keys"

### Getting API Keys

- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **AbuseIPDB**: https://www.abuseipdb.com/account/api
- **URLScan.io**: https://urlscan.io/user/profile/
- **GreyNoise**: https://viz.greynoise.io/account/api-key
- **Shodan**: https://account.shodan.io/
- **AlienVault OTX**: https://otx.alienvault.com/api
- **MXToolbox**: https://mxtoolbox.com/user/api/
- **Hybrid Analysis**: https://www.hybrid-analysis.com/my-account?tab=api-key

## System Requirements

- **OS**: Windows 11 or newer
- **RAM**: 4 GB minimum
- **Disk**: 200 MB free space
- **Network**: Internet connection for API queries

## Security Notes

- API keys are stored locally with encryption
- No data is transmitted except to the configured TI sources
- All queries are made directly to official API endpoints
- Consider network security when submitting sensitive indicators

## Development

### Project Structure

```
threat-intel-app/
├── main.js              # Electron main process
├── preload.js           # Preload script for IPC
├── package.json         # Dependencies and build config
├── server/              # Express.js backend
│   ├── index.js         # Server entry point
│   └── services/        # TI query services
├── src/                 # React frontend
│   ├── public/          # Static files
│   └── src/             # React components
├── assets/              # App icons
└── config/              # Configuration templates
```

### Building

```bash
# Build React frontend
npm run build:react

# Package for Windows
npm run build:win
```

## Troubleshooting

### "API Key not configured" errors
Ensure you've entered valid API keys in Settings.

### Connection timeouts
Check your internet connection and firewall settings.

### App won't start
Try deleting the settings file at:
`%APPDATA%/threat-intel-checker/threat-intel-settings.json`

## License

See LICENSE.txt for details.
