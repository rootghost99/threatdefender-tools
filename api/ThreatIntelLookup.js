const { app } = require('@azure/functions');
const axios = require('axios');

app.http('ThreatIntelLookup', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Threat Intel Lookup function triggered');

        if (request.method === 'OPTIONS') {
            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type'
                }
            };
        }

        try {
            const body = await request.json();
            const { indicator } = body;

            if (!indicator) {
                return {
                    status: 400,
                    jsonBody: { error: 'Missing indicator field' }
                };
            }

            const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
            const aipdbApiKey = process.env.ABUSEIPDB_API_KEY;
            const urlscanApiKey = process.env.URLSCAN_API_KEY;
            const greynoiseApiKey = process.env.GREYNOISE_API_KEY;
            const shodanApiKey = process.env.SHODAN_API_KEY;
            const otxApiKey = process.env.ALIENVAULT_OTX_API_KEY;

            const indicatorType = detectIndicatorType(indicator);
            const results = {
                indicator: indicator,
                type: indicatorType,
                virusTotal: null,
                abuseIPDB: null,
                urlScan: null,
                greyNoise: null,
                shodan: null,
                alienVault: null
            };

            // Query VirusTotal
            if (vtApiKey) {
                try {
                    context.log('Querying VirusTotal for:', indicator);
                    results.virusTotal = await queryVirusTotal(indicator, indicatorType, vtApiKey);
                    context.log('VirusTotal query successful');
                } catch (error) {
                    context.log.error('VirusTotal error:', error.message);
                    results.virusTotal = { error: error.message };
                }
            }

            // Query AbuseIPDB (IP only)
            if (indicatorType === 'IP' && aipdbApiKey) {
                try {
                    context.log('Querying AbuseIPDB for:', indicator);
                    results.abuseIPDB = await queryAbuseIPDB(indicator, aipdbApiKey);
                    context.log('AbuseIPDB query successful');
                } catch (error) {
                    context.log.error('AbuseIPDB error:', error.message);
                    results.abuseIPDB = { error: error.message };
                }
            }

            // Query URLScan.io (URL and Domain)
            if ((indicatorType === 'URL' || indicatorType === 'Domain') && urlscanApiKey) {
                try {
                    context.log('Querying URLScan for:', indicator);
                    results.urlScan = await queryURLScan(indicator, indicatorType, urlscanApiKey);
                    context.log('URLScan query successful');
                } catch (error) {
                    context.log.error('URLScan error:', error.message);
                    results.urlScan = { error: error.message };
                }
            }

            // Query GreyNoise (IP only)
            if (indicatorType === 'IP' && greynoiseApiKey) {
                try {
                    context.log('Querying GreyNoise for:', indicator);
                    results.greyNoise = await queryGreyNoise(indicator, greynoiseApiKey);
                    context.log('GreyNoise query successful');
                } catch (error) {
                    context.log.error('GreyNoise error:', error.message);
                    results.greyNoise = { error: error.message };
                }
            }

            // Query Shodan (IP only)
            if (indicatorType === 'IP' && shodanApiKey) {
                try {
                    context.log('Querying Shodan for:', indicator);
                    results.shodan = await queryShodan(indicator, shodanApiKey);
                    context.log('Shodan query successful');
                } catch (error) {
                    context.log.error('Shodan error:', error.message);
                    results.shodan = { error: error.message };
                }
            }

            // Query AlienVault OTX (all types)
            if (otxApiKey) {
                try {
                    context.log('Querying AlienVault OTX for:', indicator);
                    results.alienVault = await queryAlienVault(indicator, indicatorType, otxApiKey);
                    context.log('AlienVault OTX query successful');
                } catch (error) {
                    context.log.error('AlienVault OTX error:', error.message);
                    context.log.error('AlienVault OTX error stack:', error.stack);
                    results.alienVault = { error: error.message };
                }
            }

            context.log('All queries complete, returning results');

            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: results
            };

        } catch (error) {
            context.log.error('CRITICAL ERROR in ThreatIntelLookup:', error.message);
            context.log.error('Error stack:', error.stack);
            context.log.error('Indicator:', indicator);
            return {
                status: 500,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: { error: 'Failed to perform lookup', details: error.message, stack: error.stack }
            };
        }
    }
});

function detectIndicatorType(indicator) {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const sha1Regex = /^[a-fA-F0-9]{40}$/;
    const sha256Regex = /^[a-fA-F0-9]{64}$/;
    const urlRegex = /^https?:\/\//;
    const domainRegex = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

    if (ipRegex.test(indicator)) return 'IP';
    if (sha256Regex.test(indicator)) return 'SHA256';
    if (sha1Regex.test(indicator)) return 'SHA1';
    if (urlRegex.test(indicator)) return 'URL';
    if (domainRegex.test(indicator)) return 'Domain';
    
    return 'Unknown';
}

async function queryVirusTotal(indicator, type, apiKey) {
    let endpoint;
    
    switch (type) {
        case 'IP':
            endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`;
            break;
        case 'SHA1':
        case 'SHA256':
            endpoint = `https://www.virustotal.com/api/v3/files/${indicator}`;
            break;
        case 'URL':
            const urlId = Buffer.from(indicator).toString('base64')
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
            break;
        case 'Domain':
            endpoint = `https://www.virustotal.com/api/v3/domains/${indicator}`;
            break;
        default:
            throw new Error('Unsupported indicator type for VirusTotal');
    }

    const response = await axios.get(endpoint, {
        headers: { 'x-apikey': apiKey }
    });

    const stats = response.data.data.attributes.last_analysis_stats;
    const lastAnalysisDate = response.data.data.attributes.last_analysis_date;
    
    return {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected,
        harmless: stats.harmless,
        reputation: response.data.data.attributes.reputation || 'N/A',
        lastAnalysis: lastAnalysisDate ? new Date(lastAnalysisDate * 1000).toISOString() : 'N/A'
    };
}

async function queryAbuseIPDB(ip, apiKey) {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        headers: {
            'Key': apiKey,
            'Accept': 'application/json'
        },
        params: {
            ipAddress: ip,
            maxAgeInDays: 90
        }
    });

    const data = response.data.data;
    return {
        abuseScore: data.abuseConfidenceScore,
        totalReports: data.totalReports,
        countryCode: data.countryCode,
        usageType: data.usageType,
        isp: data.isp,
        domain: data.domain,
        isWhitelisted: data.isWhitelisted
    };
}

async function queryURLScan(indicator, type, apiKey) {
    // First, search for existing scans
    const searchQuery = type === 'URL' ? `page.url:"${indicator}"` : `domain:${indicator}`;
    
    try {
        const searchResponse = await axios.get('https://urlscan.io/api/v1/search/', {
            headers: { 'API-Key': apiKey },
            params: { q: searchQuery }
        });

        if (searchResponse.data.results && searchResponse.data.results.length > 0) {
            const latestResult = searchResponse.data.results[0];
            return {
                verdictMalicious: latestResult.verdicts?.overall?.malicious || false,
                score: latestResult.verdicts?.overall?.score || 0,
                categories: latestResult.verdicts?.overall?.categories || [],
                screenshot: latestResult.screenshot,
                reportUrl: latestResult.result,
                ip: latestResult.page?.ip,
                server: latestResult.page?.server,
                scanDate: latestResult.task?.time
            };
        }

        // If no results, submit a new scan
        const submitResponse = await axios.post('https://urlscan.io/api/v1/scan/', {
            url: indicator,
            visibility: 'public'
        }, {
            headers: { 
                'API-Key': apiKey,
                'Content-Type': 'application/json'
            }
        });

        return {
            scanning: true,
            reportUrl: submitResponse.data.result,
            message: 'Scan submitted, results will be available in ~30 seconds'
        };

    } catch (error) {
        throw new Error(`URLScan query failed: ${error.message}`);
    }
}

async function queryGreyNoise(ip, apiKey) {
    try {
        const response = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
            headers: { 'key': apiKey }
        });

        const data = response.data;
        return {
            noise: data.noise || false,
            riot: data.riot || false,
            classification: data.classification || 'unknown',
            name: data.name || 'N/A',
            lastSeen: data.last_seen || 'N/A',
            message: data.message || ''
        };
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return {
                noise: false,
                riot: false,
                classification: 'unknown',
                message: 'IP not found in GreyNoise database'
            };
        }
        throw new Error(`GreyNoise query failed: ${error.message}`);
    }
}

async function queryShodan(ip, apiKey) {
    try {
        const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
            params: { key: apiKey }
        });

        const data = response.data;
        
        // Extract open ports and services
        const ports = data.ports || [];
        const services = (data.data || []).slice(0, 10).map(service => ({
            port: service.port,
            protocol: service.transport,
            product: service.product || 'Unknown',
            version: service.version || '',
            banner: service.data ? service.data.substring(0, 200) : ''
        }));

        // Extract vulnerabilities
        const vulns = data.vulns || [];
        const topVulns = Object.keys(vulns).slice(0, 10);

        return {
            organization: data.org || 'Unknown',
            isp: data.isp || 'Unknown',
            asn: data.asn || 'Unknown',
            country: data.country_name || 'Unknown',
            city: data.city || 'Unknown',
            ports: ports,
            openPortsCount: ports.length,
            services: services,
            vulnerabilities: topVulns,
            vulnCount: Object.keys(vulns).length,
            lastUpdate: data.last_update || 'N/A',
            hostnames: data.hostnames || [],
            tags: data.tags || []
        };
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return {
                message: 'No information available for this IP',
                error: 'not_found'
            };
        }
        throw new Error(`Shodan query failed: ${error.message}`);
    }
}

async function queryAlienVault(indicator, type, apiKey) {
    try {
        let endpoint;
        
        // Determine the correct OTX endpoint based on indicator type
        switch (type) {
            case 'IP':
                endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general`;
                break;
            case 'Domain':
                endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${indicator}/general`;
                break;
            case 'URL':
                // URL needs to be encoded
                const encodedUrl = encodeURIComponent(indicator);
                endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodedUrl}/general`;
                break;
            case 'SHA1':
            case 'SHA256':
                endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${indicator}/general`;
                break;
            default:
                throw new Error('Unsupported indicator type for AlienVault OTX');
        }

        const response = await axios.get(endpoint, {
            headers: { 'X-OTX-API-KEY': apiKey }
        });

        const data = response.data;
        
        // Extract pulse information
        const pulses = data.pulse_info?.pulses || [];
        const topPulses = pulses.slice(0, 5).map(pulse => ({
            name: pulse.name,
            tags: pulse.tags || [],
            malwareFamilies: pulse.malware_families || [],
            adversary: pulse.adversary || null,
            created: pulse.created,
            modified: pulse.modified,
            id: pulse.id
        }));

        // Extract validation info
        const validations = data.validation || [];
        
        // Get reputation/threat score
        const reputation = data.reputation || 0;
        
        return {
            pulseCount: data.pulse_info?.count || 0,
            pulses: topPulses,
            validations: validations,
            reputation: reputation,
            sections: data.sections || [],
            whois: data.whois || null,
            hasData: pulses.length > 0 || validations.length > 0
        };
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return {
                pulseCount: 0,
                pulses: [],
                validations: [],
                reputation: 0,
                hasData: false,
                message: 'No threat intelligence data found'
            };
        }
        throw new Error(`AlienVault OTX query failed: ${error.message}`);
    }
}
