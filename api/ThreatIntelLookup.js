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

        let indicator = 'unknown'; // Initialize with default value

        try {
            const body = await request.json();
            indicator = body.indicator;

            if (!indicator) {
                return {
                    status: 400,
                    headers: {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    jsonBody: { error: 'Missing indicator field' }
                };
            }

            const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
            const aipdbApiKey = process.env.ABUSEIPDB_API_KEY;
            const urlscanApiKey = process.env.URLSCAN_API_KEY;
            const greynoiseApiKey = process.env.GREYNOISE_API_KEY;
            const shodanApiKey = process.env.SHODAN_API_KEY;
            const otxApiKey = process.env.ALIENVAULT_OTX_API_KEY;
            const mxToolboxApiKey = process.env.MXTOOLBOX_API_KEY;

            const indicatorType = detectIndicatorType(indicator);
            const results = {
                indicator: indicator,
                type: indicatorType,
                virusTotal: null,
                abuseIPDB: null,
                urlScan: null,
                greyNoise: null,
                shodan: null,
                alienVault: null,
                mxToolbox: null
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

            // Query MXToolbox for ARIN/WHOIS (IP only)
            if (indicatorType === 'IP' && mxToolboxApiKey) {
                try {
                    context.log('Querying MXToolbox ARIN/WHOIS for:', indicator);
                    results.mxToolbox = await queryMXToolbox(indicator, mxToolboxApiKey);
                    context.log('MXToolbox query successful');
                } catch (error) {
                    context.log.error('MXToolbox error:', error.message);
                    results.mxToolbox = { error: error.message };
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
                jsonBody: { 
                    error: 'Failed to perform lookup', 
                    details: error.message,
                    indicator: indicator
                }
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
        headers: { 'x-apikey': apiKey },
        timeout: 15000
    });

    const stats = response.data.data.attributes.last_analysis_stats;
    const lastAnalysisDate = response.data.data.attributes.last_analysis_date;
    
    return {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        lastAnalysisDate: lastAnalysisDate ? new Date(lastAnalysisDate * 1000).toLocaleString() : 'N/A',
        hasData: true
    };
}

async function queryAbuseIPDB(ip, apiKey) {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: {
            ipAddress: ip,
            maxAgeInDays: 90,
            verbose: true
        },
        headers: {
            'Key': apiKey,
            'Accept': 'application/json'
        },
        timeout: 15000
    });

    const data = response.data.data;
    
    return {
        abuseConfidenceScore: data.abuseConfidenceScore,
        usageType: data.usageType || 'Unknown',
        isp: data.isp || 'Unknown',
        domain: data.domain || 'N/A',
        country: data.countryCode || 'Unknown',
        totalReports: data.totalReports,
        lastReportedAt: data.lastReportedAt || 'Never',
        isWhitelisted: data.isWhitelisted || false,
        hasData: true
    };
}

async function queryURLScan(indicator, type, apiKey) {
    let searchUrl;
    
    if (type === 'URL') {
        searchUrl = indicator;
    } else if (type === 'Domain') {
        searchUrl = `http://${indicator}`;
    }

    const submitResponse = await axios.post('https://urlscan.io/api/v1/scan/', 
        { url: searchUrl },
        {
            headers: { 'API-Key': apiKey },
            timeout: 15000
        }
    );

    const scanId = submitResponse.data.uuid;
    
    await new Promise(resolve => setTimeout(resolve, 10000));

    const resultResponse = await axios.get(`https://urlscan.io/api/v1/result/${scanId}/`, {
        timeout: 15000
    });

    const result = resultResponse.data;
    
    return {
        verdict: result.verdicts?.overall?.score > 50 ? 'Malicious' : 'Clean',
        score: result.verdicts?.overall?.score || 0,
        malicious: result.verdicts?.overall?.malicious || false,
        categories: result.verdicts?.overall?.categories || [],
        brands: result.verdicts?.overall?.brands || [],
        screenshot: result.task?.screenshotURL || null,
        hasData: true
    };
}

async function queryGreyNoise(ip, apiKey) {
    const response = await axios.get(`https://api.greynoise.io/v3/community/${ip}`, {
        headers: { 'key': apiKey },
        timeout: 15000
    });

    const data = response.data;
    
    return {
        classification: data.classification || 'unknown',
        name: data.name || 'Unknown',
        link: data.link || null,
        lastSeen: data.last_seen || 'Never',
        message: data.message || 'No additional information',
        hasData: data.classification !== 'unknown'
    };
}

async function queryShodan(ip, apiKey) {
    try {
        const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
            params: { key: apiKey },
            timeout: 15000
        });

        const data = response.data;
        
        const ports = data.ports || [];
        const services = (data.data || []).slice(0, 5).map(service => ({
            port: service.port,
            protocol: service.transport || 'tcp',
            product: service.product || 'Unknown',
            version: service.version || '',
            banner: service.data ? service.data.substring(0, 200) : ''
        }));

        const vulns = data.vulns || {};
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
            vulnCount: topVulns.length,
            lastUpdate: data.last_update || 'N/A',
            hostnames: data.hostnames || [],
            tags: data.tags || [],
            hasData: true
        };
    } catch (error) {
        return {
            message: 'No information available for this IP',
            hasData: false,
            error: 'not_found'
        };
    }
}

async function queryAlienVault(indicator, type, apiKey) {
    try {
        let endpoint;
        
        switch (type) {
            case 'IP':
                endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general`;
                break;
            case 'Domain':
                endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${indicator}/general`;
                break;
            case 'URL':
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
            headers: { 'X-OTX-API-KEY': apiKey },
            timeout: 15000
        });

        const data = response.data;
        
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

        const validations = data.validation || [];
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

async function queryMXToolbox(ip, apiKey) {
    try {
        const response = await axios.get(`https://mxtoolbox.com/api/v1/Lookup/whois`, {
            params: { argument: ip },
            headers: { 
                'Authorization': apiKey
            },
            timeout: 15000
        });

        const data = response.data;
        
        const info = data.Information || [];
        const failed = data.Failed || [];
        const relatedIP = data.RelatedIP || [];
        
        let organization = 'Unknown';
        let netRange = 'N/A';
        let netName = 'N/A';
        let country = 'N/A';
        let registrationDate = 'N/A';
        let updated = 'N/A';
        let abuseEmail = 'N/A';
        let techEmail = 'N/A';
        
        info.forEach(item => {
            const line = item.Information || '';
            if (line.includes('Organization:')) {
                organization = line.split('Organization:')[1]?.trim() || organization;
            }
            if (line.includes('OrgName:')) {
                organization = line.split('OrgName:')[1]?.trim() || organization;
            }
            if (line.includes('NetRange:')) {
                netRange = line.split('NetRange:')[1]?.trim() || netRange;
            }
            if (line.includes('CIDR:')) {
                const cidr = line.split('CIDR:')[1]?.trim();
                if (cidr && netRange === 'N/A') {
                    netRange = cidr;
                }
            }
            if (line.includes('NetName:')) {
                netName = line.split('NetName:')[1]?.trim() || netName;
            }
            if (line.includes('Country:')) {
                country = line.split('Country:')[1]?.trim() || country;
            }
            if (line.includes('RegDate:')) {
                registrationDate = line.split('RegDate:')[1]?.trim() || registrationDate;
            }
            if (line.includes('Updated:')) {
                updated = line.split('Updated:')[1]?.trim() || updated;
            }
            if (line.includes('OrgAbuseEmail:')) {
                abuseEmail = line.split('OrgAbuseEmail:')[1]?.trim() || abuseEmail;
            }
            if (line.includes('OrgTechEmail:')) {
                techEmail = line.split('OrgTechEmail:')[1]?.trim() || techEmail;
            }
        });

        return {
            organization: organization,
            netRange: netRange,
            netName: netName,
            country: country,
            registrationDate: registrationDate,
            updated: updated,
            abuseContact: abuseEmail,
            techContact: techEmail,
            relatedIPs: relatedIP.slice(0, 5),
            rawInfo: info.slice(0, 20).map(i => i.Information || ''),
            hasData: info.length > 0 && !failed.length,
            failed: failed.length > 0,
            failedMessage: failed.length > 0 ? failed[0].Failed : null
        };
    } catch (error) {
        return {
            organization: 'Unknown',
            netRange: 'N/A',
            netName: 'N/A',
            country: 'N/A',
            registrationDate: 'N/A',
            updated: 'N/A',
            abuseContact: 'N/A',
            techContact: 'N/A',
            relatedIPs: [],
            rawInfo: [],
            hasData: false,
            error: true,
            errorMessage: error.response?.status === 404 
                ? 'IP not found in ARIN database' 
                : `Query failed: ${error.message || 'Unknown error'}`,
            errorCode: error.response?.status || 'timeout'
        };
    }
}
