const { app } = require('@azure/functions');
const axios = require('axios');

app.http('EnrichIOC', {
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous', // No function key required
    handler: async (request, context) => {
        context.log('EnrichIOC function triggered');

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
            const { indicator, incidentId, clientName } = body;

            if (!indicator) {
                return {
                    status: 400,
                    jsonBody: { error: 'Missing indicator field' }
                };
            }

            context.log(`Enriching indicator: ${indicator} for incident: ${incidentId || 'N/A'}, client: ${clientName || 'N/A'}`);

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

            // Query all available sources
            const promises = [];

            if (vtApiKey) {
                promises.push(
                    queryVirusTotal(indicator, indicatorType, vtApiKey)
                        .then(data => { results.virusTotal = data; })
                        .catch(error => { 
                            context.log.error('VirusTotal error:', error.message);
                            results.virusTotal = { error: error.message }; 
                        })
                );
            }

            if (indicatorType === 'IP' && aipdbApiKey) {
                promises.push(
                    queryAbuseIPDB(indicator, aipdbApiKey)
                        .then(data => { results.abuseIPDB = data; })
                        .catch(error => { 
                            context.log.error('AbuseIPDB error:', error.message);
                            results.abuseIPDB = { error: error.message }; 
                        })
                );
            }

            if ((indicatorType === 'URL' || indicatorType === 'Domain') && urlscanApiKey) {
                promises.push(
                    queryURLScan(indicator, indicatorType, urlscanApiKey)
                        .then(data => { results.urlScan = data; })
                        .catch(error => { 
                            context.log.error('URLScan error:', error.message);
                            results.urlScan = { error: error.message }; 
                        })
                );
            }

            if (indicatorType === 'IP' && greynoiseApiKey) {
                promises.push(
                    queryGreyNoise(indicator, greynoiseApiKey)
                        .then(data => { results.greyNoise = data; })
                        .catch(error => { 
                            context.log.error('GreyNoise error:', error.message);
                            results.greyNoise = { error: error.message }; 
                        })
                );
            }

            if (indicatorType === 'IP' && shodanApiKey) {
                promises.push(
                    queryShodan(indicator, shodanApiKey)
                        .then(data => { results.shodan = data; })
                        .catch(error => { 
                            context.log.error('Shodan error:', error.message);
                            results.shodan = { error: error.message }; 
                        })
                );
            }

            if (otxApiKey) {
                promises.push(
                    queryAlienVault(indicator, indicatorType, otxApiKey)
                        .then(data => { results.alienVault = data; })
                        .catch(error => { 
                            context.log.error('AlienVault OTX error:', error.message);
                            results.alienVault = { error: error.message }; 
                        })
                );
            }

            // Wait for all queries to complete
            await Promise.all(promises);

            // Calculate risk score
            const riskScore = calculateRiskScore(results);
            const verdict = getVerdict(riskScore);

            // Generate formatted incident comment
            const incidentComment = generateIncidentComment(results, riskScore, verdict, incidentId, clientName);

            // Return enriched data
            return {
                status: 200,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: {
                    indicator: indicator,
                    type: indicatorType,
                    riskScore: riskScore,
                    verdict: verdict,
                    incidentComment: incidentComment,
                    rawData: results,
                    enrichmentTimestamp: new Date().toISOString(),
                    incidentId: incidentId || null,
                    clientName: clientName || null
                }
            };

        } catch (error) {
            context.log.error('CRITICAL ERROR in EnrichIOC:', error.message);
            context.log.error('Error stack:', error.stack);
            return {
                status: 500,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                jsonBody: { 
                    error: 'Failed to perform enrichment', 
                    details: error.message 
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

function calculateRiskScore(results) {
    let score = 0;
    let maxScore = 0;

    // VirusTotal scoring (0-30 points)
    if (results.virusTotal && !results.virusTotal.error) {
        maxScore += 30;
        const malicious = results.virusTotal.malicious || 0;
        const suspicious = results.virusTotal.suspicious || 0;
        const total = malicious + suspicious + (results.virusTotal.undetected || 0) + (results.virusTotal.harmless || 0);
        
        if (total > 0) {
            const detectionRate = (malicious + (suspicious * 0.5)) / total;
            score += detectionRate * 30;
        }
    }

    // AbuseIPDB scoring (0-25 points)
    if (results.abuseIPDB && !results.abuseIPDB.error) {
        maxScore += 25;
        const abuseScore = results.abuseIPDB.abuseScore || 0;
        score += (abuseScore / 100) * 25;
    }

    // GreyNoise scoring (0-20 points)
    if (results.greyNoise && !results.greyNoise.error) {
        maxScore += 20;
        if (results.greyNoise.classification === 'malicious') {
            score += 20;
        } else if (results.greyNoise.classification === 'benign') {
            score += 0; // Actually reduces risk
        } else if (results.greyNoise.noise === true) {
            score += 10; // Noise is suspicious but not necessarily malicious
        }
    }

    // URLScan scoring (0-15 points)
    if (results.urlScan && !results.urlScan.error && !results.urlScan.scanning) {
        maxScore += 15;
        if (results.urlScan.verdictMalicious) {
            score += 15;
        }
        // Add partial score based on URLScan score
        score += (results.urlScan.score || 0) / 100 * 5;
    }

    // AlienVault OTX scoring (0-20 points)
    if (results.alienVault && results.alienVault.hasData && !results.alienVault.error) {
        maxScore += 20;
        const pulseCount = results.alienVault.pulseCount || 0;
        if (pulseCount > 0) {
            score += Math.min(pulseCount * 4, 20); // 4 points per pulse, max 20
        }
    }

    // Shodan scoring (0-10 points) - presence of vulnerabilities
    if (results.shodan && results.shodan.hasData && !results.shodan.error) {
        maxScore += 10;
        const vulnCount = results.shodan.vulnCount || 0;
        if (vulnCount > 0) {
            score += Math.min(vulnCount * 2, 10); // 2 points per vuln, max 10
        }
    }

    // Normalize to 0-100 scale
    if (maxScore === 0) return 0;
    return Math.min(Math.round((score / maxScore) * 100), 100);
}

function getVerdict(riskScore) {
    if (riskScore >= 80) return 'MALICIOUS';
    if (riskScore >= 60) return 'HIGHLY SUSPICIOUS';
    if (riskScore >= 40) return 'SUSPICIOUS';
    if (riskScore >= 20) return 'POTENTIALLY SUSPICIOUS';
    return 'LIKELY BENIGN';
}

function generateIncidentComment(results, riskScore, verdict, incidentId, clientName) {
    let comment = '## 🔍 Automated Threat Intelligence Enrichment\n\n';
    
    if (clientName) {
        comment += `**Client:** ${clientName}\n`;
    }
    if (incidentId) {
        comment += `**Incident:** ${incidentId}\n`;
    }
    
    comment += `**Indicator:** \`${results.indicator}\` (${results.type})\n`;
    comment += `**Risk Score:** ${riskScore}/100\n`;
    comment += `**Verdict:** **${verdict}**\n\n`;
    
    comment += '---\n\n';
    
    // VirusTotal
    if (results.virusTotal && !results.virusTotal.error) {
        const malicious = results.virusTotal.malicious || 0;
        const total = malicious + (results.virusTotal.suspicious || 0) + (results.virusTotal.undetected || 0) + (results.virusTotal.harmless || 0);
        comment += `### 🛡️ VirusTotal\n`;
        if (malicious > 0) {
            comment += `⚠️ **${malicious}/${total} detections - MALICIOUS**\n\n`;
        } else {
            comment += `✅ Clean (0/${total} detections)\n\n`;
        }
    }
    
    // AbuseIPDB
    if (results.abuseIPDB && !results.abuseIPDB.error) {
        comment += `### 🚨 AbuseIPDB\n`;
        comment += `- Abuse Confidence: **${results.abuseIPDB.abuseScore}%**\n`;
        comment += `- Total Reports: ${results.abuseIPDB.totalReports}\n`;
        comment += `- Country: ${results.abuseIPDB.countryCode}\n`;
        comment += `- ISP: ${results.abuseIPDB.isp}\n\n`;
    }
    
    // GreyNoise
    if (results.greyNoise && !results.greyNoise.error) {
        comment += `### 🌐 GreyNoise\n`;
        comment += `- Classification: **${results.greyNoise.classification.toUpperCase()}**\n`;
        if (results.greyNoise.riot) {
            comment += `- 🏢 RIOT: Common Business Service (likely benign)\n`;
        }
        if (results.greyNoise.noise) {
            comment += `- 🔊 Internet Noise Detected\n`;
        }
        if (results.greyNoise.name && results.greyNoise.name !== 'N/A') {
            comment += `- Name: ${results.greyNoise.name}\n`;
        }
        comment += '\n';
    }
    
    // URLScan
    if (results.urlScan && !results.urlScan.error && !results.urlScan.scanning) {
        comment += `### 🔎 URLScan.io\n`;
        if (results.urlScan.verdictMalicious) {
            comment += `⚠️ **MALICIOUS** (Score: ${results.urlScan.score})\n`;
        } else {
            comment += `✅ Clean (Score: ${results.urlScan.score})\n`;
        }
        if (results.urlScan.reportUrl) {
            comment += `- [View Full Report](${results.urlScan.reportUrl})\n`;
        }
        comment += '\n';
    }
    
    // AlienVault OTX
    if (results.alienVault && results.alienVault.hasData && !results.alienVault.error) {
        comment += `### 🔮 AlienVault OTX\n`;
        comment += `- **${results.alienVault.pulseCount} threat pulses found**\n`;
        
        if (results.alienVault.pulses && results.alienVault.pulses.length > 0) {
            const topPulse = results.alienVault.pulses[0];
            
            if (topPulse.malwareFamilies && topPulse.malwareFamilies.length > 0) {
                const families = topPulse.malwareFamilies
                    .map(f => typeof f === 'string' ? f : (f.display_name || f.name || 'Unknown'))
                    .join(', ');
                comment += `- 🦠 **Malware Families:** ${families}\n`;
            }
            
            if (topPulse.adversary) {
                const adversary = typeof topPulse.adversary === 'string' ? topPulse.adversary : JSON.stringify(topPulse.adversary);
                comment += `- 🎯 **Threat Actor:** ${adversary}\n`;
            }
            
            if (topPulse.name) {
                comment += `- Campaign: "${topPulse.name}"\n`;
            }
        }
        comment += '\n';
    }
    
    // Shodan
    if (results.shodan && results.shodan.hasData && !results.shodan.error) {
        comment += `### 🔍 Shodan\n`;
        comment += `- Open Ports: ${results.shodan.openPortsCount}\n`;
        if (results.shodan.vulnCount > 0) {
            comment += `- ⚠️ **Vulnerabilities: ${results.shodan.vulnCount}**\n`;
        }
        if (results.shodan.organization) {
            comment += `- Organization: ${results.shodan.organization}\n`;
        }
        comment += '\n';
    }
    
    // Recommendations
    comment += '---\n\n';
    comment += '### 📌 Recommended Actions\n\n';
    
    if (riskScore >= 80) {
        comment += '🔴 **IMMEDIATE ACTION REQUIRED**\n';
        comment += '- Block indicator in firewalls and EDR\n';
        comment += '- Hunt for related activity in environment\n';
        comment += '- Create custom Defender indicator\n';
        comment += '- Escalate to Tier 2/3 for investigation\n';
    } else if (riskScore >= 60) {
        comment += '🟠 **HIGH PRIORITY**\n';
        comment += '- Investigate related alerts\n';
        comment += '- Consider blocking if confirmed malicious\n';
        comment += '- Monitor for additional activity\n';
    } else if (riskScore >= 40) {
        comment += '🟡 **MEDIUM PRIORITY**\n';
        comment += '- Review context of detection\n';
        comment += '- Monitor for suspicious behavior\n';
        comment += '- Correlate with other security events\n';
    } else if (riskScore >= 20) {
        comment += '🟢 **LOW PRIORITY**\n';
        comment += '- Minimal threat indicators found\n';
        comment += '- Review if part of broader pattern\n';
        comment += '- Consider closing if no other concerns\n';
    } else {
        comment += '⚪ **LIKELY SAFE**\n';
        comment += '- No significant threat indicators\n';
        comment += '- Appears to be legitimate traffic\n';
        comment += '- Recommend closing if no other concerns\n';
    }
    
    comment += `\n---\n\n`;
    comment += `*Enrichment completed at ${new Date().toISOString()}*\n`;
    comment += `*Powered by ThreatDefender Automated Enrichment*`;
    
    return comment;
}

// Include all the query functions from ThreatIntelLookup.js
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

        return { scanning: true, message: 'No recent scan data available' };
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
        const ports = data.ports || [];
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
            headers: { 'X-OTX-API-KEY': apiKey }
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
