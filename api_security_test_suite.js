/**
 * API Security Test Suite
 * Comprehensive testing framework for API vulnerabilities
 * Tests authentication bypass, authorization flaws, and data manipulation
 */

class APISecurityTestSuite {
    constructor() {
        this.testId = 'API_TEST_' + Date.now();
        this.baseURL = window.location.origin;
        this.testResults = [];
        this.discoveredAPIs = [];
        this.vulnerableEndpoints = [];
        this.testConfig = {
            timeout: 10000,
            maxRetries: 3,
            delayBetweenTests: 500,
            enableBruteForce: true,
            enableFuzzing: true
        };
    }

    /**
     * Initialize API security test suite
     */
    async initializeTestSuite() {
        console.log('[API TEST] Initializing API security test suite');

        // Discover API endpoints
        await this.discoverAPIEndpoints();

        // Register test categories
        this.registerAuthenticationTests();
        this.registerAuthorizationTests();
        this.registerInputValidationTests();
        this.registerBusinessLogicTests();
        this.registerRateLimitingTests();

        console.log(`[API TEST] Discovered ${this.discoveredAPIs.length} API endpoints`);
        console.log(`[API TEST] Registered ${this.getTestCount()} security tests`);
    }

    /**
     * Discover API endpoints through multiple methods
     */
    async discoverAPIEndpoints() {
        console.log('[API TEST] Discovering API endpoints');

        // Method 1: Extract from JavaScript
        await this.extractAPIsFromJavaScript();

        // Method 2: Brute force common endpoints
        if (this.testConfig.enableBruteForce) {
            await this.bruteForceCommonEndpoints();
        }

        // Method 3: Analyze network traffic
        this.setupNetworkInterception();

        // Method 4: Check for API documentation
        await this.discoverAPIDocumentation();
    }

    /**
     * Extract API endpoints from JavaScript code
     */
    async extractAPIsFromJavaScript() {
        const apiPatterns = [
            /\/api\/v?\d*\/[a-zA-Z0-9\/_-]+/g,
            /\/rest\/[a-zA-Z0-9\/_-]+/g,
            /\/graphql\/?/g,
            /\/webhook\/[a-zA-Z0-9\/_-]+/g,
            /https?:\/\/[^\/\s]+\/api\/[a-zA-Z0-9\/_-]+/g
        ];

        // Search in all script elements
        const scripts = document.querySelectorAll('script');
        const foundEndpoints = new Set();

        scripts.forEach(script => {
            const content = script.innerHTML || script.textContent;
            if (content) {
                apiPatterns.forEach(pattern => {
                    const matches = content.match(pattern);
                    if (matches) {
                        matches.forEach(match => foundEndpoints.add(match));
                    }
                });
            }
        });

        // Add discovered endpoints
        foundEndpoints.forEach(endpoint => {
            this.addDiscoveredAPI(endpoint, 'javascript_extraction');
        });

        console.log(`[API TEST] Extracted ${foundEndpoints.size} endpoints from JavaScript`);
    }

    /**
     * Brute force common API endpoints
     */
    async bruteForceCommonEndpoints() {
        console.log('[API TEST] Brute forcing common API endpoints');

        const commonEndpoints = [
            // Authentication & Authorization
            '/api/auth/login', '/api/auth/logout', '/api/auth/refresh', '/api/auth/register',
            '/api/oauth/token', '/api/oauth/authorize', '/api/sso/login',
            
            // User Management
            '/api/users', '/api/users/me', '/api/users/profile', '/api/customers',
            '/api/accounts', '/api/profiles', '/api/user/settings',
            
            // Administrative
            '/api/admin', '/api/admin/users', '/api/admin/settings', '/api/admin/logs',
            '/api/system', '/api/health', '/api/status', '/api/config',
            
            // Business Logic
            '/api/vehicles', '/api/models', '/api/inventory', '/api/catalog',
            '/api/orders', '/api/bookings', '/api/reservations', '/api/appointments',
            
            // Financial
            '/api/payments', '/api/billing', '/api/transactions', '/api/invoices',
            '/api/pricing', '/api/quotes', '/api/financing',
            
            // Data & Analytics
            '/api/analytics', '/api/reports', '/api/export', '/api/import',
            '/api/search', '/api/recommendations',
            
            // File & Media
            '/api/files', '/api/upload', '/api/download', '/api/media',
            '/api/images', '/api/documents',
            
            // Versioned APIs
            '/api/v1', '/api/v2', '/api/v3', '/v1/api', '/v2/api', '/v3/api'
        ];

        const batchSize = 5; // Process in batches to avoid overwhelming server
        
        for (let i = 0; i < commonEndpoints.length; i += batchSize) {
            const batch = commonEndpoints.slice(i, i + batchSize);
            const promises = batch.map(endpoint => this.testEndpointExistence(endpoint));
            
            await Promise.allSettled(promises);
            await this.sleep(this.testConfig.delayBetweenTests);
        }
    }

    /**
     * Test if API endpoint exists
     */
    async testEndpointExistence(endpoint) {
        const fullURL = this.baseURL + endpoint;
        const methods = ['GET', 'POST', 'OPTIONS'];

        for (const method of methods) {
            try {
                const response = await fetch(fullURL, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' }
                });

                // Consider endpoint as existing if not 404
                if (response.status !== 404) {
                    this.addDiscoveredAPI(fullURL, 'brute_force', {
                        method: method,
                        status: response.status,
                        headers: Object.fromEntries(response.headers.entries())
                    });
                    break; // Found the endpoint, no need to test other methods
                }
            } catch (e) {
                // Network error or CORS - endpoint might still exist
            }
        }
    }

    /**
     * Add discovered API to collection
     */
    addDiscoveredAPI(endpoint, source, metadata = {}) {
        const normalizedEndpoint = endpoint.startsWith('http') ? endpoint : this.baseURL + endpoint;
        
        const existing = this.discoveredAPIs.find(api => api.endpoint === normalizedEndpoint);
        if (!existing) {
            this.discoveredAPIs.push({
                endpoint: normalizedEndpoint,
                source: source,
                metadata: metadata,
                discovered_at: Date.now(),
                tested: false
            });
        }
    }

    /**
     * Register authentication bypass tests
     */
    registerAuthenticationTests() {
        this.authenticationTests = [
            {
                name: 'Missing Authentication',
                test: async (api) => await this.testMissingAuthentication(api)
            },
            {
                name: 'Weak Authentication',
                test: async (api) => await this.testWeakAuthentication(api)
            },
            {
                name: 'Authentication Bypass via Headers',
                test: async (api) => await this.testAuthBypassHeaders(api)
            },
            {
                name: 'JWT Token Manipulation',
                test: async (api) => await this.testJWTManipulation(api)
            },
            {
                name: 'Session Fixation',
                test: async (api) => await this.testSessionFixation(api)
            }
        ];
    }

    /**
     * Test for missing authentication
     */
    async testMissingAuthentication(api) {
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
        const results = [];

        for (const method of methods) {
            try {
                const response = await fetch(api.endpoint, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' }
                });

                // Check if request succeeded without authentication
                if (response.status === 200) {
                    const responseText = await response.text();
                    results.push({
                        method: method,
                        status: response.status,
                        vulnerable: true,
                        response_snippet: responseText.substring(0, 200),
                        severity: 'high'
                    });
                }
            } catch (e) {
                // Request failed
            }
        }

        return {
            vulnerable: results.some(r => r.vulnerable),
            details: results,
            recommendation: results.length > 0 ? 'Implement proper authentication for all API endpoints' : null
        };
    }

    /**
     * Test authentication bypass via headers
     */
    async testAuthBypassHeaders(api) {
        const bypassHeaders = [
            { 'X-Forwarded-For': '127.0.0.1' },
            { 'X-Real-IP': '127.0.0.1' },
            { 'X-Originating-IP': '127.0.0.1' },
            { 'X-Admin': 'true' },
            { 'X-Internal': 'true' },
            { 'X-Debug': 'true' },
            { 'X-User-ID': '1' },
            { 'X-Role': 'admin' },
            { 'Authorization': 'Bearer admin' },
            { 'Authorization': 'Bearer test' },
            { 'Authorization': 'Basic YWRtaW46YWRtaW4=' }, // admin:admin
        ];

        const results = [];

        for (const headers of bypassHeaders) {
            try {
                const response = await fetch(api.endpoint, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        ...headers
                    }
                });

                if (response.status === 200) {
                    const responseText = await response.text();
                    results.push({
                        bypass_headers: headers,
                        status: response.status,
                        vulnerable: true,
                        response_snippet: responseText.substring(0, 200),
                        severity: 'critical'
                    });
                }
            } catch (e) {
                // Bypass attempt failed
            }
        }

        return {
            vulnerable: results.length > 0,
            details: results,
            recommendation: results.length > 0 ? 'Remove authentication bypass via headers' : null
        };
    }

    /**
     * Register authorization tests
     */
    registerAuthorizationTests() {
        this.authorizationTests = [
            {
                name: 'Horizontal Privilege Escalation',
                test: async (api) => await this.testHorizontalPrivilegeEscalation(api)
            },
            {
                name: 'Vertical Privilege Escalation',
                test: async (api) => await this.testVerticalPrivilegeEscalation(api)
            },
            {
                name: 'IDOR (Insecure Direct Object Reference)',
                test: async (api) => await this.testIDOR(api)
            },
            {
                name: 'Role-Based Access Control Bypass',
                test: async (api) => await this.testRBACBypass(api)
            }
        ];
    }

    /**
     * Test for IDOR vulnerabilities
     */
    async testIDOR(api) {
        // Test common IDOR patterns
        const idorPatterns = [
            { original: '/1', test: '/2' },
            { original: '/user/1', test: '/user/2' },
            { original: '/customer/1', test: '/customer/2' },
            { original: '?id=1', test: '?id=2' },
            { original: '?userId=1', test: '?userId=2' },
            { original: '?customerId=1', test: '?customerId=2' }
        ];

        const results = [];

        for (const pattern of idorPatterns) {
            if (api.endpoint.includes(pattern.original)) {
                const testEndpoint = api.endpoint.replace(pattern.original, pattern.test);
                
                try {
                    const response = await fetch(testEndpoint, {
                        method: 'GET',
                        headers: { 'Content-Type': 'application/json' }
                    });

                    if (response.status === 200) {
                        const responseText = await response.text();
                        results.push({
                            original_endpoint: api.endpoint,
                            test_endpoint: testEndpoint,
                            pattern: pattern,
                            status: response.status,
                            vulnerable: true,
                            response_snippet: responseText.substring(0, 200),
                            severity: 'high'
                        });
                    }
                } catch (e) {
                    // IDOR test failed
                }
            }
        }

        return {
            vulnerable: results.length > 0,
            details: results,
            recommendation: results.length > 0 ? 'Implement proper authorization checks for object access' : null
        };
    }

    /**
     * Register input validation tests
     */
    registerInputValidationTests() {
        this.inputValidationTests = [
            {
                name: 'SQL Injection',
                test: async (api) => await this.testSQLInjection(api)
            },
            {
                name: 'NoSQL Injection',
                test: async (api) => await this.testNoSQLInjection(api)
            },
            {
                name: 'Command Injection',
                test: async (api) => await this.testCommandInjection(api)
            },
            {
                name: 'XXE (XML External Entity)',
                test: async (api) => await this.testXXE(api)
            },
            {
                name: 'JSON Injection',
                test: async (api) => await this.testJSONInjection(api)
            }
        ];
    }

    /**
     * Test for SQL injection vulnerabilities
     */
    async testSQLInjection(api) {
        const sqlPayloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "' UNION SELECT NULL,NULL,NULL--",
            "admin'--",
            "' OR 'x'='x",
            "1' OR '1'='1' /*"
        ];

        const results = [];

        // Test in URL parameters
        for (const payload of sqlPayloads) {
            const testURL = api.endpoint + (api.endpoint.includes('?') ? '&' : '?') + `test=${encodeURIComponent(payload)}`;
            
            try {
                const response = await fetch(testURL, {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json' }
                });

                const responseText = await response.text();
                
                // Check for SQL error indicators
                const sqlErrorPatterns = [
                    /SQL syntax.*MySQL/i,
                    /Warning.*mysql_/i,
                    /valid MySQL result/i,
                    /PostgreSQL.*ERROR/i,
                    /Warning.*pg_/i,
                    /valid PostgreSQL result/i,
                    /Microsoft.*ODBC.*SQL Server/i,
                    /OLE DB.*SQL Server/i,
                    /SQLServer JDBC Driver/i,
                    /Oracle error/i,
                    /Oracle.*ORA-\d+/i,
                    /Microsoft JET Database/i
                ];

                const hasError = sqlErrorPatterns.some(pattern => pattern.test(responseText));
                
                if (hasError) {
                    results.push({
                        payload: payload,
                        test_url: testURL,
                        vulnerable: true,
                        error_detected: true,
                        response_snippet: responseText.substring(0, 300),
                        severity: 'critical'
                    });
                }
            } catch (e) {
                // Request failed
            }
        }

        // Test in POST body
        for (const payload of sqlPayloads) {
            try {
                const response = await fetch(api.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: payload,
                        email: payload,
                        search: payload
                    })
                });

                const responseText = await response.text();
                const sqlErrorPatterns = [
                    /SQL syntax.*MySQL/i,
                    /PostgreSQL.*ERROR/i,
                    /Microsoft.*ODBC.*SQL Server/i,
                    /Oracle error/i
                ];

                const hasError = sqlErrorPatterns.some(pattern => pattern.test(responseText));
                
                if (hasError) {
                    results.push({
                        payload: payload,
                        method: 'POST',
                        vulnerable: true,
                        error_detected: true,
                        response_snippet: responseText.substring(0, 300),
                        severity: 'critical'
                    });
                }
            } catch (e) {
                // Request failed
            }
        }

        return {
            vulnerable: results.length > 0,
            details: results,
            recommendation: results.length > 0 ? 'Implement parameterized queries and input validation' : null
        };
    }

    /**
     * Register business logic tests
     */
    registerBusinessLogicTests() {
        this.businessLogicTests = [
            {
                name: 'Price Manipulation',
                test: async (api) => await this.testPriceManipulation(api)
            },
            {
                name: 'Quantity Manipulation',
                test: async (api) => await this.testQuantityManipulation(api)
            },
            {
                name: 'Workflow Bypass',
                test: async (api) => await this.testWorkflowBypass(api)
            },
            {
                name: 'Race Conditions',
                test: async (api) => await this.testRaceConditions(api)
            }
        ];
    }

    /**
     * Test for price manipulation vulnerabilities
     */
    async testPriceManipulation(api) {
        const priceFields = ['price', 'amount', 'total', 'cost', 'value'];
        const results = [];

        for (const field of priceFields) {
            try {
                // Test negative prices
                const negativeResponse = await fetch(api.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        [field]: -100,
                        quantity: 1
                    })
                });

                if (negativeResponse.status === 200) {
                    results.push({
                        field: field,
                        test_value: -100,
                        vulnerable: true,
                        issue: 'Negative price accepted',
                        severity: 'high'
                    });
                }

                // Test zero prices
                const zeroResponse = await fetch(api.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        [field]: 0,
                        quantity: 1
                    })
                });

                if (zeroResponse.status === 200) {
                    results.push({
                        field: field,
                        test_value: 0,
                        vulnerable: true,
                        issue: 'Zero price accepted',
                        severity: 'medium'
                    });
                }

                // Test extremely small prices
                const smallResponse = await fetch(api.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        [field]: 0.01,
                        quantity: 1000
                    })
                });

                if (smallResponse.status === 200) {
                    results.push({
                        field: field,
                        test_value: 0.01,
                        vulnerable: true,
                        issue: 'Extremely small price accepted',
                        severity: 'medium'
                    });
                }

            } catch (e) {
                // Test failed
            }
        }

        return {
            vulnerable: results.length > 0,
            details: results,
            recommendation: results.length > 0 ? 'Implement proper price validation and business logic checks' : null
        };
    }

    /**
     * Run comprehensive API security test
     */
    async runComprehensiveTest() {
        console.log('[API TEST] Starting comprehensive API security test');
        
        await this.initializeTestSuite();
        
        const testCategories = [
            { name: 'Authentication', tests: this.authenticationTests },
            { name: 'Authorization', tests: this.authorizationTests },
            { name: 'Input Validation', tests: this.inputValidationTests },
            { name: 'Business Logic', tests: this.businessLogicTests }
        ];

        for (const api of this.discoveredAPIs) {
            console.log(`[API TEST] Testing API: ${api.endpoint}`);
            
            for (const category of testCategories) {
                for (const test of category.tests) {
                    try {
                        const result = await test.test(api);
                        
                        this.testResults.push({
                            api: api.endpoint,
                            category: category.name,
                            test_name: test.name,
                            result: result,
                            timestamp: Date.now()
                        });

                        if (result.vulnerable) {
                            this.vulnerableEndpoints.push({
                                endpoint: api.endpoint,
                                vulnerability: test.name,
                                category: category.name,
                                details: result
                            });
                        }

                    } catch (e) {
                        console.error(`[API TEST] Test failed: ${test.name} on ${api.endpoint}`, e.message);
                    }
                }
            }
            
            api.tested = true;
            await this.sleep(this.testConfig.delayBetweenTests);
        }

        return this.generateAPITestReport();
    }

    /**
     * Generate comprehensive API test report
     */
    generateAPITestReport() {
        const vulnerableTests = this.testResults.filter(r => r.result.vulnerable);
        const safeTests = this.testResults.filter(r => !r.result.vulnerable);

        const severityBreakdown = {
            critical: vulnerableTests.filter(t => t.result.details?.some(d => d.severity === 'critical')).length,
            high: vulnerableTests.filter(t => t.result.details?.some(d => d.severity === 'high')).length,
            medium: vulnerableTests.filter(t => t.result.details?.some(d => d.severity === 'medium')).length,
            low: vulnerableTests.filter(t => t.result.details?.some(d => d.severity === 'low')).length
        };

        const report = {
            test_id: this.testId,
            timestamp: Date.now(),
            summary: {
                apis_discovered: this.discoveredAPIs.length,
                apis_tested: this.discoveredAPIs.filter(api => api.tested).length,
                total_tests: this.testResults.length,
                vulnerable_endpoints: this.vulnerableEndpoints.length,
                safe_tests: safeTests.length
            },
            severity_breakdown: severityBreakdown,
            vulnerable_endpoints: this.vulnerableEndpoints,
            discovered_apis: this.discoveredAPIs,
            test_results: this.testResults,
            recommendations: this.generateAPIRecommendations()
        };

        console.log('[API TEST] API Security Test Report:', report.summary);
        return report;
    }

    /**
     * Generate API security recommendations
     */
    generateAPIRecommendations() {
        const recommendations = [];

        // Authentication recommendations
        const authIssues = this.vulnerableEndpoints.filter(v => v.category === 'Authentication');
        if (authIssues.length > 0) {
            recommendations.push({
                category: 'Authentication',
                priority: 'critical',
                recommendation: 'Implement proper authentication for all API endpoints',
                affected_endpoints: authIssues.length
            });
        }

        // Authorization recommendations
        const authzIssues = this.vulnerableEndpoints.filter(v => v.category === 'Authorization');
        if (authzIssues.length > 0) {
            recommendations.push({
                category: 'Authorization',
                priority: 'high',
                recommendation: 'Implement proper authorization checks and prevent privilege escalation',
                affected_endpoints: authzIssues.length
            });
        }

        // Input validation recommendations
        const inputIssues = this.vulnerableEndpoints.filter(v => v.category === 'Input Validation');
        if (inputIssues.length > 0) {
            recommendations.push({
                category: 'Input Validation',
                priority: 'critical',
                recommendation: 'Implement comprehensive input validation and sanitization',
                affected_endpoints: inputIssues.length
            });
        }

        return recommendations;
    }

    /**
     * Utility functions
     */
    getTestCount() {
        return (this.authenticationTests?.length || 0) +
               (this.authorizationTests?.length || 0) +
               (this.inputValidationTests?.length || 0) +
               (this.businessLogicTests?.length || 0);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Execute API security test suite
     */
    async execute() {
        try {
            console.log('[API TEST] Starting API security test suite');
            const report = await this.runComprehensiveTest();
            console.log('[API TEST] API security testing completed');
            return report;
        } catch (error) {
            console.error('[API TEST] Test suite execution failed:', error);
            throw error;
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    const apiTestSuite = new APISecurityTestSuite();
    apiTestSuite.execute().then(report => {
        console.log('[API TEST] Final API Security Report:', report);
    });
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APISecurityTestSuite;
}