/**
 * Mobile Security Test Framework
 * Comprehensive testing for mobile app vulnerabilities
 * Tests WebView security, JavaScript bridges, and device access
 */

class MobileSecurityTestFramework {
    constructor() {
        this.testId = 'MOBILE_TEST_' + Date.now();
        this.testResults = [];
        this.vulnerabilities = [];
        this.deviceCapabilities = {};
        this.bridgeTests = [];
        this.isWebView = false;
        this.testConfig = {
            timeout: 8000,
            enableDeviceTests: true,
            enableBridgeTests: true,
            enablePermissionTests: true,
            verbose: true
        };
    }

    /**
     * Initialize mobile security test framework
     */
    async initializeMobileTests() {
        console.log('[MOBILE TEST] Initializing mobile security test framework');

        // Detect mobile environment
        this.detectMobileEnvironment();

        // Discover device capabilities
        await this.discoverDeviceCapabilities();

        // Register test suites
        this.registerWebViewTests();
        this.registerJavaScriptBridgeTests();
        this.registerDeviceAccessTests();
        this.registerPermissionTests();
        this.registerDataStorageTests();

        console.log(`[MOBILE TEST] Environment: ${this.isWebView ? 'WebView' : 'Browser'}`);
        console.log(`[MOBILE TEST] Registered ${this.getTestCount()} mobile security tests`);
    }

    /**
     * Detect mobile environment and WebView
     */
    detectMobileEnvironment() {
        const userAgent = navigator.userAgent;
        
        // WebView detection patterns
        const webViewPatterns = [
            /wv\)/i,                    // Android WebView
            /Version\/.*Mobile.*Safari/i, // iOS WebView
            /PorscheApp/i,              // Custom Porsche app
            /MyPorsche/i,               // My Porsche app
            /PorscheConnect/i           // Porsche Connect app
        ];

        this.isWebView = webViewPatterns.some(pattern => pattern.test(userAgent));
        
        // Mobile platform detection
        this.deviceInfo = {
            userAgent: userAgent,
            platform: navigator.platform,
            isWebView: this.isWebView,
            isMobile: /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent),
            isAndroid: /Android/i.test(userAgent),
            isIOS: /iPhone|iPad|iPod/i.test(userAgent),
            screen: {
                width: screen.width,
                height: screen.height,
                orientation: screen.orientation?.type
            }
        };

        console.log('[MOBILE TEST] Device Info:', this.deviceInfo);
    }

    /**
     * Discover device capabilities and APIs
     */
    async discoverDeviceCapabilities() {
        console.log('[MOBILE TEST] Discovering device capabilities');

        this.deviceCapabilities = {
            // Location services
            geolocation: !!navigator.geolocation,
            
            // Media devices
            mediaDevices: !!navigator.mediaDevices,
            getUserMedia: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
            
            // Device sensors
            deviceOrientation: 'DeviceOrientationEvent' in window,
            deviceMotion: 'DeviceMotionEvent' in window,
            
            // Device features
            vibration: !!navigator.vibrate,
            battery: !!navigator.getBattery,
            clipboard: !!navigator.clipboard,
            share: !!navigator.share,
            
            // Storage
            localStorage: !!window.localStorage,
            sessionStorage: !!window.sessionStorage,
            indexedDB: !!window.indexedDB,
            
            // Network
            connection: !!navigator.connection,
            onLine: navigator.onLine,
            
            // Notifications
            notification: !!window.Notification,
            serviceWorker: !!navigator.serviceWorker,
            
            // JavaScript bridges (discovered separately)
            bridges: this.discoverJavaScriptBridges()
        };

        console.log('[MOBILE TEST] Device capabilities:', this.deviceCapabilities);
    }

    /**
     * Discover JavaScript bridges to native functions
     */
    discoverJavaScriptBridges() {
        const commonBridges = [
            'webkit', 'WebViewJavascriptBridge', 'JSBridge',
            'PorscheBridge', 'MyPorscheBridge', 'ConnectBridge',
            'NativeBridge', 'AppBridge', 'MobileBridge',
            'Android', 'iOS', 'cordova', 'PhoneGap'
        ];

        const discoveredBridges = [];

        commonBridges.forEach(bridgeName => {
            if (window[bridgeName]) {
                const bridgeInfo = {
                    name: bridgeName,
                    type: typeof window[bridgeName],
                    methods: this.extractBridgeMethods(window[bridgeName])
                };
                discoveredBridges.push(bridgeInfo);
                console.log(`[MOBILE TEST] Found bridge: ${bridgeName}`);
            }
        });

        // Check for webkit message handlers (iOS)
        if (window.webkit && window.webkit.messageHandlers) {
            Object.keys(window.webkit.messageHandlers).forEach(handler => {
                discoveredBridges.push({
                    name: `webkit.messageHandlers.${handler}`,
                    type: 'webkit_handler',
                    methods: ['postMessage']
                });
                console.log(`[MOBILE TEST] Found webkit handler: ${handler}`);
            });
        }

        return discoveredBridges;
    }

    /**
     * Extract methods from bridge objects
     */
    extractBridgeMethods(bridgeObject) {
        const methods = [];
        
        try {
            if (typeof bridgeObject === 'object') {
                Object.getOwnPropertyNames(bridgeObject).forEach(prop => {
                    if (typeof bridgeObject[prop] === 'function') {
                        methods.push(prop);
                    }
                });
            }
        } catch (e) {
            console.log('[MOBILE TEST] Error extracting bridge methods:', e.message);
        }

        return methods;
    }

    /**
     * Register WebView security tests
     */
    registerWebViewTests() {
        this.webViewTests = [
            {
                name: 'File URL Access',
                severity: 'high',
                test: async () => await this.testFileURLAccess()
            },
            {
                name: 'Intent URL Schemes',
                severity: 'medium',
                test: async () => await this.testIntentURLSchemes()
            },
            {
                name: 'Custom URL Schemes',
                severity: 'medium',
                test: async () => await this.testCustomURLSchemes()
            },
            {
                name: 'WebView Debugging',
                severity: 'high',
                test: async () => await this.testWebViewDebugging()
            },
            {
                name: 'JavaScript Injection',
                severity: 'critical',
                test: async () => await this.testJavaScriptInjection()
            }
        ];
    }

    /**
     * Test file URL access vulnerability
     */
    async testFileURLAccess() {
        console.log('[MOBILE TEST] Testing file URL access');

        const sensitiveFiles = [
            'file:///android_asset/',
            'file:///data/data/com.porsche.app/',
            'file:///storage/emulated/0/',
            'file:///system/etc/hosts',
            'file:///proc/version',
            'file:///etc/passwd'
        ];

        const results = [];

        for (const fileUrl of sensitiveFiles) {
            try {
                const response = await fetch(fileUrl);
                if (response.ok) {
                    const content = await response.text();
                    results.push({
                        file_url: fileUrl,
                        accessible: true,
                        content_length: content.length,
                        content_snippet: content.substring(0, 100),
                        severity: 'critical'
                    });
                }
            } catch (e) {
                results.push({
                    file_url: fileUrl,
                    accessible: false,
                    error: e.message
                });
            }
        }

        const vulnerableFiles = results.filter(r => r.accessible);

        return {
            vulnerable: vulnerableFiles.length > 0,
            severity: vulnerableFiles.length > 0 ? 'critical' : 'safe',
            details: results,
            recommendation: vulnerableFiles.length > 0 ? 
                'Disable file URL access in WebView configuration' : 
                'File URL access properly restricted'
        };
    }

    /**
     * Register JavaScript bridge tests
     */
    registerJavaScriptBridgeTests() {
        this.bridgeTests = [
            {
                name: 'Bridge Method Enumeration',
                severity: 'medium',
                test: async () => await this.testBridgeMethodEnumeration()
            },
            {
                name: 'Bridge Privilege Escalation',
                severity: 'critical',
                test: async () => await this.testBridgePrivilegeEscalation()
            },
            {
                name: 'Bridge Data Extraction',
                severity: 'high',
                test: async () => await this.testBridgeDataExtraction()
            },
            {
                name: 'Bridge Command Injection',
                severity: 'critical',
                test: async () => await this.testBridgeCommandInjection()
            }
        ];
    }

    /**
     * Test bridge method enumeration
     */
    async testBridgeMethodEnumeration() {
        console.log('[MOBILE TEST] Testing bridge method enumeration');

        const results = [];
        const bridges = this.deviceCapabilities.bridges;

        for (const bridge of bridges) {
            try {
                const bridgeObject = this.getBridgeObject(bridge.name);
                if (bridgeObject) {
                    // Try to enumerate all methods
                    const methods = Object.getOwnPropertyNames(bridgeObject);
                    const functions = methods.filter(method => 
                        typeof bridgeObject[method] === 'function'
                    );

                    results.push({
                        bridge_name: bridge.name,
                        total_methods: methods.length,
                        function_methods: functions.length,
                        methods: functions,
                        enumerable: true,
                        severity: functions.length > 0 ? 'medium' : 'low'
                    });
                }
            } catch (e) {
                results.push({
                    bridge_name: bridge.name,
                    enumerable: false,
                    error: e.message
                });
            }
        }

        const enumerableBridges = results.filter(r => r.enumerable);

        return {
            vulnerable: enumerableBridges.length > 0,
            severity: enumerableBridges.length > 0 ? 'medium' : 'safe',
            details: results,
            recommendation: enumerableBridges.length > 0 ? 
                'Restrict bridge method enumeration and implement proper access controls' : 
                'Bridge enumeration properly restricted'
        };
    }

    /**
     * Test bridge privilege escalation
     */
    async testBridgePrivilegeEscalation() {
        console.log('[MOBILE TEST] Testing bridge privilege escalation');

        const privilegeEscalationPayloads = [
            { action: 'getDeviceInfo' },
            { action: 'requestPermissions', permissions: ['camera', 'microphone', 'location'] },
            { action: 'enableDebug' },
            { action: 'setDeveloperMode', enabled: true },
            { action: 'getSystemInfo' },
            { action: 'executeCommand', command: 'id' },
            { action: 'readFile', path: '/data/data/com.porsche.app/' },
            { action: 'getSharedPreferences' },
            { action: 'getKeychain' }
        ];

        const results = [];
        const bridges = this.deviceCapabilities.bridges;

        for (const bridge of bridges) {
            for (const payload of privilegeEscalationPayloads) {
                try {
                    const result = await this.testBridgeMethod(bridge, payload);
                    if (result.success) {
                        results.push({
                            bridge_name: bridge.name,
                            payload: payload,
                            result: result,
                            vulnerable: true,
                            severity: 'critical'
                        });
                    }
                } catch (e) {
                    // Privilege escalation attempt failed
                }
            }
        }

        return {
            vulnerable: results.length > 0,
            severity: results.length > 0 ? 'critical' : 'safe',
            details: results,
            recommendation: results.length > 0 ? 
                'Implement proper authorization checks for bridge methods' : 
                'Bridge privilege escalation properly prevented'
        };
    }

    /**
     * Test bridge method with payload
     */
    async testBridgeMethod(bridge, payload) {
        const bridgeObject = this.getBridgeObject(bridge.name);
        if (!bridgeObject) return { success: false };

        try {
            let result;
            
            if (bridge.name.includes('webkit.messageHandlers')) {
                // iOS webkit message handler
                result = bridgeObject.postMessage(payload);
            } else if (bridgeObject.call && typeof bridgeObject.call === 'function') {
                // Generic bridge call method
                result = await bridgeObject.call(payload);
            } else if (bridge.methods.includes('invoke')) {
                // Bridge with invoke method
                result = await bridgeObject.invoke(payload);
            }

            return {
                success: !!result,
                result: result,
                method_used: 'postMessage/call/invoke'
            };
        } catch (e) {
            return {
                success: false,
                error: e.message
            };
        }
    }

    /**
     * Get bridge object from window
     */
    getBridgeObject(bridgeName) {
        if (bridgeName.includes('.')) {
            const parts = bridgeName.split('.');
            let obj = window;
            for (const part of parts) {
                obj = obj[part];
                if (!obj) return null;
            }
            return obj;
        }
        return window[bridgeName];
    }

    /**
     * Register device access tests
     */
    registerDeviceAccessTests() {
        this.deviceAccessTests = [
            {
                name: 'Location Access',
                severity: 'high',
                test: async () => await this.testLocationAccess()
            },
            {
                name: 'Camera Access',
                severity: 'high',
                test: async () => await this.testCameraAccess()
            },
            {
                name: 'Microphone Access',
                severity: 'high',
                test: async () => await this.testMicrophoneAccess()
            },
            {
                name: 'Device Sensors',
                severity: 'medium',
                test: async () => await this.testDeviceSensors()
            },
            {
                name: 'Clipboard Access',
                severity: 'medium',
                test: async () => await this.testClipboardAccess()
            }
        ];
    }

    /**
     * Test location access
     */
    async testLocationAccess() {
        console.log('[MOBILE TEST] Testing location access');

        if (!this.deviceCapabilities.geolocation) {
            return {
                vulnerable: false,
                details: { error: 'Geolocation API not available' }
            };
        }

        try {
            const position = await new Promise((resolve, reject) => {
                navigator.geolocation.getCurrentPosition(
                    resolve,
                    reject,
                    { enableHighAccuracy: true, timeout: 5000 }
                );
            });

            return {
                vulnerable: true,
                severity: 'high',
                details: {
                    location_accessed: true,
                    accuracy: position.coords.accuracy,
                    latitude: position.coords.latitude.toFixed(4) + '***', // Partial for privacy
                    longitude: position.coords.longitude.toFixed(4) + '***'
                },
                recommendation: 'Location access granted - ensure proper user consent and data protection'
            };
        } catch (e) {
            return {
                vulnerable: false,
                details: {
                    location_accessed: false,
                    error: e.message
                },
                recommendation: 'Location access properly restricted'
            };
        }
    }

    /**
     * Test camera access
     */
    async testCameraAccess() {
        console.log('[MOBILE TEST] Testing camera access');

        if (!this.deviceCapabilities.getUserMedia) {
            return {
                vulnerable: false,
                details: { error: 'getUserMedia API not available' }
            };
        }

        try {
            const stream = await navigator.mediaDevices.getUserMedia({ 
                video: { facingMode: 'user' } 
            });

            // Stop the stream immediately
            stream.getTracks().forEach(track => track.stop());

            return {
                vulnerable: true,
                severity: 'critical',
                details: {
                    camera_accessed: true,
                    video_tracks: stream.getVideoTracks().length
                },
                recommendation: 'Camera access granted - implement proper permission controls'
            };
        } catch (e) {
            return {
                vulnerable: false,
                details: {
                    camera_accessed: false,
                    error: e.message
                },
                recommendation: 'Camera access properly restricted'
            };
        }
    }

    /**
     * Register data storage tests
     */
    registerDataStorageTests() {
        this.dataStorageTests = [
            {
                name: 'LocalStorage Security',
                severity: 'medium',
                test: async () => await this.testLocalStorageSecurity()
            },
            {
                name: 'SessionStorage Security',
                severity: 'medium',
                test: async () => await this.testSessionStorageSecurity()
            },
            {
                name: 'IndexedDB Security',
                severity: 'medium',
                test: async () => await this.testIndexedDBSecurity()
            },
            {
                name: 'Cookie Security',
                severity: 'high',
                test: async () => await this.testCookieSecurity()
            }
        ];
    }

    /**
     * Test localStorage security
     */
    async testLocalStorageSecurity() {
        console.log('[MOBILE TEST] Testing localStorage security');

        const results = [];
        const sensitiveDataPatterns = [
            /password/i, /token/i, /auth/i, /session/i, /key/i,
            /credit.*card/i, /ssn/i, /social.*security/i
        ];

        // Check existing localStorage data
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);

            // Check for sensitive data patterns
            const hasSensitiveKey = sensitiveDataPatterns.some(pattern => pattern.test(key));
            const hasSensitiveValue = sensitiveDataPatterns.some(pattern => pattern.test(value));

            if (hasSensitiveKey || hasSensitiveValue) {
                results.push({
                    key: key,
                    has_sensitive_key: hasSensitiveKey,
                    has_sensitive_value: hasSensitiveValue,
                    value_length: value.length,
                    vulnerable: true
                });
            }
        }

        // Test if we can store sensitive data
        try {
            const testKey = 'mobile_test_sensitive_data';
            const testValue = 'password123_token_auth_data';
            localStorage.setItem(testKey, testValue);
            
            const retrieved = localStorage.getItem(testKey);
            if (retrieved === testValue) {
                results.push({
                    test: 'sensitive_data_storage',
                    stored_successfully: true,
                    vulnerable: true
                });
            }
            
            // Clean up
            localStorage.removeItem(testKey);
        } catch (e) {
            results.push({
                test: 'sensitive_data_storage',
                stored_successfully: false,
                error: e.message
            });
        }

        const vulnerableItems = results.filter(r => r.vulnerable);

        return {
            vulnerable: vulnerableItems.length > 0,
            severity: vulnerableItems.length > 0 ? 'medium' : 'safe',
            details: {
                total_items: localStorage.length,
                sensitive_items: vulnerableItems.length,
                results: results
            },
            recommendation: vulnerableItems.length > 0 ? 
                'Encrypt sensitive data before storing in localStorage' : 
                'localStorage usage appears secure'
        };
    }

    /**
     * Run comprehensive mobile security test
     */
    async runComprehensiveMobileTest() {
        console.log('[MOBILE TEST] Starting comprehensive mobile security test');

        await this.initializeMobileTests();

        const testSuites = [
            { name: 'WebView Security', tests: this.webViewTests },
            { name: 'JavaScript Bridges', tests: this.bridgeTests },
            { name: 'Device Access', tests: this.deviceAccessTests },
            { name: 'Data Storage', tests: this.dataStorageTests }
        ];

        for (const suite of testSuites) {
            console.log(`[MOBILE TEST] Running ${suite.name} tests`);
            
            for (const test of suite.tests) {
                try {
                    const result = await Promise.race([
                        test.test(),
                        this.timeoutPromise(this.testConfig.timeout)
                    ]);

                    this.testResults.push({
                        suite: suite.name,
                        test_name: test.name,
                        severity: test.severity,
                        result: result,
                        timestamp: Date.now()
                    });

                    if (result.vulnerable) {
                        this.vulnerabilities.push({
                            suite: suite.name,
                            test: test.name,
                            severity: test.severity,
                            details: result
                        });
                    }

                    if (this.testConfig.verbose) {
                        console.log(`[MOBILE TEST] ${test.name}: ${result.vulnerable ? 'VULNERABLE' : 'SAFE'}`);
                    }

                } catch (e) {
                    console.error(`[MOBILE TEST] Test failed: ${test.name}`, e.message);
                    this.testResults.push({
                        suite: suite.name,
                        test_name: test.name,
                        severity: test.severity,
                        error: e.message,
                        timestamp: Date.now()
                    });
                }
            }
        }

        return this.generateMobileTestReport();
    }

    /**
     * Generate mobile security test report
     */
    generateMobileTestReport() {
        const vulnerableTests = this.testResults.filter(r => r.result?.vulnerable);
        const safeTests = this.testResults.filter(r => r.result && !r.result.vulnerable);
        const failedTests = this.testResults.filter(r => r.error);

        const severityBreakdown = {
            critical: this.vulnerabilities.filter(v => v.severity === 'critical').length,
            high: this.vulnerabilities.filter(v => v.severity === 'high').length,
            medium: this.vulnerabilities.filter(v => v.severity === 'medium').length,
            low: this.vulnerabilities.filter(v => v.severity === 'low').length
        };

        const report = {
            test_id: this.testId,
            timestamp: Date.now(),
            device_info: this.deviceInfo,
            device_capabilities: this.deviceCapabilities,
            summary: {
                total_tests: this.testResults.length,
                vulnerable: vulnerableTests.length,
                safe: safeTests.length,
                failed: failedTests.length,
                critical_vulnerabilities: this.vulnerabilities.filter(v => v.severity === 'critical').length
            },
            severity_breakdown: severityBreakdown,
            vulnerabilities: this.vulnerabilities,
            test_results: this.testResults,
            recommendations: this.generateMobileRecommendations()
        };

        console.log('[MOBILE TEST] Mobile Security Test Report:', report.summary);
        return report;
    }

    /**
     * Generate mobile security recommendations
     */
    generateMobileRecommendations() {
        const recommendations = [];

        // WebView security recommendations
        const webViewIssues = this.vulnerabilities.filter(v => v.suite === 'WebView Security');
        if (webViewIssues.length > 0) {
            recommendations.push({
                category: 'WebView Security',
                priority: 'high',
                recommendation: 'Secure WebView configuration and disable dangerous features',
                issues: webViewIssues.length
            });
        }

        // Bridge security recommendations
        const bridgeIssues = this.vulnerabilities.filter(v => v.suite === 'JavaScript Bridges');
        if (bridgeIssues.length > 0) {
            recommendations.push({
                category: 'JavaScript Bridges',
                priority: 'critical',
                recommendation: 'Implement proper authorization and input validation for bridge methods',
                issues: bridgeIssues.length
            });
        }

        // Device access recommendations
        const deviceIssues = this.vulnerabilities.filter(v => v.suite === 'Device Access');
        if (deviceIssues.length > 0) {
            recommendations.push({
                category: 'Device Access',
                priority: 'high',
                recommendation: 'Implement proper permission controls and user consent mechanisms',
                issues: deviceIssues.length
            });
        }

        return recommendations;
    }

    /**
     * Utility functions
     */
    getTestCount() {
        return (this.webViewTests?.length || 0) +
               (this.bridgeTests?.length || 0) +
               (this.deviceAccessTests?.length || 0) +
               (this.dataStorageTests?.length || 0);
    }

    timeoutPromise(ms) {
        return new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Test timeout')), ms)
        );
    }

    /**
     * Execute mobile security test framework
     */
    async execute() {
        try {
            console.log('[MOBILE TEST] Starting mobile security test framework');
            const report = await this.runComprehensiveMobileTest();
            console.log('[MOBILE TEST] Mobile security testing completed');
            return report;
        } catch (error) {
            console.error('[MOBILE TEST] Test framework execution failed:', error);
            throw error;
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    const mobileTestFramework = new MobileSecurityTestFramework();
    mobileTestFramework.execute().then(report => {
        console.log('[MOBILE TEST] Final Mobile Security Report:', report);
    });
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MobileSecurityTestFramework;
}