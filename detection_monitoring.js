/**
 * Detection and Monitoring System
 * Real-time detection of account takeover attempts and security breaches
 * Monitors for the vulnerabilities discovered in Porsche JavaScript files
 */

class SecurityMonitoringSystem {
    constructor() {
        this.alertEndpoint = 'https://security-team.porsche.com/alerts';
        this.detectionRules = this.initializeDetectionRules();
        this.alertThresholds = {
            critical: 1,    // Alert immediately
            high: 3,        // Alert after 3 occurrences
            medium: 10      // Alert after 10 occurrences
        };
        this.detectionLog = [];
        this.isMonitoring = false;
        this.startTime = Date.now();
    }

    /**
     * Initialize detection rules for known vulnerabilities
     */
    initializeDetectionRules() {
        return {
            // HTML Sanitization Bypass Detection
            htmlSanitizationBypass: {
                severity: 'critical',
                patterns: [
                    /data-[^=]*=.*eval\(/i,
                    /data-[^=]*=.*atob\(/i,
                    /data-[^=]*=.*Function\(/i,
                    /onmouseover.*eval/i,
                    /onclick.*eval/i,
                    /allowVulnerableTags/i
                ],
                description: 'HTML sanitization bypass attempt detected'
            },

            // Blob URL Manipulation Detection
            blobUrlManipulation: {
                severity: 'critical',
                patterns: [
                    /URL\.createObjectURL.*application\/javascript/i,
                    /new Blob.*application\/javascript/i,
                    /sourceMappingURL.*data:/i
                ],
                description: 'Suspicious blob URL creation with JavaScript MIME type'
            },

            // Authentication Token Manipulation
            tokenManipulation: {
                severity: 'critical',
                patterns: [
                    /localStorage\.setItem.*auth.*admin/i,
                    /localStorage\.setItem.*token.*super/i,
                    /roles.*admin.*super_admin/i,
                    /permissions.*\[\"\*\"\]/i
                ],
                description: 'Suspicious authentication token manipulation'
            },

            // Dynamic Script Injection
            scriptInjection: {
                severity: 'high',
                patterns: [
                    /document\.createElement\(\"script\"\)/i,
                    /appendChild.*script/i,
                    /insertBefore.*script/i,
                    /document\.write.*script/i
                ],
                description: 'Dynamic script injection detected'
            },

            // Service Worker Backdoor
            serviceWorkerBackdoor: {
                severity: 'critical',
                patterns: [
                    /serviceWorker\.register.*blob:/i,
                    /addEventListener.*fetch.*intercept/i,
                    /fetch.*auth.*intercept/i
                ],
                description: 'Service Worker backdoor installation attempt'
            }
        };
    }

    /**
     * Start comprehensive security monitoring
     */
    startMonitoring() {
        if (this.isMonitoring) {
            console.log('[SECURITY] Monitoring already active');
            return;
        }

        console.log('[SECURITY] Starting comprehensive security monitoring...');
        this.isMonitoring = true;

        // Monitor localStorage changes
        this.monitorLocalStorageChanges();

        // Monitor DOM mutations
        this.monitorDOMMutations();

        // Monitor network requests
        this.monitorNetworkRequests();

        // Monitor blob URL creation
        this.monitorBlobCreation();

        // Monitor Service Worker registration
        this.monitorServiceWorkers();

        // Monitor authentication events
        this.monitorAuthenticationEvents();

        // Start periodic security scans
        this.startPeriodicScans();

        console.log('[SECURITY] All monitoring systems activated');
    }

    /**
     * Monitor localStorage for suspicious authentication changes
     */
    monitorLocalStorageChanges() {
        const originalSetItem = localStorage.setItem;
        const self = this;

        localStorage.setItem = function(key, value) {
            // Check for suspicious auth token changes
            if (key.includes('auth') || key.includes('token')) {
                self.analyzeAuthTokenChange(key, value);
            }

            // Check for admin privilege escalation
            if (value && typeof value === 'string') {
                try {
                    const parsedValue = JSON.parse(value);
                    if (parsedValue.roles && Array.isArray(parsedValue.roles)) {
                        if (parsedValue.roles.includes('admin') || 
                            parsedValue.roles.includes('super_admin')) {
                            self.triggerAlert('critical', 'Admin privilege escalation detected', {
                                key: key,
                                roles: parsedValue.roles,
                                timestamp: Date.now()
                            });
                        }
                    }
                } catch (e) {
                    // Not JSON, check for JWT tokens
                    if (value.includes('.') && value.split('.').length === 3) {
                        self.analyzeJWTToken(key, value);
                    }
                }
            }

            return originalSetItem.call(this, key, value);
        };
    }

    /**
     * Analyze authentication token changes for suspicious activity
     */
    analyzeAuthTokenChange(key, value) {
        try {
            // Check if it's a JWT token
            if (value.includes('.') && value.split('.').length === 3) {
                const parts = value.split('.');
                const payload = JSON.parse(atob(parts[1]));

                // Check for suspicious claims
                const suspiciousIndicators = [
                    payload.roles && payload.roles.includes('admin'),
                    payload.permissions && payload.permissions.includes('*'),
                    payload.exp && payload.exp > (Date.now() / 1000) + (365 * 24 * 60 * 60), // > 1 year
                    payload.iss && !payload.iss.includes('porsche.auth0.com'),
                    payload.sub && payload.sub.includes('admin'),
                    payload.bypass_all_restrictions === true
                ];

                if (suspiciousIndicators.some(indicator => indicator)) {
                    this.triggerAlert('critical', 'Suspicious JWT token detected', {
                        key: key,
                        payload: payload,
                        indicators: suspiciousIndicators,
                        timestamp: Date.now()
                    });
                }
            }
        } catch (e) {
            // Token parsing failed, might be malformed or encrypted
            this.logDetection('medium', 'Malformed authentication token', {
                key: key,
                error: e.message
            });
        }
    }

    /**
     * Monitor DOM mutations for malicious content injection
     */
    monitorDOMMutations() {
        const self = this;
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.addedNodes) {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.nodeType === 1) { // Element node
                            self.scanElementForThreats(node);
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['data-*', 'onclick', 'onmouseover', 'onload']
        });
    }

    /**
     * Scan DOM elements for security threats
     */
    scanElementForThreats(element) {
        // Check element attributes for malicious patterns
        if (element.attributes) {
            for (let attr of element.attributes) {
                const attrValue = attr.value;
                
                // Check against detection rules
                Object.keys(this.detectionRules).forEach(ruleName => {
                    const rule = this.detectionRules[ruleName];
                    rule.patterns.forEach(pattern => {
                        if (pattern.test(attrValue)) {
                            this.triggerAlert(rule.severity, rule.description, {
                                element: element.tagName,
                                attribute: attr.name,
                                value: attrValue,
                                rule: ruleName,
                                timestamp: Date.now()
                            });
                        }
                    });
                });
            }
        }

        // Check element content
        if (element.innerHTML) {
            this.scanContentForThreats(element.innerHTML, 'innerHTML');
        }

        // Recursively check child elements
        if (element.children) {
            for (let child of element.children) {
                this.scanElementForThreats(child);
            }
        }
    }

    /**
     * Scan content for malicious patterns
     */
    scanContentForThreats(content, source) {
        Object.keys(this.detectionRules).forEach(ruleName => {
            const rule = this.detectionRules[ruleName];
            rule.patterns.forEach(pattern => {
                if (pattern.test(content)) {
                    this.triggerAlert(rule.severity, rule.description, {
                        source: source,
                        content: content.substring(0, 200) + '...', // Truncate for logging
                        rule: ruleName,
                        timestamp: Date.now()
                    });
                }
            });
        });
    }

    /**
     * Monitor network requests for suspicious activity
     */
    monitorNetworkRequests() {
        const originalFetch = window.fetch;
        const self = this;

        window.fetch = function(...args) {
            const [url, options] = args;
            
            // Log suspicious requests
            self.analyzeNetworkRequest(url, options);
            
            return originalFetch.apply(this, args).then(response => {
                // Monitor responses for sensitive data
                if (url.includes('/api/') || url.includes('/auth/')) {
                    self.analyzeNetworkResponse(url, response);
                }
                return response;
            });
        };

        // Also monitor XMLHttpRequest
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            self.analyzeNetworkRequest(url, { method: method });
            return originalXHROpen.apply(this, [method, url, ...args]);
        };
    }

    /**
     * Analyze network requests for suspicious patterns
     */
    analyzeNetworkRequest(url, options) {
        // Check for data exfiltration attempts
        const suspiciousPatterns = [
            /evil|attacker|malicious|hack/i,
            /steal|exfil|collect/i,
            /backdoor|c2|command/i
        ];

        suspiciousPatterns.forEach(pattern => {
            if (pattern.test(url)) {
                this.triggerAlert('critical', 'Suspicious network request detected', {
                    url: url,
                    options: options,
                    pattern: pattern.toString(),
                    timestamp: Date.now()
                });
            }
        });

        // Check for unusual authentication endpoints
        if (url.includes('/auth') && !url.includes('porsche.auth0.com')) {
            this.triggerAlert('high', 'Unusual authentication endpoint', {
                url: url,
                timestamp: Date.now()
            });
        }
    }

    /**
     * Monitor blob URL creation for malicious JavaScript
     */
    monitorBlobCreation() {
        const originalCreateObjectURL = URL.createObjectURL;
        const self = this;

        URL.createObjectURL = function(blob) {
            if (blob.type === 'application/javascript') {
                self.triggerAlert('critical', 'JavaScript blob URL creation detected', {
                    type: blob.type,
                    size: blob.size,
                    timestamp: Date.now()
                });

                // Try to read blob content for analysis
                const reader = new FileReader();
                reader.onload = function() {
                    self.scanContentForThreats(reader.result, 'blob_content');
                };
                reader.readAsText(blob);
            }

            return originalCreateObjectURL.call(this, blob);
        };
    }

    /**
     * Monitor Service Worker registration
     */
    monitorServiceWorkers() {
        if ('serviceWorker' in navigator) {
            const originalRegister = navigator.serviceWorker.register;
            const self = this;

            navigator.serviceWorker.register = function(scriptURL, options) {
                self.triggerAlert('high', 'Service Worker registration detected', {
                    scriptURL: scriptURL,
                    options: options,
                    timestamp: Date.now()
                });

                // Check if it's a blob URL (potential backdoor)
                if (scriptURL.startsWith('blob:')) {
                    self.triggerAlert('critical', 'Service Worker registered from blob URL', {
                        scriptURL: scriptURL,
                        timestamp: Date.now()
                    });
                }

                return originalRegister.call(this, scriptURL, options);
            };
        }
    }

    /**
     * Monitor authentication events
     */
    monitorAuthenticationEvents() {
        // Monitor for Auth0 events if available
        if (window.auth0) {
            const self = this;
            
            // Hook into Auth0 methods
            const originalGetTokenSilently = window.auth0.getTokenSilently;
            if (originalGetTokenSilently) {
                window.auth0.getTokenSilently = function(...args) {
                    return originalGetTokenSilently.apply(this, args).then(token => {
                        self.analyzeJWTToken('auth0_token', token);
                        return token;
                    });
                };
            }
        }

        // Monitor login/logout events
        window.addEventListener('storage', (event) => {
            if (event.key && (event.key.includes('auth') || event.key.includes('token'))) {
                this.logDetection('medium', 'Authentication storage event', {
                    key: event.key,
                    oldValue: event.oldValue,
                    newValue: event.newValue,
                    timestamp: Date.now()
                });
            }
        });
    }

    /**
     * Start periodic security scans
     */
    startPeriodicScans() {
        const self = this;

        // Scan every 30 seconds
        setInterval(() => {
            self.performSecurityScan();
        }, 30000);

        // Deep scan every 5 minutes
        setInterval(() => {
            self.performDeepSecurityScan();
        }, 300000);
    }

    /**
     * Perform quick security scan
     */
    performSecurityScan() {
        // Check for suspicious localStorage entries
        this.scanLocalStorage();
        
        // Check for suspicious DOM elements
        this.scanDOM();
        
        // Check for active Service Workers
        this.scanServiceWorkers();
    }

    /**
     * Scan localStorage for threats
     */
    scanLocalStorage() {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            
            // Check for backdoor keys
            const backdoorPatterns = [
                /backdoor/i,
                /persistence/i,
                /exfil/i,
                /attack/i
            ];

            backdoorPatterns.forEach(pattern => {
                if (pattern.test(key) || pattern.test(value)) {
                    this.triggerAlert('critical', 'Backdoor detected in localStorage', {
                        key: key,
                        value: value.substring(0, 100) + '...',
                        timestamp: Date.now()
                    });
                }
            });
        }
    }

    /**
     * Scan DOM for threats
     */
    scanDOM() {
        // Check for hidden elements with suspicious attributes
        const hiddenElements = document.querySelectorAll('[style*="display:none"], [style*="visibility:hidden"]');
        
        hiddenElements.forEach(element => {
            if (element.innerHTML.includes('eval') || 
                element.innerHTML.includes('atob') ||
                element.innerHTML.includes('Function')) {
                this.triggerAlert('high', 'Hidden element with suspicious content', {
                    element: element.outerHTML.substring(0, 200) + '...',
                    timestamp: Date.now()
                });
            }
        });
    }

    /**
     * Scan active Service Workers
     */
    scanServiceWorkers() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.getRegistrations().then(registrations => {
                registrations.forEach(registration => {
                    if (registration.active && registration.active.scriptURL.startsWith('blob:')) {
                        this.triggerAlert('critical', 'Active Service Worker from blob URL detected', {
                            scriptURL: registration.active.scriptURL,
                            scope: registration.scope,
                            timestamp: Date.now()
                        });
                    }
                });
            });
        }
    }

    /**
     * Trigger security alert
     */
    triggerAlert(severity, message, details) {
        const alert = {
            id: 'ALERT_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
            severity: severity,
            message: message,
            details: details,
            timestamp: Date.now(),
            url: window.location.href,
            userAgent: navigator.userAgent
        };

        console.error(`[SECURITY ALERT - ${severity.toUpperCase()}] ${message}`, details);
        
        this.detectionLog.push(alert);
        
        // Send to security team if critical or high severity
        if (severity === 'critical' || severity === 'high') {
            this.sendAlertToSecurityTeam(alert);
        }

        // Show visual alert for critical threats
        if (severity === 'critical') {
            this.showVisualAlert(alert);
        }
    }

    /**
     * Log detection event
     */
    logDetection(severity, message, details) {
        const detection = {
            severity: severity,
            message: message,
            details: details,
            timestamp: Date.now()
        };

        console.log(`[SECURITY LOG - ${severity.toUpperCase()}] ${message}`, details);
        this.detectionLog.push(detection);
    }

    /**
     * Send alert to security team
     */
    sendAlertToSecurityTeam(alert) {
        fetch(this.alertEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Security-Alert': 'true'
            },
            body: JSON.stringify(alert)
        }).catch(error => {
            console.error('[SECURITY] Failed to send alert to security team:', error);
            
            // Fallback: store alert locally
            localStorage.setItem('security_alert_' + alert.id, JSON.stringify(alert));
        });
    }

    /**
     * Show visual security alert
     */
    showVisualAlert(alert) {
        const alertElement = document.createElement('div');
        alertElement.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #ff4444;
            color: white;
            padding: 15px;
            border-radius: 5px;
            z-index: 999999;
            font-family: Arial, sans-serif;
            max-width: 400px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        `;

        alertElement.innerHTML = `
            <h3>🚨 SECURITY ALERT</h3>
            <p><strong>${alert.message}</strong></p>
            <p><small>Severity: ${alert.severity.toUpperCase()}</small></p>
            <button onclick="this.parentElement.remove()" style="margin-top: 10px; padding: 5px 10px; background: white; color: red; border: none; border-radius: 3px; cursor: pointer;">
                Dismiss
            </button>
        `;

        document.body.appendChild(alertElement);

        // Auto-remove after 30 seconds
        setTimeout(() => {
            if (alertElement.parentElement) {
                alertElement.parentElement.removeChild(alertElement);
            }
        }, 30000);
    }

    /**
     * Get security monitoring report
     */
    getSecurityReport() {
        const report = {
            monitoring_duration: Date.now() - this.startTime,
            total_detections: this.detectionLog.length,
            critical_alerts: this.detectionLog.filter(d => d.severity === 'critical').length,
            high_alerts: this.detectionLog.filter(d => d.severity === 'high').length,
            medium_alerts: this.detectionLog.filter(d => d.severity === 'medium').length,
            recent_alerts: this.detectionLog.slice(-10),
            system_status: this.isMonitoring ? 'ACTIVE' : 'INACTIVE'
        };

        return report;
    }

    /**
     * Stop monitoring
     */
    stopMonitoring() {
        this.isMonitoring = false;
        console.log('[SECURITY] Monitoring stopped');
    }
}

// Auto-start monitoring if in browser environment
if (typeof window !== 'undefined') {
    const securityMonitor = new SecurityMonitoringSystem();
    securityMonitor.startMonitoring();
    
    // Make it globally accessible for manual control
    window.securityMonitor = securityMonitor;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityMonitoringSystem;
}