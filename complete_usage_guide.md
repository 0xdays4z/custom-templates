# 🎯 COMPLETE USAGE GUIDE
## From Deployment to Results - End-to-End Security Testing

### 📋 **QUICK START CHECKLIST**

#### **1. Verify Deployment Status**
```bash
# Check if services are running
curl -k https://localhost:8443/health
# Expected: {"status":"healthy","timestamp":"2024-01-15T10:30:00Z"}

# Check dashboard access
open https://localhost:8443/
# Should show Porsche Security Dashboard
```

#### **2. Run Your First Security Scan**
```bash
# Quick vulnerability scan (5-10 minutes)
curl -X POST https://localhost:3000/api/scan/quick

# Check scan progress
curl -k https://localhost:3000/api/scan/status
```

#### **3. View Results**
```bash
# Get latest results summary
curl -k https://localhost:3000/api/results/latest | jq '.summary'

# Access web dashboard
https://localhost:8443/dashboard
```

---

## 🚀 **STEP-BY-STEP USAGE WORKFLOW**

### **Phase 1: Initial Setup Verification (5 minutes)**

#### **Check System Health**
```bash
# 1. Verify all services are running
systemctl status porsche-security-suite  # Linux
docker-compose ps                         # Docker
kubectl get pods -n porsche-security     # Kubernetes

# 2. Test API connectivity
curl -k https://localhost:3000/api/health
curl -k https://localhost:8443/health

# 3. Verify database connection
curl -k https://localhost:3000/api/database/status
```

#### **Access Dashboard**
```bash
# Open web interface
Browser: https://localhost:8443/

# Default sections to verify:
✅ System Status: Should show "Operational"
✅ Last Scan: Should show "Never" or recent timestamp
✅ Vulnerabilities: Should show "Loading..." or counts
✅ Risk Level: Should show current assessment
```

### **Phase 2: Run Security Tests (10-30 minutes)**

#### **Option A: Quick Security Scan**
```bash
# Start quick scan (5-10 minutes)
curl -X POST https://localhost:3000/api/scan/quick \
  -H "Content-Type: application/json" \
  -d '{"target":"current_domain","scope":"basic"}'

# Monitor progress
watch -n 10 'curl -s -k https://localhost:3000/api/scan/status | jq ".progress"'
```

#### **Option B: Comprehensive Assessment**
```bash
# Start full assessment (20-30 minutes)
curl -X POST https://localhost:3000/api/scan/comprehensive \
  -H "Content-Type: application/json" \
  -d '{"target":"all_domains","scope":"full","include_mobile":true}'

# Track detailed progress
curl -k https://localhost:3000/api/scan/progress | jq '.'
```

#### **Option C: Targeted Testing**
```bash
# API Security Only
curl -X POST https://localhost:3000/api/scan/api-security

# Mobile Security Only  
curl -X POST https://localhost:3000/api/scan/mobile-security

# Payment Security Only
curl -X POST https://localhost:3000/api/scan/payment-security
```

### **Phase 3: Review Results (10-15 minutes)**

#### **Get Results Summary**
```bash
# Latest scan overview
curl -k https://localhost:3000/api/results/latest | jq '.summary'

# Expected output:
{
  "scan_id": "SCAN_2024-01-15_14-30-00",
  "total_tests": 45,
  "vulnerabilities_found": 12,
  "risk_level": "HIGH",
  "critical_issues": 3,
  "compliance_score": 75
}
```

#### **Critical Findings Review**
```bash
# Get critical vulnerabilities only
curl -k https://localhost:3000/api/vulnerabilities/critical | jq '.'

# Get detailed vulnerability info
curl -k https://localhost:3000/api/vulnerabilities/{vuln-id} | jq '.'
```

#### **Download Detailed Reports**
```bash
# Download JSON report
curl -k https://localhost:3000/api/reports/latest/json > security_report.json

# Download PDF report (if available)
curl -k https://localhost:3000/api/reports/latest/pdf > security_report.pdf

# Download CSV summary
curl -k https://localhost:3000/api/reports/latest/csv > vulnerability_summary.csv
```

---

## 📊 **UNDERSTANDING YOUR RESULTS**

### **Risk Level Interpretation**
```bash
🔴 CRITICAL (80-100%): 
   - Immediate action required (within 4 hours)
   - Potential for complete system compromise
   - Executive notification needed

🟠 HIGH (60-79%):
   - Urgent remediation (within 24-48 hours)
   - Significant security risk
   - Security team lead notification

🟡 MEDIUM (40-59%):
   - Scheduled remediation (within 1 week)
   - Moderate security risk
   - Development team notification

🟢 LOW (20-39%):
   - Plan remediation (within 1 month)
   - Limited security risk
   - Standard development cycle

⚪ MINIMAL (0-19%):
   - Good security posture
   - Routine monitoring sufficient
```

### **Vulnerability Categories**
```json
{
  "vulnerability_types": {
    "xss": {
      "description": "Cross-Site Scripting vulnerabilities",
      "typical_severity": "High to Critical",
      "common_locations": "HTML sanitization, user input fields"
    },
    "authentication": {
      "description": "Authentication and authorization flaws", 
      "typical_severity": "Critical",
      "common_locations": "Login systems, JWT tokens, session management"
    },
    "api_security": {
      "description": "API security vulnerabilities",
      "typical_severity": "Medium to High", 
      "common_locations": "REST endpoints, GraphQL, authentication headers"
    },
    "mobile_security": {
      "description": "Mobile app specific vulnerabilities",
      "typical_severity": "Medium to High",
      "common_locations": "WebView, JavaScript bridges, device access"
    }
  }
}
```

---

## 🔧 **TAKING ACTION ON RESULTS**

### **Immediate Actions for Critical Findings**

#### **1. HTML Sanitization Issues**
```bash
# Emergency mitigation
# Add CSP header immediately
Content-Security-Policy: script-src 'self'; object-src 'none';

# Identify affected files
grep -r "allowVulnerableTags\|data-.*=" /path/to/js/files/

# Quick fix
# Remove wildcard attribute matching from sanitizer configuration
```

#### **2. Authentication Bypass**
```bash
# Emergency response
# 1. Revoke all active sessions
curl -X POST https://localhost:3000/api/auth/revoke-all-sessions

# 2. Force password reset for admin users
curl -X POST https://localhost:3000/api/auth/force-password-reset

# 3. Enable additional monitoring
curl -X POST https://localhost:3000/api/monitoring/enable-auth-alerts
```

#### **3. API Security Issues**
```bash
# Immediate API hardening
# 1. Enable rate limiting
curl -X POST https://localhost:3000/api/config/enable-rate-limiting

# 2. Add authentication to unprotected endpoints
curl -X POST https://localhost:3000/api/config/enforce-authentication

# 3. Monitor for exploitation attempts
tail -f /var/log/porsche-security/api-access.log | grep -E "(401|403|429)"
```

### **Remediation Tracking**
```bash
# Create remediation ticket
curl -X POST https://localhost:3000/api/remediation/create \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "HTML_SANITIZATION_001",
    "priority": "P0",
    "assigned_to": "security-team",
    "due_date": "2024-01-16T10:00:00Z"
  }'

# Track remediation progress
curl -k https://localhost:3000/api/remediation/status/{ticket-id}
```

---

## 📈 **ONGOING MONITORING**

### **Automated Scanning Schedule**
```bash
# Verify scheduled scans are running
crontab -l | grep porsche-security

# Expected cron jobs:
# 0 * * * * - Hourly quick scans
# 0 2 * * * - Daily comprehensive scans  
# 0 3 * * 0 - Weekly deep scans
```

### **Real-Time Monitoring**
```bash
# Monitor live security events
curl -k https://localhost:3000/api/events/live | jq '.'

# Set up webhook for critical alerts
curl -X POST https://localhost:3000/api/webhooks/configure \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-slack-webhook.com/...",
    "events": ["critical_vulnerability", "scan_complete", "system_error"]
  }'
```

### **Performance Monitoring**
```bash
# Check system performance
curl -k https://localhost:3000/api/metrics/system | jq '.'

# Monitor scan performance
curl -k https://localhost:3000/api/metrics/scans | jq '.average_duration'

# Resource usage
curl -k https://localhost:3000/api/metrics/resources | jq '.'
```

---

## 🎯 **COMMON USAGE SCENARIOS**

### **Scenario 1: Daily Security Check (5 minutes)**
```bash
# Morning security check routine
echo "🔍 Daily Security Check - $(date)"

# 1. Check system status
curl -s -k https://localhost:3000/api/health | jq '.status'

# 2. Get vulnerability count
curl -s -k https://localhost:3000/api/vulnerabilities/count | jq '.'

# 3. Check for new critical issues
CRITICAL=$(curl -s -k https://localhost:3000/api/vulnerabilities/critical | jq 'length')
if [ "$CRITICAL" -gt 0 ]; then
  echo "⚠️  $CRITICAL critical vulnerabilities found!"
  curl -s -k https://localhost:3000/api/vulnerabilities/critical | jq '.[] | .title'
fi

# 4. Verify last scan time
curl -s -k https://localhost:3000/api/scan/last | jq '.timestamp'
```

### **Scenario 2: Pre-Deployment Security Check**
```bash
# Before deploying new code
echo "🚀 Pre-deployment security validation"

# 1. Run comprehensive scan
SCAN_ID=$(curl -s -X POST https://localhost:3000/api/scan/comprehensive | jq -r '.scan_id')

# 2. Wait for completion
while [ "$(curl -s -k https://localhost:3000/api/scan/$SCAN_ID/status | jq -r '.status')" != "completed" ]; do
  echo "Scanning... $(curl -s -k https://localhost:3000/api/scan/$SCAN_ID/status | jq -r '.progress')%"
  sleep 30
done

# 3. Check if deployment should proceed
CRITICAL=$(curl -s -k https://localhost:3000/api/scan/$SCAN_ID/results | jq '.summary.critical')
if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ Deployment blocked: $CRITICAL critical vulnerabilities found"
  exit 1
else
  echo "✅ Deployment approved: No critical vulnerabilities"
fi
```

### **Scenario 3: Incident Response**
```bash
# When security incident is suspected
echo "🚨 Security Incident Response"

# 1. Run emergency scan
curl -X POST https://localhost:3000/api/scan/emergency \
  -H "Content-Type: application/json" \
  -d '{"priority":"immediate","scope":"full"}'

# 2. Check for active exploitation
curl -k https://localhost:3000/api/threats/active | jq '.'

# 3. Generate incident report
curl -k https://localhost:3000/api/reports/incident > incident_report_$(date +%Y%m%d_%H%M).json

# 4. Alert security team
curl -X POST https://localhost:3000/api/alerts/incident \
  -H "Content-Type: application/json" \
  -d '{"severity":"critical","message":"Security incident detected - immediate response required"}'
```

---

## 📚 **TROUBLESHOOTING GUIDE**

### **Common Issues and Solutions**

#### **Issue: Scans Not Running**
```bash
# Check service status
systemctl status porsche-security-suite

# Check logs for errors
tail -f /var/log/porsche-security/security-suite-production.log

# Restart service if needed
sudo systemctl restart porsche-security-suite
```

#### **Issue: No Results Displayed**
```bash
# Check database connectivity
curl -k https://localhost:3000/api/database/status

# Verify scan completion
curl -k https://localhost:3000/api/scan/history | jq '.[-1]'

# Check for scan errors
curl -k https://localhost:3000/api/scan/errors | jq '.'
```

#### **Issue: Dashboard Not Loading**
```bash
# Check if dashboard service is running
netstat -tlnp | grep :8443

# Verify SSL certificate
openssl s_client -connect localhost:8443

# Check browser console for JavaScript errors
# Open browser dev tools (F12) and check console
```

---

## 🏆 **BEST PRACTICES**

### **Daily Operations**
- ✅ Check dashboard every morning
- ✅ Review critical alerts immediately
- ✅ Monitor scan completion status
- ✅ Verify system health metrics

### **Weekly Operations**
- ✅ Review vulnerability trends
- ✅ Update remediation progress
- ✅ Check compliance scores
- ✅ Validate backup procedures

### **Monthly Operations**
- ✅ Generate executive reports
- ✅ Review security policies
- ✅ Update threat models
- ✅ Conduct security training

### **Emergency Procedures**
- ✅ Critical vulnerability response plan
- ✅ Incident escalation procedures
- ✅ Emergency contact information
- ✅ Backup communication channels

This complete usage guide provides everything needed to effectively use the Porsche Security Testing Suite from initial deployment through ongoing operations and incident response.