#!/bin/bash

# Porsche Security Testing Suite Deployment Script
# Automated deployment for production environments
# Version: 1.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_ENV="${1:-production}"
SECURITY_SUITE_VERSION="1.0.0"
LOG_FILE="/var/log/security-suite-deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log "Checking deployment prerequisites..."
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo privileges"
    fi
    
    # Check required commands
    local required_commands=("node" "npm" "git" "curl" "systemctl" "nginx")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command '$cmd' is not installed"
        fi
    done
    
    # Check Node.js version
    local node_version=$(node --version | cut -d'v' -f2)
    local required_version="14.0.0"
    if ! printf '%s\n%s\n' "$required_version" "$node_version" | sort -V -C; then
        error "Node.js version $required_version or higher is required (found: $node_version)"
    fi
    
    success "All prerequisites met"
}

# Create directory structure
create_directory_structure() {
    log "Creating directory structure..."
    
    local base_dir="/opt/porsche-security-suite"
    local directories=(
        "$base_dir"
        "$base_dir/scripts"
        "$base_dir/config"
        "$base_dir/logs"
        "$base_dir/reports"
        "$base_dir/backups"
        "/etc/porsche-security"
        "/var/log/porsche-security"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log "Created directory: $dir"
    done
    
    # Set proper permissions
    chown -R www-data:www-data "$base_dir"
    chmod -R 755 "$base_dir"
    
    success "Directory structure created"
}

# Install security testing suite
install_security_suite() {
    log "Installing Porsche Security Testing Suite..."
    
    local base_dir="/opt/porsche-security-suite"
    
    # Copy security testing scripts
    local scripts=(
        "automated_vulnerability_scanner.js"
        "api_security_test_suite.js"
        "mobile_security_test_framework.js"
        "comprehensive_test_orchestrator.js"
        "detection_monitoring.js"
        "poc_customer_account_takeover.js"
        "poc_admin_panel_compromise.js"
        "poc_supply_chain_attack.js"
        "poc_payment_system_compromise.js"
        "poc_mobile_app_compromise.js"
        "poc_api_security_bypass.js"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$SCRIPT_DIR/$script" ]]; then
            cp "$SCRIPT_DIR/$script" "$base_dir/scripts/"
            chmod +x "$base_dir/scripts/$script"
            log "Installed: $script"
        else
            warning "Script not found: $script"
        fi
    done
    
    success "Security testing suite installed"
}

# Create configuration files
create_configuration() {
    log "Creating configuration files..."
    
    local config_dir="/etc/porsche-security"
    
    # Main configuration file
    cat > "$config_dir/security-suite.conf" << 'EOF'
# Porsche Security Testing Suite Configuration

# Environment settings
ENVIRONMENT=production
DEBUG_MODE=false
LOG_LEVEL=info

# Security settings
ENABLE_REAL_TIME_MONITORING=true
ENABLE_AUTOMATED_REPORTING=true
ENABLE_CRITICAL_ALERTS=true

# API endpoints
SECURITY_TEAM_ENDPOINT=https://security-team.porsche.com/alerts
REPORT_ENDPOINT=https://security-team.porsche.com/reports
WEBHOOK_ENDPOINT=https://security-team.porsche.com/webhooks

# Testing configuration
RUN_COMPREHENSIVE_SCAN_INTERVAL=86400  # 24 hours
RUN_QUICK_SCAN_INTERVAL=3600          # 1 hour
ENABLE_PARALLEL_TESTING=false
MAX_CONCURRENT_TESTS=5

# Notification settings
SLACK_WEBHOOK_URL=
EMAIL_NOTIFICATIONS=true
SMS_ALERTS_CRITICAL=true

# Database settings (if using database for reports)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=porsche_security
DB_USER=security_user
DB_PASSWORD_FILE=/etc/porsche-security/db_password

# SSL/TLS settings
SSL_CERT_PATH=/etc/ssl/certs/porsche-security.crt
SSL_KEY_PATH=/etc/ssl/private/porsche-security.key
EOF

    # Environment-specific configuration
    cat > "$config_dir/environments/$DEPLOYMENT_ENV.conf" << EOF
# Environment: $DEPLOYMENT_ENV

# Override settings for $DEPLOYMENT_ENV environment
ENVIRONMENT=$DEPLOYMENT_ENV

# Logging
LOG_FILE=/var/log/porsche-security/security-suite-$DEPLOYMENT_ENV.log
AUDIT_LOG_FILE=/var/log/porsche-security/audit-$DEPLOYMENT_ENV.log

# Performance settings
MAX_MEMORY_USAGE=2048M
MAX_CPU_USAGE=80%
TIMEOUT_SECONDS=300

# Security settings for $DEPLOYMENT_ENV
$(if [[ "$DEPLOYMENT_ENV" == "production" ]]; then
    echo "ENABLE_DEBUG_ENDPOINTS=false"
    echo "STRICT_SSL_VERIFICATION=true"
    echo "RATE_LIMIT_ENABLED=true"
else
    echo "ENABLE_DEBUG_ENDPOINTS=true"
    echo "STRICT_SSL_VERIFICATION=false"
    echo "RATE_LIMIT_ENABLED=false"
fi)
EOF

    # Create systemd service configuration
    cat > "/etc/systemd/system/porsche-security-suite.service" << 'EOF'
[Unit]
Description=Porsche Security Testing Suite
Documentation=https://security.porsche.com/docs
After=network.target
Wants=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/porsche-security-suite
ExecStart=/usr/bin/node scripts/comprehensive_test_orchestrator.js
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=porsche-security-suite

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/porsche-security-suite/logs /opt/porsche-security-suite/reports /var/log/porsche-security

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Environment
Environment=NODE_ENV=production
Environment=CONFIG_FILE=/etc/porsche-security/security-suite.conf

[Install]
WantedBy=multi-user.target
EOF

    # Create logrotate configuration
    cat > "/etc/logrotate.d/porsche-security" << 'EOF'
/var/log/porsche-security/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload porsche-security-suite > /dev/null 2>&1 || true
    endscript
}
EOF

    # Set proper permissions
    chmod 600 "$config_dir/security-suite.conf"
    chmod 600 "$config_dir/environments/$DEPLOYMENT_ENV.conf"
    chmod 644 "/etc/systemd/system/porsche-security-suite.service"
    
    success "Configuration files created"
}

# Setup monitoring and alerting
setup_monitoring() {
    log "Setting up monitoring and alerting..."
    
    # Create monitoring script
    cat > "/opt/porsche-security-suite/scripts/monitor.sh" << 'EOF'
#!/bin/bash

# Porsche Security Suite Monitoring Script

CONFIG_FILE="/etc/porsche-security/security-suite.conf"
source "$CONFIG_FILE"

LOG_FILE="/var/log/porsche-security/monitor.log"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=80
ALERT_THRESHOLD_DISK=90

# Function to send alert
send_alert() {
    local message="$1"
    local severity="$2"
    
    echo "[$(date)] ALERT [$severity]: $message" >> "$LOG_FILE"
    
    # Send to security team endpoint
    if [[ -n "$SECURITY_TEAM_ENDPOINT" ]]; then
        curl -X POST "$SECURITY_TEAM_ENDPOINT" \
             -H "Content-Type: application/json" \
             -d "{\"message\":\"$message\",\"severity\":\"$severity\",\"timestamp\":\"$(date -Iseconds)\"}" \
             2>/dev/null || echo "Failed to send alert to security team"
    fi
    
    # Send Slack notification if configured
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
             -H "Content-Type: application/json" \
             -d "{\"text\":\"🚨 Porsche Security Alert [$severity]: $message\"}" \
             2>/dev/null || echo "Failed to send Slack notification"
    fi
}

# Check service status
check_service_status() {
    if ! systemctl is-active --quiet porsche-security-suite; then
        send_alert "Porsche Security Suite service is not running" "CRITICAL"
        return 1
    fi
    return 0
}

# Check resource usage
check_resource_usage() {
    # Check CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    if (( $(echo "$cpu_usage > $ALERT_THRESHOLD_CPU" | bc -l) )); then
        send_alert "High CPU usage: ${cpu_usage}%" "WARNING"
    fi
    
    # Check memory usage
    local memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    if (( $(echo "$memory_usage > $ALERT_THRESHOLD_MEMORY" | bc -l) )); then
        send_alert "High memory usage: ${memory_usage}%" "WARNING"
    fi
    
    # Check disk usage
    local disk_usage=$(df /opt/porsche-security-suite | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    if (( disk_usage > ALERT_THRESHOLD_DISK )); then
        send_alert "High disk usage: ${disk_usage}%" "WARNING"
    fi
}

# Check log files for errors
check_log_errors() {
    local error_count=$(grep -c "ERROR\|CRITICAL" /var/log/porsche-security/*.log 2>/dev/null || echo 0)
    if (( error_count > 10 )); then
        send_alert "High error count in logs: $error_count errors found" "WARNING"
    fi
}

# Main monitoring function
main() {
    echo "[$(date)] Starting monitoring check" >> "$LOG_FILE"
    
    check_service_status
    check_resource_usage
    check_log_errors
    
    echo "[$(date)] Monitoring check completed" >> "$LOG_FILE"
}

main "$@"
EOF

    chmod +x "/opt/porsche-security-suite/scripts/monitor.sh"
    
    # Create cron job for monitoring
    cat > "/etc/cron.d/porsche-security-monitoring" << 'EOF'
# Porsche Security Suite Monitoring
# Run monitoring checks every 5 minutes
*/5 * * * * www-data /opt/porsche-security-suite/scripts/monitor.sh

# Run comprehensive security scan daily at 2 AM
0 2 * * * www-data /usr/bin/node /opt/porsche-security-suite/scripts/comprehensive_test_orchestrator.js --scheduled

# Run quick security scan every hour
0 * * * * www-data /usr/bin/node /opt/porsche-security-suite/scripts/automated_vulnerability_scanner.js --quick-scan

# Cleanup old reports weekly
0 3 * * 0 www-data find /opt/porsche-security-suite/reports -name "*.json" -mtime +30 -delete
EOF

    success "Monitoring and alerting configured"
}

# Setup web dashboard (optional)
setup_web_dashboard() {
    log "Setting up web dashboard..."
    
    # Create simple web dashboard
    local dashboard_dir="/opt/porsche-security-suite/dashboard"
    mkdir -p "$dashboard_dir"
    
    cat > "$dashboard_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Porsche Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #000; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-good { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-critical { color: #dc3545; }
        .metric { font-size: 2em; font-weight: bold; }
        .refresh-btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Porsche Security Dashboard</h1>
        <p>Real-time security monitoring and vulnerability assessment</p>
    </div>
    
    <div class="dashboard">
        <div class="card">
            <h3>System Status</h3>
            <div id="system-status" class="metric status-good">✅ Operational</div>
            <p>Security suite is running normally</p>
        </div>
        
        <div class="card">
            <h3>Active Vulnerabilities</h3>
            <div id="vulnerability-count" class="metric">Loading...</div>
            <p>Critical and high severity issues</p>
        </div>
        
        <div class="card">
            <h3>Last Scan</h3>
            <div id="last-scan" class="metric">Loading...</div>
            <p>Most recent security assessment</p>
        </div>
        
        <div class="card">
            <h3>Risk Level</h3>
            <div id="risk-level" class="metric">Loading...</div>
            <p>Overall security risk assessment</p>
        </div>
        
        <div class="card">
            <h3>Quick Actions</h3>
            <button class="refresh-btn" onclick="runQuickScan()">Run Quick Scan</button>
            <button class="refresh-btn" onclick="viewReports()">View Reports</button>
            <button class="refresh-btn" onclick="downloadLogs()">Download Logs</button>
        </div>
        
        <div class="card">
            <h3>Recent Alerts</h3>
            <div id="recent-alerts">Loading...</div>
        </div>
    </div>
    
    <script>
        // Dashboard JavaScript functionality
        async function loadDashboardData() {
            try {
                // Load system status
                const response = await fetch('/api/status');
                const data = await response.json();
                
                document.getElementById('vulnerability-count').textContent = data.vulnerabilities || '0';
                document.getElementById('last-scan').textContent = data.lastScan || 'Never';
                document.getElementById('risk-level').textContent = data.riskLevel || 'Unknown';
                
                // Update status colors
                const riskElement = document.getElementById('risk-level');
                if (data.riskLevel === 'CRITICAL') {
                    riskElement.className = 'metric status-critical';
                } else if (data.riskLevel === 'HIGH') {
                    riskElement.className = 'metric status-warning';
                } else {
                    riskElement.className = 'metric status-good';
                }
                
            } catch (error) {
                console.error('Failed to load dashboard data:', error);
            }
        }
        
        function runQuickScan() {
            alert('Quick scan initiated. Results will be available in a few minutes.');
            // In production, this would trigger the actual scan
        }
        
        function viewReports() {
            window.open('/reports', '_blank');
        }
        
        function downloadLogs() {
            window.open('/api/logs/download', '_blank');
        }
        
        // Load data on page load and refresh every 30 seconds
        loadDashboardData();
        setInterval(loadDashboardData, 30000);
    </script>
</body>
</html>
EOF

    # Create Nginx configuration for dashboard
    cat > "/etc/nginx/sites-available/porsche-security-dashboard" << 'EOF'
server {
    listen 8443 ssl;
    server_name security-dashboard.porsche.local;
    
    ssl_certificate /etc/ssl/certs/porsche-security.crt;
    ssl_private_key /etc/ssl/private/porsche-security.key;
    
    root /opt/porsche-security-suite/dashboard;
    index index.html;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Dashboard
    location / {
        try_files $uri $uri/ =404;
    }
    
    # API endpoints
    location /api/ {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    # Reports directory
    location /reports/ {
        alias /opt/porsche-security-suite/reports/;
        autoindex on;
        auth_basic "Security Reports";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
    
    # Access logs
    access_log /var/log/nginx/porsche-security-access.log;
    error_log /var/log/nginx/porsche-security-error.log;
}
EOF

    # Enable the site
    ln -sf /etc/nginx/sites-available/porsche-security-dashboard /etc/nginx/sites-enabled/
    
    success "Web dashboard configured"
}

# Setup SSL certificates
setup_ssl_certificates() {
    log "Setting up SSL certificates..."
    
    local cert_dir="/etc/ssl/certs"
    local key_dir="/etc/ssl/private"
    
    # Generate self-signed certificate for development/testing
    if [[ "$DEPLOYMENT_ENV" != "production" ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_dir/porsche-security.key" \
            -out "$cert_dir/porsche-security.crt" \
            -subj "/C=DE/ST=Baden-Württemberg/L=Stuttgart/O=Porsche AG/OU=Security Team/CN=security.porsche.local"
        
        success "Self-signed SSL certificate generated"
    else
        warning "Production SSL certificates should be obtained from a trusted CA"
        warning "Please replace the self-signed certificates with proper ones"
    fi
    
    # Set proper permissions
    chmod 600 "$key_dir/porsche-security.key"
    chmod 644 "$cert_dir/porsche-security.crt"
}

# Create backup and restore scripts
create_backup_scripts() {
    log "Creating backup and restore scripts..."
    
    cat > "/opt/porsche-security-suite/scripts/backup.sh" << 'EOF'
#!/bin/bash

# Porsche Security Suite Backup Script

BACKUP_DIR="/opt/porsche-security-suite/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="porsche-security-backup-$TIMESTAMP.tar.gz"

echo "Starting backup at $(date)"

# Create backup
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude="$BACKUP_DIR" \
    /opt/porsche-security-suite \
    /etc/porsche-security \
    /etc/systemd/system/porsche-security-suite.service \
    /etc/nginx/sites-available/porsche-security-dashboard \
    /var/log/porsche-security

echo "Backup created: $BACKUP_DIR/$BACKUP_FILE"

# Keep only last 7 backups
find "$BACKUP_DIR" -name "porsche-security-backup-*.tar.gz" -mtime +7 -delete

echo "Backup completed at $(date)"
EOF

    cat > "/opt/porsche-security-suite/scripts/restore.sh" << 'EOF'
#!/bin/bash

# Porsche Security Suite Restore Script

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <backup-file>"
    exit 1
fi

BACKUP_FILE="$1"

if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "Starting restore from $BACKUP_FILE at $(date)"

# Stop services
systemctl stop porsche-security-suite
systemctl stop nginx

# Restore files
tar -xzf "$BACKUP_FILE" -C /

# Reload systemd and restart services
systemctl daemon-reload
systemctl start porsche-security-suite
systemctl start nginx

echo "Restore completed at $(date)"
EOF

    chmod +x "/opt/porsche-security-suite/scripts/backup.sh"
    chmod +x "/opt/porsche-security-suite/scripts/restore.sh"
    
    # Add backup to cron
    echo "0 1 * * * root /opt/porsche-security-suite/scripts/backup.sh" >> /etc/cron.d/porsche-security-monitoring
    
    success "Backup and restore scripts created"
}

# Start services
start_services() {
    log "Starting services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start the security suite service
    systemctl enable porsche-security-suite
    systemctl start porsche-security-suite
    
    # Check service status
    if systemctl is-active --quiet porsche-security-suite; then
        success "Porsche Security Suite service started successfully"
    else
        error "Failed to start Porsche Security Suite service"
    fi
    
    # Restart nginx if dashboard is enabled
    if [[ -f "/etc/nginx/sites-enabled/porsche-security-dashboard" ]]; then
        nginx -t && systemctl reload nginx
        success "Nginx configuration reloaded"
    fi
    
    # Start monitoring
    systemctl restart cron
    success "Monitoring cron jobs activated"
}

# Validate deployment
validate_deployment() {
    log "Validating deployment..."
    
    local validation_errors=0
    
    # Check service status
    if ! systemctl is-active --quiet porsche-security-suite; then
        error "Security suite service is not running"
        ((validation_errors++))
    fi
    
    # Check log files
    if [[ ! -f "/var/log/porsche-security/security-suite-$DEPLOYMENT_ENV.log" ]]; then
        warning "Log file not found (may be created after first run)"
    fi
    
    # Check configuration files
    local config_files=(
        "/etc/porsche-security/security-suite.conf"
        "/etc/porsche-security/environments/$DEPLOYMENT_ENV.conf"
        "/etc/systemd/system/porsche-security-suite.service"
    )
    
    for config_file in "${config_files[@]}"; do
        if [[ ! -f "$config_file" ]]; then
            error "Configuration file missing: $config_file"
            ((validation_errors++))
        fi
    done
    
    # Check script files
    local required_scripts=(
        "/opt/porsche-security-suite/scripts/comprehensive_test_orchestrator.js"
        "/opt/porsche-security-suite/scripts/automated_vulnerability_scanner.js"
        "/opt/porsche-security-suite/scripts/monitor.sh"
    )
    
    for script in "${required_scripts[@]}"; do
        if [[ ! -f "$script" ]]; then
            error "Required script missing: $script"
            ((validation_errors++))
        fi
    done
    
    if [[ $validation_errors -eq 0 ]]; then
        success "Deployment validation passed"
        return 0
    else
        error "Deployment validation failed with $validation_errors errors"
        return 1
    fi
}

# Main deployment function
main() {
    log "Starting Porsche Security Testing Suite deployment for environment: $DEPLOYMENT_ENV"
    
    check_prerequisites
    create_directory_structure
    install_security_suite
    create_configuration
    setup_monitoring
    setup_web_dashboard
    setup_ssl_certificates
    create_backup_scripts
    start_services
    validate_deployment
    
    success "Deployment completed successfully!"
    
    echo
    echo "=== Deployment Summary ==="
    echo "Environment: $DEPLOYMENT_ENV"
    echo "Installation Directory: /opt/porsche-security-suite"
    echo "Configuration Directory: /etc/porsche-security"
    echo "Log Directory: /var/log/porsche-security"
    echo "Service Name: porsche-security-suite"
    echo
    echo "=== Next Steps ==="
    echo "1. Review configuration files in /etc/porsche-security/"
    echo "2. Update SSL certificates for production use"
    echo "3. Configure notification endpoints (Slack, email, etc.)"
    echo "4. Access web dashboard at https://$(hostname):8443"
    echo "5. Monitor logs: tail -f /var/log/porsche-security/security-suite-$DEPLOYMENT_ENV.log"
    echo
    echo "=== Service Management ==="
    echo "Start:   systemctl start porsche-security-suite"
    echo "Stop:    systemctl stop porsche-security-suite"
    echo "Status:  systemctl status porsche-security-suite"
    echo "Logs:    journalctl -u porsche-security-suite -f"
    echo
}

# Run main function
main "$@"