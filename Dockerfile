# Porsche Security Testing Suite - Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM node:18-alpine AS builder

LABEL maintainer="Porsche Security Team <security@porsche.com>"
LABEL description="Porsche Security Testing Suite - Comprehensive vulnerability assessment platform"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    git \
    python3 \
    make \
    g++ \
    curl \
    bash

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy security testing scripts
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY dashboard/ ./dashboard/

# Set proper permissions
RUN chmod +x scripts/*.js && \
    chmod +x scripts/*.sh

# Production stage
FROM node:18-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    bash \
    nginx \
    supervisor \
    openssl \
    ca-certificates \
    tzdata

# Create non-root user for security
RUN addgroup -g 1001 -S porsche && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G porsche -g porsche porsche

# Set working directory
WORKDIR /app

# Copy from builder stage
COPY --from=builder --chown=porsche:porsche /app ./

# Create necessary directories
RUN mkdir -p \
    /app/logs \
    /app/reports \
    /app/backups \
    /var/log/porsche-security \
    /etc/porsche-security \
    /var/run/nginx \
    /var/cache/nginx && \
    chown -R porsche:porsche /app /var/log/porsche-security /etc/porsche-security && \
    chown -R nginx:nginx /var/run/nginx /var/cache/nginx

# Copy configuration files
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/security-suite.conf /etc/porsche-security/security-suite.conf

# Create SSL certificates (self-signed for development)
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/porsche-security.key \
    -out /etc/ssl/certs/porsche-security.crt \
    -subj "/C=DE/ST=Baden-Württemberg/L=Stuttgart/O=Porsche AG/OU=Security Team/CN=security.porsche.local" && \
    chmod 600 /etc/ssl/private/porsche-security.key && \
    chmod 644 /etc/ssl/certs/porsche-security.crt

# Expose ports
EXPOSE 3000 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f https://localhost:8443/health || exit 1

# Set environment variables
ENV NODE_ENV=production \
    CONFIG_FILE=/etc/porsche-security/security-suite.conf \
    LOG_LEVEL=info \
    TZ=Europe/Berlin

# Switch to non-root user
USER porsche

# Start supervisor to manage multiple processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]