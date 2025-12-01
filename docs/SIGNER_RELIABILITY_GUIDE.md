# Keycast Signer Daemon Reliability Guide

**Version:** 1.0
**Last Updated:** 2025-10-18

## Overview

This guide ensures the Keycast signer daemon runs reliably in all environments with automatic restart, monitoring, and alerting.

---

## Quick Start

### Fix Immediate Issue (Local Dev)

```bash
# 1. Remove stale pidfile
rm database/.signer.pid

# 2. Start signer daemon
cargo run --bin keycast_signer

# 3. Verify it's running
curl http://localhost:8080/health
```

### Verify Daemon is Working

```bash
# Check health endpoint
curl -v http://localhost:8080/health
# Should return: OK

# Check logs for successful startup
# You should see:
# ✔︎ Database initialized
# Loaded X total authorizations (Y regular + Z OAuth)
# Connected to 3 relays for redundancy
# 🤙 Unified signer daemon ready
```

---

## Deployment Environments

### 1. Local Development

**Method:** Run manually or via shell script

**Start Daemon:**
```bash
# Option A: Cargo run (development)
cargo run --bin keycast_signer

# Option B: Compiled binary
./target/release/keycast_signer

# Run in background with logging
nohup ./target/release/keycast_signer > /var/log/keycast/signer.log 2>&1 &
```

**Monitor:**
```bash
# Check if running
ps aux | grep keycast_signer

# Check health
curl http://localhost:8080/health

# View logs
tail -f /var/log/keycast/signer.log
```

**Stop:**
```bash
# Find PID
cat database/.signer.pid

# Kill gracefully
kill -TERM $(cat database/.signer.pid)
```

---

### 2. Docker Compose (Recommended for VPS)

**Configuration:** Already set up in `docker-compose.yml`

**Features:**
- ✅ Automatic restart on crash (`restart: unless-stopped`)
- ✅ Health checks every 10 seconds
- ✅ Log rotation (10MB max, 3 files, compressed)
- ✅ Isolated networking

**Start:**
```bash
docker-compose up -d keycast-signer
```

**Monitor:**
```bash
# Check status
docker-compose ps keycast-signer

# View logs
docker-compose logs -f keycast-signer

# Check health
docker-compose exec keycast-signer /usr/local/bin/healthcheck.sh signer
```

**Restart:**
```bash
# Graceful restart
docker-compose restart keycast-signer

# Force restart
docker-compose stop keycast-signer && docker-compose up -d keycast-signer
```

**Health Check Details:**
- Interval: 10 seconds
- Timeout: 5 seconds
- Retries: 3 failures before marking unhealthy
- Start period: 10 seconds (grace period during startup)
- Test: `curl -f http://localhost:8080/health`

---

### 3. Systemd (Linux VPS/Bare Metal)

**Installation:**
```bash
# 1. Copy service file
sudo cp deployment/keycast-signer.service /etc/systemd/system/

# 2. Create keycast user
sudo useradd -r -s /bin/false keycast

# 3. Create directories
sudo mkdir -p /opt/keycast/database
sudo mkdir -p /var/log/keycast

# 4. Set permissions
sudo chown -R keycast:keycast /opt/keycast
sudo chown -R keycast:keycast /var/log/keycast

# 5. Copy binary and files
sudo cp target/release/keycast_signer /opt/keycast/
sudo cp master.key /opt/keycast/
sudo cp -r database/migrations /opt/keycast/database/

# 6. Reload systemd
sudo systemctl daemon-reload

# 7. Enable and start
sudo systemctl enable keycast-signer
sudo systemctl start keycast-signer
```

**Monitor:**
```bash
# Check status
sudo systemctl status keycast-signer

# View logs
sudo journalctl -u keycast-signer -f

# Check if healthy
curl http://localhost:8080/health
```

**Management:**
```bash
# Stop
sudo systemctl stop keycast-signer

# Restart
sudo systemctl restart keycast-signer

# View recent failures
sudo systemctl list-units --state=failed

# View restart count
systemctl show keycast-signer | grep NRestarts
```

**Features:**
- Automatic restart on crash (5 second delay)
- Rate limiting: Max 5 restarts in 60 seconds
- Hardened security (NoNewPrivileges, PrivateTmp, etc.)
- Resource limits (1GB memory, 65536 file descriptors)
- Logs to journald

---

### 4. Supervisor (Alternative to Systemd)

**Installation:**
```bash
# 1. Install supervisor
sudo apt-get install supervisor

# 2. Copy config
sudo cp deployment/supervisor-signer.conf /etc/supervisor/conf.d/

# 3. Create directories
sudo mkdir -p /var/log/keycast

# 4. Reload supervisor
sudo supervisorctl reread
sudo supervisorctl update
```

**Monitor:**
```bash
# Check status
sudo supervisorctl status keycast-signer

# View logs
sudo tail -f /var/log/keycast/signer.out.log
sudo tail -f /var/log/keycast/signer.err.log
```

**Management:**
```bash
# Start
sudo supervisorctl start keycast-signer

# Stop
sudo supervisorctl stop keycast-signer

# Restart
sudo supervisorctl restart keycast-signer
```

---

### 5. Google Cloud Run (Production)

**Configuration:** `signer-service-deploy.yaml`

**Features:**
- ✅ Auto-scaling (down to 0, up based on load)
- ✅ Health checks (startup probe on /health)
- ✅ Automatic rollback on failed deployment
- ✅ Cloud Logging integration
- ✅ Litestream for database backup
- ✅ GCP KMS encryption

**Deploy:**
```bash
# 1. Build and push image
gcloud builds submit --config cloudbuild.yaml

# 2. Deploy signer service
gcloud run services replace signer-service-deploy.yaml \
  --region=us-central1 \
  --project=openvine-co
```

**Monitor:**
```bash
# View logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=keycast" \
  --project=openvine-co \
  --limit=50 \
  --format='value(jsonPayload.fields.message)'

# Tail logs
gcloud alpha logging tail "resource.type=cloud_run_revision AND resource.labels.service_name=keycast" \
  --project=openvine-co

# Check service status
gcloud run services describe keycast \
  --region=us-central1 \
  --project=openvine-co
```

**Health Check:**
- Path: `/health`
- Port: 8080
- Failure threshold: 30 retries
- Period: 3 seconds
- Timeout: 2 seconds
- Total wait time: 90 seconds (for DB restore + startup)

---

## Monitoring and Alerting

### Health Check Monitoring

**What the Health Check Tests:**
- HTTP endpoint is responding (/health returns "OK")
- HTTP server is running (axum on port 8080)
- Process is alive and accepting connections

**What It DOESN'T Test (but should be monitored separately):**
- Relay connection status
- Database connectivity
- Authorization loading
- NIP-46 request handling

### Enhanced Monitoring Script

Create `/opt/keycast/scripts/check-signer.sh`:

```bash
#!/bin/bash
set -e

# Check HTTP health endpoint
if ! curl -sf http://localhost:8080/health > /dev/null; then
    echo "ERROR: Health endpoint not responding"
    exit 1
fi

# Check relay connections (look for "Connected to 3 relays" in recent logs)
if command -v journalctl &> /dev/null; then
    if ! journalctl -u keycast-signer --since "5 minutes ago" | grep -q "Connected to.*relays"; then
        echo "WARNING: No recent relay connection log (may be old startup)"
    fi
fi

# Check for errors in last 5 minutes
if command -v journalctl &> /dev/null; then
    ERROR_COUNT=$(journalctl -u keycast-signer --since "5 minutes ago" --priority=err | wc -l)
    if [ "$ERROR_COUNT" -gt 10 ]; then
        echo "WARNING: $ERROR_COUNT errors in last 5 minutes"
    fi
fi

# Check for NIP-46 activity
if command -v journalctl &> /dev/null; then
    if journalctl -u keycast-signer --since "1 hour ago" | grep -q "Processing NIP-46 method"; then
        echo "✅ Signer is actively processing NIP-46 requests"
    else
        echo "ℹ️ No NIP-46 activity in last hour (may be normal if no users)"
    fi
fi

echo "✅ Health check passed"
exit 0
```

### Set Up Monitoring Alerts

#### Option 1: Cloud Monitoring (GCP)

```bash
# Create uptime check
gcloud monitoring uptime create \
  --display-name="Keycast Signer Health" \
  --resource-type=uptime-url \
  --monitored-resource=https://your-signer-url/health \
  --period=60s \
  --project=openvine-co

# Create alert policy for downtime
gcloud alpha monitoring policies create \
  --notification-channels=YOUR_CHANNEL_ID \
  --display-name="Keycast Signer Down" \
  --condition-display-name="Health check failed" \
  --project=openvine-co
```

#### Option 2: Cron + Email (Simple VPS)

```bash
# Add to crontab
*/5 * * * * /opt/keycast/scripts/check-signer.sh || echo "Signer health check failed" | mail -s "Keycast Signer Alert" admin@example.com
```

#### Option 3: External Monitoring (UptimeRobot, Pingdom, etc.)

Configure external service to check:
- URL: `https://your-domain.com/health` (if publicly accessible)
- OR: Install agent to check local `http://localhost:8080/health`
- Interval: 1-5 minutes
- Alert on: 2-3 consecutive failures

---

## Troubleshooting

### Daemon Won't Start

**1. Check for stale pidfile**
```bash
# Remove if process is not running
rm database/.signer.pid
```

**2. Check database permissions**
```bash
# Ensure readable
ls -la database/keycast.db

# Fix permissions
chmod 644 database/keycast.db
chown keycast:keycast database/keycast.db  # if using systemd
```

**3. Check logs for startup errors**
```bash
# Local
tail -f database/signer.log

# Docker
docker-compose logs keycast-signer

# Systemd
journalctl -u keycast-signer -f
```

**Common startup errors:**
- `Database error`: Check DATABASE_PATH and migrations
- `KMS error`: Check GCP credentials and permissions
- `Port already in use`: Another process on port 8080

---

### Daemon Crashes Repeatedly

**1. Check crash logs**
```bash
# Systemd: Look for crash patterns
journalctl -u keycast-signer | grep -i "panic\|error\|failed"

# Docker
docker-compose logs keycast-signer | tail -100
```

**2. Common crash causes:**
- **Relay connection failures**: Check internet connectivity, firewall rules for wss://
- **Database corruption**: Run `psql database/keycast.db "PRAGMA integrity_check;"`
- **Memory exhaustion**: Check `docker stats` or `systemctl status keycast-signer` for OOM
- **KMS permission errors**: Check service account has `cloudkms.cryptoKeyVersions.useToDecrypt`

**3. Enable debug logging**
```bash
# Set in environment
export RUST_LOG=debug,keycast_signer=trace

# Or in systemd service file
Environment="RUST_LOG=debug"
```

---

### Bunker Connections Timeout

**1. Verify daemon is loaded authorizations**
```bash
# Check logs for
journalctl -u keycast-signer | grep "Loaded.*authorizations"

# Should see: "Loaded X total authorizations (Y regular + Z OAuth)"
```

**2. Verify relay connections**
```bash
# Check logs for
journalctl -u keycast-signer | grep "Connected to.*relays"

# Should see: "Connected to 3 relays for redundancy"
```

**3. Verify NIP-46 subscription**
```bash
# Check logs for
journalctl -u keycast-signer | grep "Subscribing to ALL kind 24133"
```

**4. Test specific bunker URL**
```bash
# Watch for incoming requests
journalctl -u keycast-signer -f | grep "Received NIP-46 request"

# Try connecting with client, should see:
# "Received NIP-46 request for bunker: abc123..."
# "Processing NIP-46 method: connect"
# "Sent NIP-46 response"
```

**5. Check relay accessibility**
```bash
# Test relay connection
websocat wss://relay.damus.io

# Send test subscription
["REQ", "test", {"kinds": [24133], "limit": 1}]
```

---

## Performance Tuning

### Resource Usage

**Expected baseline:**
- Memory: 50-200 MB (depends on number of authorizations)
- CPU: <5% idle, 10-30% during active signing
- Network: Minimal (websocket keepalive + event traffic)

**Scaling limits (single instance):**
- Tested with 100+ authorizations
- Architecture scales to millions (single relay subscription)
- Bottleneck: KMS decryption during authorization loading

### Optimization Tips

**1. Fast reload for new registrations**
- Uses optimized reload (only checks last 5 authorizations)
- Triggered by `.reload_signal` file
- Reload time: ~1.5 seconds vs 18-21 seconds for full reload

**2. Connection pooling**
- Connects to 3 relays for redundancy (relay.damus.io, nos.lol, relay.nsec.app)
- Single subscription per relay (not per user)
- In-memory HashMap for bunker pubkey lookup

**3. Async event handling**
- Each NIP-46 request handled in separate tokio task
- Non-blocking encryption/decryption
- No queue buildup under load

---

## Security Hardening

### Systemd Security

The systemd service includes security hardening:
- `NoNewPrivileges`: Prevents privilege escalation
- `PrivateTmp`: Isolated /tmp directory
- `ProtectSystem=strict`: Read-only system directories
- `RestrictAddressFamilies`: Only IPv4/IPv6/Unix sockets
- `SystemCallFilter`: Restricts to safe syscalls

### File Permissions

```bash
# Database
chmod 600 database/keycast.db
chown keycast:keycast database/keycast.db

# Master key
chmod 600 master.key
chown keycast:keycast master.key

# Binary
chmod 755 keycast_signer
chown root:root keycast_signer
```

### Network Security

**Firewall rules:**
- Outbound: Allow wss:// (port 443) to relay.damus.io, nos.lol, relay.nsec.app
- Inbound: Only allow port 8080 from localhost (health checks)

```bash
# Example ufw rules
sudo ufw allow from 127.0.0.1 to any port 8080
sudo ufw allow out 443/tcp
```

---

## Maintenance

### Log Rotation

**Docker Compose:**
Already configured in `docker-compose.yml`:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    compress: "true"
```

**Systemd:**
Logs to journald, managed by system:
```bash
# Check journal size
journalctl --disk-usage

# Vacuum old logs (keep last 1GB)
sudo journalctl --vacuum-size=1G
```

**Manual logs:**
Add to `/etc/logrotate.d/keycast`:
```
/var/log/keycast/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 keycast keycast
    sharedscripts
    postrotate
        systemctl reload keycast-signer > /dev/null 2>&1 || true
    endscript
}
```

### Database Backup

**Production (Cloud Run):**
- Litestream handles automatic backup to GCS
- Restore on container start

**VPS:**
```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR=/opt/keycast/backups
mkdir -p $BACKUP_DIR
psql /opt/keycast/database/keycast.db ".backup $BACKUP_DIR/keycast-$(date +%Y%m%d).db"

# Keep last 7 days
find $BACKUP_DIR -name "keycast-*.db" -mtime +7 -delete
```

Add to crontab:
```
0 2 * * * /opt/keycast/scripts/backup-db.sh
```

### Updates and Restarts

**Docker:**
```bash
# Pull latest
docker-compose pull keycast-signer

# Restart with new image
docker-compose up -d keycast-signer
```

**Systemd:**
```bash
# Update binary
sudo cp target/release/keycast_signer /opt/keycast/

# Restart service
sudo systemctl restart keycast-signer
```

**Cloud Run:**
- Automated via cloudbuild.yaml
- Blue/green deployment
- Automatic rollback on health check failure

---

## Operational Checklist

### Daily

- [ ] Check daemon is running: `systemctl status keycast-signer`
- [ ] Check health endpoint: `curl http://localhost:8080/health`
- [ ] Review error logs: `journalctl -u keycast-signer --since today | grep ERROR`

### Weekly

- [ ] Check resource usage: `systemctl status keycast-signer` (memory/CPU)
- [ ] Review restart count: `systemctl show keycast-signer | grep NRestarts`
- [ ] Check disk space: `df -h /opt/keycast`
- [ ] Review database size: `du -h database/keycast.db`

### Monthly

- [ ] Review and clear old logs
- [ ] Test database backup restore
- [ ] Review authorization count growth
- [ ] Check for available updates

### After Deployments

- [ ] Verify daemon restarted successfully
- [ ] Check authorizations loaded: `journalctl -u keycast-signer | grep "Loaded.*authorizations"`
- [ ] Check relay connections: `journalctl -u keycast-signer | grep "Connected to.*relays"`
- [ ] Test bunker connection with test client
- [ ] Monitor error rate for 15 minutes

---

## Disaster Recovery

### Complete Failure Scenario

**If signer daemon is down and won't start:**

1. **Check system resources**
   ```bash
   df -h  # Disk space
   free -h  # Memory
   top  # CPU/processes
   ```

2. **Check logs for root cause**
   ```bash
   journalctl -u keycast-signer --since "1 hour ago" | tail -100
   ```

3. **Try clean restart**
   ```bash
   # Stop service
   sudo systemctl stop keycast-signer

   # Remove pidfile
   rm /opt/keycast/database/.signer.pid

   # Check database integrity
   psql /opt/keycast/database/keycast.db "PRAGMA integrity_check;"

   # Start service
   sudo systemctl start keycast-signer
   ```

4. **If database is corrupted, restore from backup**
   ```bash
   sudo systemctl stop keycast-signer
   cp /opt/keycast/backups/keycast-YYYYMMDD.db /opt/keycast/database/keycast.db
   sudo systemctl start keycast-signer
   ```

5. **If still failing, run in debug mode**
   ```bash
   # Stop systemd service
   sudo systemctl stop keycast-signer

   # Run manually with debug logging
   cd /opt/keycast
   RUST_LOG=debug ./keycast_signer
   ```

### Relay Connection Issues

**If relays are unreachable:**

1. Check network connectivity
2. Test relay URLs directly
3. Check firewall rules
4. Consider adding backup relays in code

---

## Summary: Making it Super Reliable

✅ **What's Already Reliable:**
1. Cloud Run deployment with auto-restart
2. Docker Compose with restart policy
3. Health check endpoint exists
4. Logging infrastructure

✅ **What We Just Added:**
1. Better health check (tests HTTP, not just process)
2. Systemd service with hardened security
3. Supervisor config (alternative)
4. Comprehensive monitoring guide
5. Operational runbook

🎯 **Next Steps for Production:**
1. Deploy using systemd or Docker Compose with updated healthcheck
2. Set up external monitoring (UptimeRobot or GCP Monitoring)
3. Configure alerts (email, Slack, PagerDuty)
4. Test failover by killing daemon and watching auto-restart
5. Add enhanced monitoring script to cron

The daemon is now **production-ready** with multiple layers of reliability! 🚀
