# vulntor server

Control Vulntor server daemon for centralized scan orchestration.

## Synopsis

```bash
vulntor server <subcommand> [flags]
```

## Description

The `server` command manages the Vulntor server daemon, which provides:
- REST API for scan submission
- Job queue and scheduler
- Worker pools for distributed scanning (Enterprise)
- Web UI hosting
- Multi-tenant storage (Enterprise)

## Subcommands

### start

Start Vulntor server.

```bash
vulntor server start [flags]
```

**Flags**:
- `--bind`: Address to bind (default: `0.0.0.0:8080`)
- `--workers`: Number of worker threads (default: CPU cores)
- `--daemon, -d`: Run as background daemon
- `--pid-file`: PID file location

**Examples**:
```bash
# Start server on default port
vulntor server start

# Custom bind address
vulntor server start --bind 127.0.0.1:9090

# Run as daemon
vulntor server start --daemon --pid-file /var/run/vulntor.pid

# With custom workers
vulntor server start --workers 8
```

### stop

Stop running Vulntor server.

```bash
vulntor server stop
```

**Flags**:
- `--force`: Force shutdown (don't wait for running scans)
- `--timeout`: Graceful shutdown timeout (default: 30s)

**Examples**:
```bash
# Graceful stop
vulntor server stop

# Force stop
vulntor server stop --force

# Custom timeout
vulntor server stop --timeout 60s
```

### status

Check server status.

```bash
vulntor server status
```

**Output**:
```
Vulntor Server Status
---------------------
Status: running
Uptime: 5 days, 3 hours
PID: 12345
Bind: 0.0.0.0:8080
Workers: 4
Active scans: 2
Queued jobs: 5
Total scans: 1,234
```

**Flags**:
- `--format`: Output format (text, json)

**Examples**:
```bash
# Text status
vulntor server status

# JSON status
vulntor server status --format json
```

### restart

Restart server (stop then start).

```bash
vulntor server restart
```

**Flags**:
- `--force`: Force restart without graceful shutdown

**Examples**:
```bash
# Graceful restart
vulntor server restart

# Force restart
vulntor server restart --force
```

### logs

Display server logs.

```bash
vulntor server logs [flags]
```

**Flags**:
- `--follow, -f`: Follow log output
- `--tail`: Show last N lines (default: 100)
- `--since`: Show logs since time (e.g., `1h`, `2023-10-06`)
- `--level`: Filter by log level

**Examples**:
```bash
# Show last 100 lines
vulntor server logs

# Follow logs
vulntor server logs --follow

# Last 1000 lines
vulntor server logs --tail 1000

# Since 1 hour ago
vulntor server logs --since 1h

# Errors only
vulntor server logs --level error
```

### reload

Reload server configuration without restart.

```bash
vulntor server reload
```

Reloads:
- Configuration files
- Scan profiles
- Notification channels

Does not reload:
- License keys (requires restart)
- Server bind address (requires restart)

**Examples**:
```bash
# Reload config
vulntor server reload
```

## Configuration

Server configuration via YAML:

```yaml
# ~/.config/vulntor/config.yaml
server:
  bind: 0.0.0.0:8080
  workers: 4
  api:
    enabled: true
    auth: true
    rate_limit: 100  # requests per minute
  ui:
    enabled: true
    path: /ui
    static_dir: /usr/share/vulntor/ui
  tls:
    enabled: false
    cert_file: /etc/vulntor/tls/cert.pem
    key_file: /etc/vulntor/tls/key.pem
  cors:
    enabled: true
    origins: ["https://vulntor.company.com"]
  queue:
    max_jobs: 1000
    retention: 7d
  workers:
    min: 2
    max: 10
    auto_scale: true
```

## Systemd Service

### Service File

`/etc/systemd/system/vulntor.service`:

```ini
[Unit]
Description=Vulntor Security Scanner Server
After=network.target

[Service]
Type=simple
User=vulntor
Group=vulntor
WorkingDirectory=/var/lib/vulntor
ExecStart=/usr/local/bin/vulntor server start --bind 0.0.0.0:8080
ExecStop=/usr/local/bin/vulntor server stop
Restart=on-failure
RestartSec=5s

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vulntor /var/log/vulntor

# Resources
LimitNOFILE=65536
MemoryMax=4G

[Install]
WantedBy=multi-user.target
```

### Systemd Commands

```bash
# Enable service
sudo systemctl enable vulntor

# Start service
sudo systemctl start vulntor

# Check status
sudo systemctl status vulntor

# View logs
sudo journalctl -u vulntor -f

# Restart service
sudo systemctl restart vulntor

# Stop service
sudo systemctl stop vulntor
```

## API Endpoints

Server exposes REST API at `/api/v1`:

### Scans

- `POST /api/v1/scans` - Submit new scan
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/{id}` - Get scan details
- `DELETE /api/v1/scans/{id}` - Delete scan

### Jobs

- `POST /api/v1/jobs` - Submit job (Enterprise)
- `GET /api/v1/jobs` - List jobs
- `GET /api/v1/jobs/{id}` - Get job status

### System

- `GET /api/v1/health` - Health check
- `GET /api/v1/version` - Version info
- `GET /api/v1/license` - License status (Enterprise)

See REST API Documentation for details.

## TLS Configuration

Enable HTTPS:

```yaml
server:
  tls:
    enabled: true
    cert_file: /etc/vulntor/tls/cert.pem
    key_file: /etc/vulntor/tls/key.pem
    # Optional: Client certificate authentication
    client_auth: false
    client_ca_file: /etc/vulntor/tls/ca.pem
```

Generate self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Authentication

### API Tokens

Generate API token:

```bash
vulntor server token create --name "CI Pipeline" --scopes scan:read,scan:write
```

Use token:

```bash
curl -H "Authorization: Bearer <token>" https://vulntor.company.com/api/v1/scans
```

### SSO Integration (Enterprise)

Configure OIDC/SAML:

```yaml
server:
  auth:
    provider: oidc
    oidc:
      issuer: https://auth.company.com
      client_id: vulntor
      client_secret: ${OIDC_SECRET}
      redirect_url: https://vulntor.company.com/auth/callback
```

## Monitoring

### Health Checks

```bash
# HTTP health check
curl http://localhost:8080/health

# Detailed status
curl http://localhost:8080/api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "uptime": 432000,
  "version": "1.0.0",
  "workers": {
    "active": 2,
    "idle": 2,
    "total": 4
  },
  "queue": {
    "pending": 5,
    "running": 2,
    "failed": 0
  }
}
```

### Metrics (Enterprise)

Prometheus metrics at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

Metrics include:
- `vulntor_scans_total` - Total scans
- `vulntor_scan_duration_seconds` - Scan duration histogram
- `vulntor_queue_length` - Queue length gauge
- `vulntor_worker_utilization` - Worker utilization

## Troubleshooting

### Server Won't Start

Check logs:
```bash
vulntor server start --log-level debug
```

Common issues:
- Port already in use: Change `--bind` address
- Permission denied: Run with sufficient privileges or `sudo`
- Config error: Validate config with `vulntor config validate`

### High Memory Usage

Reduce workers:
```yaml
server:
  workers: 2
```

Enable memory limits:
```yaml
engine:
  max_memory: 2GB
```

### Slow Response Times

Increase workers:
```yaml
server:
  workers: 8
```

Enable caching:
```yaml
server:
  cache:
    enabled: true
    ttl: 5m
```

## See Also

- Server Deployment - Deployment guide
- REST API - API reference
- Configuration - Server configuration
