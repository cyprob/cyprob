# vulntor scan

Execute security scans against target hosts and networks.

## Synopsis

```bash
vulntor scan --targets <targets> [flags]
vulntor scan --target-file <file> [flags]
```

## Description

The `scan` command performs comprehensive security scanning including host discovery, port scanning, service fingerprinting, and optional vulnerability assessment. It orchestrates the complete scan pipeline through the DAG engine.

## Basic Usage

### Single Target

```bash
vulntor scan --targets 192.168.1.100
```

### CIDR Range

```bash
vulntor scan --targets 192.168.1.0/24
```

### Multiple Targets

```bash
vulntor scan --targets "192.168.1.100,192.168.1.200,10.0.0.1"
```

### From File

```bash
vulntor scan --target-file targets.txt
```

`targets.txt` format (one target per line):
```
192.168.1.100
192.168.1.0/24
example.com
10.0.0.1-10.0.0.254
```

## Target Specification

### --targets, -t

Comma-separated list of targets.

**Formats**:
- Single IP: `192.168.1.100`
- CIDR: `192.168.1.0/24`
- Range: `192.168.1.1-192.168.1.254`
- Hostname: `example.com`
- Multiple: `192.168.1.100,10.0.0.0/24`

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24
vulntor scan -t "192.168.1.100,192.168.1.200"
```

### --target-file, -f

Read targets from file (one per line).

**Example**:
```bash
vulntor scan --target-file /path/to/targets.txt
vulntor scan -f targets.txt
```

### --exclude

Exclude specific targets or ranges.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

### --exclude-file

Read exclusions from file.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --exclude-file blocklist.txt
```

## Scan Profiles

### --profile, -p

Use predefined scan profile.

**Built-in Profiles**:
- `quick`: Fast scan, top 100 ports, minimal fingerprinting
- `standard`: Balanced scan, top 1000 ports (default)
- `deep`: Comprehensive scan, all 65535 ports
- `webapp`: Web application focus
- `infrastructure`: Network device focus

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --profile deep
vulntor scan -t example.com -p webapp
```

### Custom Profiles

Reference custom profile file:

```bash
vulntor scan --targets 192.168.1.100 --profile /path/to/custom-profile.yaml
```

See Scan Profiles for profile structure.

## Phase Control

### --only-discover

Run discovery phase only (identify live hosts).

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --only-discover
```

Output: List of responsive hosts, no port scanning.

### --no-discover

Skip discovery phase (assume targets are live).

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --no-discover
```

Useful when targets are known to be live or ICMP is blocked.

### --vuln

Enable vulnerability evaluation.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --vuln
```

Matches service versions against CVE database.

### --no-vuln

Disable vulnerability checks (faster).

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --no-vuln
```

### --no-fingerprint

Skip service fingerprinting.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --no-fingerprint
```

Only reports port states, no service identification.

## Discovery Options

### --discover-profile

Select discovery method.

**Options**:
- `fast`: ICMP only
- `standard`: ICMP + ARP (default)
- `deep`: ICMP + ARP + TCP SYN probes
- `tcp`: TCP SYN only (no ICMP)

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --discover-profile deep
```

### --discovery-timeout

Discovery probe timeout.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --discovery-timeout 5s
```

### --discovery-retry

Number of discovery retries.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --discovery-retry 3
```

## Port Scanning Options

### --ports

Specify ports to scan.

**Formats**:
- Single: `80`
- List: `80,443,8080`
- Range: `1-1000`
- Mixed: `22,80,443,8000-9000`

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --ports 80,443
vulntor scan --targets 192.168.1.100 --ports 1-65535
```

### --top-ports

Scan top N most common ports.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --top-ports 100
```

### --rate, -r

Packets per second rate limit.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --rate 5000
vulntor scan -t 192.168.1.100 -r 100
```

Lower rates are less disruptive but slower.

### --timeout

Connection timeout for port probes.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --timeout 5s
```

### --scan-type

Port scanning technique.

**Options**:
- `syn`: TCP SYN scan (default, requires root)
- `connect`: Full TCP connect (no root required)
- `udp`: UDP scan

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --scan-type connect
```

### --max-retries

Port scan retry attempts.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --max-retries 2
```

## Fingerprinting Options

### --fingerprint-cache

Use cached fingerprint database.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --fingerprint-cache
```

### --fingerprint-rules

Load custom fingerprint rules.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --fingerprint-rules custom-rules.yaml
```

### --fingerprint-timeout

Fingerprint probe timeout.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --fingerprint-timeout 10s
```

### --max-protocols

Maximum protocols to probe per port.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --max-protocols 2
```

## Output Options

### --output, -o

Output file path.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --output results.json
vulntor scan -t 192.168.1.100 -o scan-report.csv
```

### --format

Output format.

**Options**:
- `json`: Structured JSON
- `jsonl`: Line-delimited JSON
- `csv`: Comma-separated values
- `text`: Human-readable text (default)

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --format json
vulntor scan --targets 192.168.1.100 --format csv --output report.csv
```

### --template

Use custom output template.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --template custom-report.tmpl
```

## Storage Options

### --storage-dir

Specify storage directory.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --storage-dir /data/vulntor
```

### --no-storage

Disable storage persistence (stateless mode).

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --no-storage
```

Results output to stdout/file only, no storage persistence.

### --scan-name

Assign custom scan name.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --scan-name "Production Network Audit"
```

### --tags

Add tags to scan for organization.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --tags "production,weekly,compliance"
```

## Concurrency Options

### --concurrency

Maximum concurrent target scans.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --concurrency 50
```

### --port-concurrency

Maximum concurrent ports per host.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --port-concurrency 100
```

## Server Mode Options

### --server

Vulntor server URL for remote execution.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --server https://vulntor.company.com
```

Requires `VULNTOR_API_TOKEN` environment variable or `--api-token` flag.

### --api-token

API authentication token.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --server https://vulntor.company.com --api-token your-token
```

### --schedule

Create recurring scan (server mode only).

**Format**: Cron expression

**Example**:
```bash
# Daily at 2 AM
vulntor scan --targets 192.168.1.0/24 --schedule "0 2 * * *" --server https://vulntor.company.com

# Every 6 hours
vulntor scan --targets 192.168.1.0/24 --schedule "0 */6 * * *"
```

### --notify

Notification channels for scan results.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --notify slack://security-alerts
vulntor scan --targets 192.168.1.100 --notify "slack://alerts,email://team@company.com"
```

## Logging Options

### --log-level

Logging verbosity.

**Options**: `debug`, `info`, `warn`, `error`

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --log-level debug
```

### --log-format

Log output format.

**Options**: `json`, `text`

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --log-format json
```

### --verbosity, -v

Shorthand verbosity levels.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 -v      # Verbose
vulntor scan --targets 192.168.1.100 -vv     # Very verbose
vulntor scan --targets 192.168.1.100 -vvv    # Maximum verbosity
```

### --quiet, -q

Suppress non-error output.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --quiet
```

### --progress

Show real-time progress.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --progress
```

## DAG Options

### --dag

Use custom DAG definition.

**Example**:
```bash
vulntor scan --targets 192.168.1.100 --dag custom-pipeline.yaml
```

### --fail-fast

Stop on first error.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --fail-fast
```

### --continue-on-error

Continue scanning despite errors.

**Example**:
```bash
vulntor scan --targets 192.168.1.0/24 --continue-on-error
```

## Examples

### Quick Network Discovery

```bash
vulntor scan --targets 192.168.1.0/24 --only-discover
```

### Standard Scan with Vulnerability Checks

```bash
vulntor scan --targets 192.168.1.100 --vuln
```

### Deep Scan of Web Server

```bash
vulntor scan --targets example.com --profile webapp --ports 80,443,8000-9000
```

### Large Network Scan with Rate Limiting

```bash
vulntor scan --targets 10.0.0.0/16 \
  --rate 500 \
  --concurrency 100 \
  --timeout 5s \
  --output full-scan.json
```

### Stateless Scan (No Storage)

```bash
vulntor scan --targets 192.168.1.100 \
  --no-storage \
  --output /tmp/scan-results.json
```

### Remote Execution via Server

```bash
export VULNTOR_SERVER=https://vulntor.company.com
export VULNTOR_API_TOKEN=abc123xyz

vulntor scan --targets 192.168.1.0/24 \
  --profile standard \
  --notify slack://security-team
```

### Scheduled Weekly Scan

```bash
vulntor scan --targets production-network.txt \
  --schedule "0 2 * * 0" \
  --tags "production,weekly" \
  --vuln \
  --notify "slack://prod-alerts,email://security@company.com" \
  --server https://vulntor.company.com
```

### Custom Ports and Fingerprinting

```bash
vulntor scan --targets 192.168.1.100 \
  --ports "22,80,443,3306,5432,6379,8080,8443" \
  --fingerprint-rules custom-signatures.yaml \
  --fingerprint-timeout 10s
```

### Exclude Sensitive Hosts

```bash
vulntor scan --targets 10.0.0.0/24 \
  --exclude "10.0.0.1,10.0.0.254" \
  --exclude-file sensitive-hosts.txt
```

### Debug Failed Scan

```bash
vulntor scan --targets 192.168.1.100 \
  --log-level debug \
  --log-format json \
  --verbosity 3 \
  2> debug.log
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Network error |
| 5 | Permission denied (requires root for SYN scan) |
| 6 | Scan timeout |
| 7 | Partial failure (some targets failed) |

## Notes

### Root Permissions

TCP SYN scans require raw socket access:

```bash
sudo vulntor scan --targets 192.168.1.0/24
```

Alternatives without root:
- Use `--scan-type connect` (full TCP connect)
- Run Vulntor with `CAP_NET_RAW` capability:
  ```bash
  sudo setcap cap_net_raw+ep /usr/local/bin/vulntor
  vulntor scan --targets 192.168.1.0/24
  ```

### Performance Tuning

For large scans:
- Increase `--rate` (default: 1000)
- Increase `--concurrency` (default: 100)
- Use `--no-fingerprint` for faster scans
- Use `--profile quick` for top ports only

### Network Considerations

- Aggressive scans may trigger IDS/IPS alerts
- Respect rate limits to avoid network congestion
- Use `--rate 100` for production networks
- Consider scan windows and maintenance schedules

## See Also

- [CLI Overview](./overview.md) - Command structure and usage patterns
- Scan Pipeline - Understanding scan stages
- Scan Profiles - Creating custom profiles
- Network Scanning Guide - Best practices
