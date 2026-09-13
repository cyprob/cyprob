# Output Formats

Vulntor supports multiple output formats for different use cases and integrations.

## Terminal Output (default)

Human-readable text output:

```bash
vulntor scan --targets 192.168.1.100
```

```
[INFO] Scan started: scan-20231006-143022
[INFO] Discovery: 1/1 hosts live
[INFO] Port scanning: 192.168.1.100
[INFO] Found 5 open ports
[INFO] Fingerprinting services...
[INFO] Scan complete in 45s
[INFO] Results: ~/.local/share/vulntor/scans/20231006-143022-a1b2c3/
```

## JSON Output

Machine-readable structured output:

```bash
vulntor scan --targets 192.168.1.100 --output json
```

```json
{
  "scan_id": "20231006-143022-a1b2c3",
  "timestamp": "2023-10-06T14:30:22Z",
  "targets": ["192.168.1.100"],
  "results": [
    {
      "host": "192.168.1.100",
      "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
      ]
    }
  ]
}
```

## JSONL Output

Line-delimited JSON (streamable):

```bash
vulntor scan --targets 192.168.1.100 --output jsonl
```

```jsonl
{"timestamp":"2023-10-06T14:30:22Z","host":"192.168.1.100","state":"up"}
{"timestamp":"2023-10-06T14:30:45Z","host":"192.168.1.100","port":22,"state":"open"}
```

## CSV Output

Tabular format for spreadsheets:

```bash
vulntor scan --targets 192.168.1.100 --output csv
```

```csv
host,port,protocol,state,service,version
192.168.1.100,22,tcp,open,ssh,OpenSSH 8.2p1
192.168.1.100,80,tcp,open,http,nginx 1.18.0
```

## File Output

Write results to file:

```bash
vulntor scan --targets 192.168.1.100 -o results.json
vulntor scan --targets 192.168.1.100 --output-file report.csv --format csv
```

## Progress and Verbosity

### Progress Display

Show real-time progress:

```bash
vulntor scan --targets 192.168.1.0/24 --progress
```

```
[=====>                    ] 25% (50/200 hosts scanned)
Currently scanning: 192.168.1.50-192.168.1.60
Elapsed: 2m 15s | Estimated remaining: 6m 45s
```

### Verbosity Levels

Increase log detail:

```bash
# Standard logging (info level)
vulntor scan --targets 192.168.1.100

# Verbose (debug level)
vulntor scan --targets 192.168.1.100 -v

# Very verbose (trace level with module details)
vulntor scan --targets 192.168.1.100 -vv

# Maximum verbosity (all events and data flow)
vulntor scan --targets 192.168.1.100 -vvv
```

### Quiet Mode

Suppress all output except errors:

```bash
vulntor scan --targets 192.168.1.100 --quiet
```

Use in scripts where only exit code matters:

```bash
if vulntor scan --targets 192.168.1.100 --quiet; then
    echo "Scan successful"
else
    echo "Scan failed"
fi
```

## Exit Codes

Vulntor uses standard Unix exit codes:

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | General error |
| 2    | Usage error (invalid arguments) |
| 3    | Configuration error |
| 4    | Network error |
| 5    | Permission error |
| 6    | Timeout |
| 7    | Scan failed (partial results may be available) |

Use in scripts:

```bash
vulntor scan --targets 192.168.1.100
case $? in
    0) echo "Success" ;;
    4) echo "Network error" ;;
    7) echo "Scan failed, check logs" ;;
    *) echo "Unknown error" ;;
esac
```
