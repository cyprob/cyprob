# CLI Overview

The Vulntor command-line interface (CLI) provides direct access to all scanning capabilities, storage management, and server control. The CLI is designed for technical operators performing ad-hoc scans, troubleshooting, and integration into automation workflows.

## Philosophy

### CLI vs UI Design

Vulntor separates technical and non-technical user experiences:

**CLI** targets:

- Security operators and penetration testers
- DevOps engineers and SREs
- Automation and CI/CD pipelines
- Power users requiring fine-grained control

**UI** targets:

- Security managers and executives
- Compliance auditors
- Non-technical stakeholders
- Scheduled scan management

The CLI remains fully functional without the server component, while the UI requires the server for centralized operations.

### Self-Sufficiency

The CLI never accesses server internals directly. When interacting with a remote Vulntor server, the CLI uses the REST/gRPC API just like any external client.

**Local Mode** (no server):

```bash
vulntor scan --targets 192.168.1.0/24
# Executes scan locally, writes to local storage
```

**Remote Mode** (with server):

```bash
vulntor scan --targets 192.168.1.0/24 --server https://vulntor.company.com
# Submits scan job to server via API
```

## Command Structure

```
vulntor <command> [subcommand] [flags] [arguments]
```

## Primary Commands

### vulntor scan

Execute security scans:

```bash
vulntor scan --targets 192.168.1.0/24
```

Performs complete scan pipeline or selective phases. Most commonly used command.

See [Scan Command Reference](./scan.md) for details.

### vulntor storage

Manage storage and scan results:

```bash
vulntor storage list              # List all scans
vulntor storage show <scan-id>    # Show scan details
vulntor storage gc                # Garbage collection
```

See Storage Commands for details.

### vulntor server

Control Vulntor server daemon:

```bash
vulntor server start                # Start server
vulntor server stop                 # Stop server
vulntor server status               # Check server status
```

See [Server Commands](./server.md) for details.

### vulntor fingerprint

Manage fingerprint catalogs:

```bash
vulntor fingerprint sync            # Update fingerprint database
vulntor fingerprint list            # List available rules
```

See [Fingerprint Commands](./fingerprint.md) for details.

### vulntor version

Display version information:

```bash
vulntor version
```

Output:

```
Vulntor version 1.0.0
Build: 20231006-a1b2c3d
Go version: go1.21.3
Platform: linux/amd64
```

### vulntor dag

Validate and inspect DAG definitions:

```bash
vulntor dag validate scan-profile.yaml   # Validate DAG
vulntor dag show scan-profile.yaml       # Visualize DAG
```

## Quick Start

### Basic Network Scan

```bash
vulntor scan --targets 192.168.1.0/24
```

### Scan with Vulnerability Detection

```bash
vulntor scan --targets 192.168.1.100 --vuln
```

### List Scan Results

```bash
vulntor storage list
```

### Export Results

```bash
vulntor storage export <scan-id> --format json -o report.json
```

## Learn More

<div className="row" style={{marginTop: '1.5rem'}}>
  <div className="col col--6">
    <div className="card">
      <div className="card__header">
        <h3>📋 Common Workflows</h3>
      </div>
      <div className="card__body">
        <p>Learn common scanning patterns and use cases</p>
        <a href="./common-workflows.md" className="button button--primary">View Workflows</a>
      </div>
    </div>
  </div>
  <div className="col col--6">
    <div className="card">
      <div className="card__header">
        <h3>📊 Output Formats</h3>
      </div>
      <div className="card__body">
        <p>Understand different output formats and verbosity levels</p>
        <a href="./output-formats.md" className="button button--primary">Learn More</a>
      </div>
    </div>
  </div>
</div>

<div className="row" style={{marginTop: '1rem'}}>
  <div className="col col--6">
    <div className="card">
      <div className="card__header">
        <h3>⚙️ Configuration</h3>
      </div>
      <div className="card__body">
        <p>Configure CLI using files, environment variables, and flags</p>
        <a href="./configuration.md" className="button button--primary">Configure CLI</a>
      </div>
    </div>
  </div>
  <div className="col col--6">
    <div className="card">
      <div className="card__header">
        <h3>🔗 Integrations</h3>
      </div>
      <div className="card__body">
        <p>Integrate with CI/CD, automation tools, and scripts</p>
        <a href="./integrations.md" className="button button--primary">View Examples</a>
      </div>
    </div>
  </div>
</div>

## Command Reference

| Command                         | Description                       |
| ------------------------------- | --------------------------------- |
| [scan](./scan.md)               | Execute security scans            |
| storage         | Manage scan results and storage   |
| [server](./server.md)           | Control Vulntor server            |
| [fingerprint](./fingerprint.md) | Manage fingerprint database       |
