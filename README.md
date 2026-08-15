# Cyprob

[![Go Report Card](https://goreportcard.com/badge/github.com/cyprob/cyprob)](https://goreportcard.com/report/github.com/cyprob/cyprob)
[![Test](https://github.com/cyprob/cyprob/actions/workflows/test.yaml/badge.svg)](https://github.com/cyprob/cyprob/actions/workflows/test.yaml)
![Coverage](https://img.shields.io/codecov/c/github/cyprob/cyprob)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/license/apache-2-0)

> ⚠️ **Active Development Notice**: Cyprob is currently under active development and has not been released yet. APIs, CLI commands, and core features are subject to change. This project is not production-ready.

**Cyprob** is a modular, high-performance security scanner that rapidly discovers network services, captures banners, and maps findings into vulnerability intelligence. Built with a powerful DAG-based execution engine, Cyprob enables security teams to perform comprehensive network assessments with precision and efficiency.

Cyprob is the open core (Apache-2.0) of the Cyprob vulnerability scanning platform. It is built to run on your own infrastructure: you decide what to look for, control rules are written by you in YAML, and scan data stays inside your network. The commercial edition (EE) ships as an on-premises appliance; see [cyprob.io](https://cyprob.io) for the product side.

> **Naming note:** the project was renamed from its former working name to Cyprob. The Go module is `github.com/cyprob/cyprob`; the CLI binary and the `cmd/vulntor/` directory still carry the old name until the code-side rename lands.

## ✨ Key Features

### 🚀 Performance & Scalability

- **Lightning-fast scanning** with intelligent rate limiting and concurrent execution
- **DAG-based execution engine** for parallel task processing and optimized workflows
- **Adaptive host discovery** using ICMP, ARP, and TCP probes
- **Efficient resource management** with configurable concurrency controls

### 🔍 Advanced Capabilities

- **Modular service detection** with extensible protocol parsers (SSH, HTTP, FTP, DNS, and more)
- **Fingerprint-based asset profiling** for accurate service version identification
- **YAML plugin system** with 19 embedded security checks and support for custom plugins
- **Plugin-based vulnerability matching** with CVE/CWE correlation and severity ratings
- **Workspace management** for organizing and querying scan results
- **Hook system** for custom automation and event-driven workflows

### 🛠️ Deployment Options

- **Standalone CLI** for quick ad-hoc scans and automation
- **Server mode** with REST/gRPC API for centralized scanning
- **Web UI** for interactive scan management and visualization (In Development)
- **Cross-platform support** (macOS, Linux, Windows)

## 🎯 Use Cases

- **Network Discovery**: Rapidly identify live hosts and services across large IP ranges
- **Asset Inventory**: Maintain accurate records of network infrastructure and services
- **Vulnerability Assessment**: Detect known vulnerabilities through banner analysis and CVE matching
- **Security Monitoring**: Continuous scanning for unauthorized services and configuration changes
- **Penetration Testing**: Reconnaissance and information gathering during security assessments

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/cyprob/cyprob.git
cd cyprob

# Build the binary (outputs to dist/)
make binary

# Or build manually to dist/
mkdir -p dist
go build -o dist/vulntor ./cmd

# Verify installation
./dist/vulntor version
```

### Basic Usage

```bash
# Scan a single target with default ports (22,80,443)
vulntor scan --targets 192.168.1.1

# Scan a CIDR range with custom ports
vulntor scan --targets 192.168.1.0/24 --ports 21,22,80,443,8080

# Perform discovery only (skip port scanning)
vulntor scan --targets 192.168.1.1 --only-discover

# Enable vulnerability detection
vulntor scan --targets 192.168.1.1 --vuln

# Scan with fingerprinting enabled
vulntor scan --targets 10.0.0.0/24 --fingerprint

# List previous scan results
vulntor storage list

# Get scan details
vulntor storage get <scan-id>
```

### Server Mode

```bash
# Start the Cyprob server
vulntor server start --addr 0.0.0.0 --port 8080

# Submit a scan via API
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"], "ports": [22,80,443]}'

# Check scan status
vulntor server status
```

### DAG Management

Validate and manage DAG (Directed Acyclic Graph) definitions:

```bash
# Validate a DAG definition file
vulntor dag validate scan-dag.yaml

# Export the internal scan DAG to YAML for inspection
vulntor dag export --targets 192.168.1.0/24 --output scan.yaml

# Export with vulnerability evaluation enabled
vulntor dag export --targets 10.0.0.1 --vuln --output full-scan.yaml

# Strict validation (treat warnings as errors)
vulntor dag validate dag.yaml --strict

# Output validation results as JSON (for CI/CD)
vulntor dag validate dag.yaml --json
```

### YAML Plugin System

**19 essential security check plugins** are embedded in the binary and ready to use immediately. Create custom vulnerability checks without writing Go code using YAML plugins:

```bash
# Load and evaluate YAML plugins
vulntor scan --targets 192.168.1.1 --plugins ./my-plugins/

# List available plugins
vulntor plugin list

# Validate a plugin definition
vulntor plugin validate ssh-cve-check.yaml
```

Example YAML plugin (`ssh-vuln-check.yaml`):

```yaml
name: SSH Vulnerability Check
version: 1.0.0
type: evaluation
author: security-team

metadata:
  cve: CVE-2024-XXXXX
  severity: high
  tags: [ssh, authentication, cve]

# Trigger when SSH version is detected
triggers:
  - data_key: ssh.version
    condition: exists
    value: true

# Match vulnerable versions
match:
  logic: AND
  rules:
    - field: ssh.version
      operator: version_lt
      value: '8.5'
    - field: ssh.banner
      operator: contains
      value: 'OpenSSH'

output:
  vulnerability: true
  message: 'SSH version vulnerable to authentication bypass'
  remediation: 'Upgrade OpenSSH to version 8.5 or higher'
```

**Supported Operators**:

- String: `equals`, `contains`, `startsWith`, `endsWith`, `matches` (regex)
- Numeric: `gt`, `gte`, `lt`, `lte`, `between`
- Version: `version_eq`, `version_lt`, `version_gt`, `version_lte`, `version_gte`, `version_between`
- Logical: `exists`, `in`, `notIn`

**Match Logic**: `AND`, `OR`, `NOT` for combining rules

**Embedded Plugins** (19 total, ~50 KB):

- **SSH** (5): weak-key-exchange, weak-mac, weak-cipher, default-creds, regreSSHion (CVE-2024-6387)
- **HTTP** (4): missing-security-headers, server-version-disclosure, default-pages, weak-ssl
- **TLS** (4): weak-cipher, expired-cert, self-signed-cert, weak-protocol
- **Database** (3): mysql-default-creds, postgres-default-creds, redis-no-auth
- **Network** (3): open-telnet, open-ftp, weak-snmp-community

See [pkg/plugin/testdata/plugins/](pkg/plugin/testdata/plugins/) and [pkg/plugin/embedded/](pkg/plugin/embedded/) for examples.

## 📂 Project Structure

```
cyprob/
├── cmd/vulntor/           # CLI entry point
├── pkg/
│   ├── api/              # REST and gRPC API servers
│   ├── appctx/           # Application context management
│   ├── cli/              # CLI command implementations
│   ├── config/           # Configuration loading and validation
│   ├── engine/           # DAG execution engine
│   ├── event/            # Event system for hooks and notifications
│   ├── fingerprint/      # Service fingerprinting engine
│   ├── hook/             # Hook system for custom automation
│   ├── logging/          # Structured logging utilities
│   ├── modules/          # Core scanning modules (discovery, probing, etc.)
│   ├── netutil/          # Network utilities and helpers
│   ├── parser/           # Protocol parsers (SSH, HTTP, FTP, etc.)
│   ├── plugin/           # YAML plugin system + legacy CVE matchers
│   ├── scan/             # Scan orchestration and coordination
│   ├── scanexec/         # Scan execution logic
│   ├── scanner/          # Port scanner and banner grabber
│   ├── server/           # HTTP/gRPC server implementation
│   ├── storage/         # Scan result persistence and queries
│   └── version/          # Version information
├── ui/                   # Web UI (React/TypeScript) - In Development
├── docs/                 # Documentation website (Docusaurus)
└── scripts/              # Build and packaging scripts
```

## 🔧 Architecture

Cyprob is built around several core concepts:

### DAG Execution Engine

The DAG (Directed Acyclic Graph) engine orchestrates scan workflows by modeling dependencies between tasks. This enables:

- Parallel execution of independent tasks
- Automatic dependency resolution
- Efficient resource utilization
- Flexible workflow composition

### Module System

Modules are self-contained units that perform specific scan phases:

- **Discovery Module**: Host discovery using multiple techniques
- **Port Scanner Module**: Fast TCP/UDP port scanning
- **Banner Grabber Module**: Service banner collection
- **Fingerprint Module**: Service version identification
- **Vulnerability Module**: CVE matching and risk assessment

### Storage Backend

All scan results are stored using the `pkg/storage` abstraction layer:

- **LocalBackend (OSS)**: File-based JSONL storage with thread-safe operations
- OS-specific defaults: `~/Library/Application Support/Vulntor` (macOS), `~/.local/share/vulntor` (Linux)
- Features: filtering, pagination, partial updates, typed errors
- Retention policies: automatic cleanup based on age and count limits

### Testing Strategy

Cyprob uses a comprehensive testing approach:

#### Unit Tests

- Run with `make test` or `go test ./...`
- Table-driven tests with testify/require
- Mock interfaces for isolation
- Target: >80% coverage for core packages

#### Integration Tests

- Build tag: `//go:build integration`
- Run with `make test-integration` or `go test -tags=integration ./...`
- Black-box testing with real HTTP servers and network requests
- Examples:
  - `pkg/server/app/app_integration_test.go` - Server lifecycle testing
  - `pkg/server/api/v1/plugins_integration_test.go` - Plugin API endpoint testing
- Run all tests: `make test-all`

#### Testing Policy

**Before Every Commit (MANDATORY)**:

- ✅ `make test` - Unit tests only (fast, <2min)
- ✅ `make validate` - Linting, formatting, spell check, shell script validation

**Before Opening PR (RECOMMENDED)**:

- ⚡ `make test-all` - Runs both unit AND integration tests

**CI/CD Behavior**:

- Unit tests run on every commit (fast feedback)
- Integration tests run on PR events (comprehensive validation)

## 🔌 Extending Cyprob

### Custom Parsers

Add support for new protocols:

```go
package parser

func init() {
    Register("myprotocol", &MyProtocolParser{})
}

type MyProtocolParser struct{}

func (p *MyProtocolParser) Parse(banner string) (map[string]string, error) {
    // Parse banner and extract metadata
    return map[string]string{
        "service": "myservice",
        "version": "1.0.0",
    }, nil
}
```

### Custom Plugins

#### YAML Plugins (Recommended)

Create vulnerability detection rules without writing Go code:

```yaml
name: HTTP Vulnerable App Detection
version: 1.0.0
type: evaluation
author: security-team

metadata:
  cve: CVE-2024-XXXXX
  severity: high
  tags: [http, web, cve]

triggers:
  - data_key: http.server
    condition: exists
    value: true

match:
  logic: AND
  rules:
    - field: http.server
      operator: contains
      value: 'VulnerableApp/1.0'
    - field: service.port
      operator: equals
      value: 8080

output:
  vulnerability: true
  message: 'Vulnerable application detected'
  remediation: 'Upgrade to version 2.0 or higher'
```

**Benefits**:

- ✅ No recompilation needed
- ✅ Easy to create and share
- ✅ Declarative and readable
- ✅ Supports complex matching logic

#### Go Plugins (Legacy)

For advanced use cases, you can still create Go-based plugins:

```go
package plugin

func init() {
    Register(&Plugins{
        ID:   "custom_vuln_check",
        Name: "Custom Vulnerability Check",
        RequirePorts: []int{8080},
        RequireKeys:  []string{"http/server"},
        MatchFunc: func(ctx map[string]string) *MatchResult {
            if strings.Contains(ctx["http/server"], "VulnerableApp/1.0") {
                return &MatchResult{
                    CVE:     []string{"CVE-2024-XXXXX"},
                    Summary: "Vulnerable application detected",
                }
            }
            return nil
        },
    })
}
```

### Event Hooks

React to scan events:

```go
package main

import "github.com/cyprob/cyprob/pkg/hook"

func init() {
    hook.Register("on_scan_complete", func(data interface{}) error {
        // Send notification, update database, etc.
        return nil
    })
}
```

## 📖 Documentation

For comprehensive documentation, visit:

- **Documentation Site**: https://cyprob.io (dedicated docs site in development)
- **Getting Started Guide**: [docs/getting-started/installation.md](docs/docs/getting-started/installation.md)
- **CLI Reference**: [docs/cli/overview.md](docs/docs/cli/overview.md)
- **Architecture Overview**: [docs/architecture/overview.md](docs/docs/architecture/overview.md)

## 🤝 Contributing

We welcome contributions! Cyprob is in active development, and we're building the foundation for a powerful security scanning platform.

Areas where we need help:

- Core scanning engine improvements
- Protocol parser implementations
- Vulnerability detection plugins
- Documentation and examples
- UI/UX design and implementation
- Testing and bug reports

Please read our contributing guidelines before submitting pull requests.

## 📋 Roadmap

- [ ] Complete core scanning engine
- [ ] REST/gRPC API implementation
- [ ] Web UI for scan management
- [ ] Distributed scanning support
- [ ] Enhanced reporting capabilities
- [ ] Integration with popular security tools
- [ ] Cloud deployment guides
- [ ] First stable release (v1.0.0)

## 📜 License

Licensed under the Apache License, Version 2.0. See [LICENSE.md](LICENSE.md) for details.

## 🔗 Links

- **Website**: https://cyprob.io
- **Documentation**: https://cyprob.io (dedicated docs site in development)
- **GitHub**: https://github.com/cyprob/cyprob
- **Issues**: https://github.com/cyprob/cyprob/issues
- **Discussions**: https://github.com/cyprob/cyprob/discussions

---

**Note**: Cyprob is under active development. Star the repository to stay updated on releases and new features!

## ValidationRunner Options (Fingerprint)

Cyprob's fingerprint validation supports functional options to configure thresholds, parallelism, timeouts, and progress callbacks.

Basic usage (defaults):

```go
runner, err := NewValidationRunner(resolver, "pkg/fingerprint/testdata/validation_dataset.yaml")
metrics, results, err := runner.Run(context.Background())
```

Custom thresholds (upstream-compatible):

```go
strict := StrictThresholds()
runner, err := NewValidationRunnerWithThresholds(resolver, "pkg/fingerprint/testdata/validation_dataset.yaml", strict)
metrics, _, _ := runner.Run(context.Background())
```

Parallel execution with progress:

```go
runner, err := NewValidationRunner(
  resolver,
  "pkg/fingerprint/testdata/validation_dataset.yaml",
  WithParallelism(4),
  WithProgressCallback(func(p float64){ fmt.Printf("%.0f%%\n", p*100) }),
)
metrics, _, _ := runner.Run(context.Background())
```

Timeout for entire run:

```go
runner, _ := NewValidationRunner(
  resolver,
  "pkg/fingerprint/testdata/validation_dataset.yaml",
  WithTimeout(30*time.Second),
)
metrics, _, _ := runner.Run(context.Background())
```
