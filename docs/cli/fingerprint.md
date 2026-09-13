# vulntor fingerprint

Manage fingerprint catalogs and service detection rules.

## Synopsis

```bash
vulntor fingerprint <subcommand> [flags]
```

## Description

The `fingerprint` command manages service fingerprinting databases, including syncing remote catalogs, listing available rules, and validating custom fingerprints.

## Subcommands

### sync

Sync fingerprint catalog from remote repository.

```bash
vulntor fingerprint sync [flags]
```

**Flags**:
- `--url`: Remote catalog URL (default: `https://catalog.vulntor.io/fingerprints.yaml`)
- `--force`: Force re-download even if cache is fresh
- `--verify`: Verify signature (Enterprise)

**Examples**:
```bash
# Sync from default catalog
vulntor fingerprint sync

# Force update
vulntor fingerprint sync --force

# Custom catalog URL
vulntor fingerprint sync --url https://custom.repo/fingerprints.yaml

# Verify signature (Enterprise)
vulntor fingerprint sync --verify
```

**Output**:
```
Syncing fingerprint catalog...
Downloaded: 15,234 fingerprints
Cached to: ~/.local/share/vulntor/cache/fingerprints/
```

### list

List available fingerprint rules.

```bash
vulntor fingerprint list [flags]
```

**Flags**:
- `--category`: Filter by category (http, ssh, smtp, etc.)
- `--format`: Output format (table, json, yaml)
- `--search`: Search fingerprints by name

**Examples**:
```bash
# List all fingerprints
vulntor fingerprint list

# Filter by category
vulntor fingerprint list --category http

# Search by name
vulntor fingerprint list --search nginx

# JSON output
vulntor fingerprint list --format json
```

**Output**:
```
NAME            CATEGORY    PATTERNS    CONFIDENCE
nginx           http        3           95
apache          http        5           95
openssh         ssh         2           90
postfix         smtp        3           85
```

### show

Show detailed fingerprint rule.

```bash
vulntor fingerprint show <name>
```

**Examples**:
```bash
# Show nginx fingerprint
vulntor fingerprint show nginx
```

**Output**:
```yaml
name: nginx
category: http
description: Nginx web server detection
patterns:
  - type: http_header
    header: Server
    regex: 'nginx/([0-9.]+)'
    version_group: 1
    confidence: 95
  - type: http_content
    regex: '<hr><center>nginx/([0-9.]+)</center>'
    version_group: 1
    confidence: 90
```

### validate

Validate custom fingerprint rules.

```bash
vulntor fingerprint validate <file>
```

**Examples**:
```bash
# Validate custom rules
vulntor fingerprint validate custom-fingerprints.yaml
```

**Output**:
```
Validating custom-fingerprints.yaml...
✓ Syntax valid
✓ 10 fingerprints loaded
✓ No duplicates found
✓ All regex patterns valid
Validation successful
```

### test

Test fingerprint rules against sample data.

```bash
vulntor fingerprint test <rule-file> <sample-data>
```

**Examples**:
```bash
# Test rule against banner
vulntor fingerprint test nginx.yaml banner.txt

# Test against HTTP response
vulntor fingerprint test webapp.yaml http-response.txt
```

**Output**:
```
Testing nginx.yaml against banner.txt...

Matches:
  ✓ nginx 1.18.0 (95% confidence)
    Pattern: http_header
    Evidence: Server: nginx/1.18.0

  ✓ Ubuntu 20.04 (80% confidence)
    Pattern: http_header
    Evidence: Server: nginx/1.18.0 (Ubuntu)
```

### stats

Display fingerprint catalog statistics.

```bash
vulntor fingerprint stats
```

**Output**:
```
Fingerprint Catalog Statistics
-------------------------------
Total fingerprints: 15,234
Categories:
  http: 5,123
  ssh: 1,045
  smtp: 823
  ftp: 645
  database: 1,234
  other: 6,364

Cache status: up-to-date
Last sync: 2023-10-06 14:30:22
Cache location: ~/.local/share/vulntor/cache/fingerprints/
```

### add

Add custom fingerprint rule.

```bash
vulntor fingerprint add <file>
```

Adds custom rule to user fingerprint directory (`~/.config/vulntor/fingerprints/custom/`).

**Examples**:
```bash
# Add custom rule
vulntor fingerprint add my-custom-rule.yaml
```

### remove

Remove custom fingerprint rule.

```bash
vulntor fingerprint remove <name>
```

**Examples**:
```bash
# Remove custom rule
vulntor fingerprint remove my_custom_app
```

## Fingerprint Rule Format

Custom fingerprint rules use YAML:

```yaml
# custom-app.yaml
fingerprints:
  - name: custom_app
    category: http
    description: Internal custom application
    patterns:
      - type: http_header
        header: X-App-Name
        regex: 'CustomApp/([0-9.]+)'
        version_group: 1
        confidence: 95
        os_hint: linux

      - type: http_content
        regex: '<meta name="generator" content="CustomApp ([0-9.]+)">'
        version_group: 1
        confidence: 90

      - type: banner
        regex: 'CustomApp v([0-9.]+) Build ([0-9]+)'
        version_group: 1
        build_group: 2
        confidence: 85

  - name: internal_service
    category: custom
    description: Internal microservice
    patterns:
      - type: banner
        regex: 'InternalService-([0-9.]+)'
        version_group: 1
        confidence: 90
```

### Pattern Types

- `http_header`: Match HTTP response header
- `http_content`: Match HTTP response body
- `banner`: Match raw TCP banner
- `tls_cert`: Match TLS certificate fields
- `ssh_banner`: Match SSH banner
- `smtp_banner`: Match SMTP greeting

### Fields

- `name`: Unique identifier
- `category`: Category (http, ssh, smtp, custom, etc.)
- `description`: Human-readable description
- `patterns`: List of detection patterns
  - `type`: Pattern type (see above)
  - `regex`: Regular expression
  - `header`: HTTP header name (for http_header type)
  - `version_group`: Regex group for version extraction
  - `os_hint`: OS hint (linux, windows, bsd, etc.)
  - `confidence`: Confidence score (0-100)

## Using Custom Fingerprints

### Global Custom Rules

Place in user config directory:

```bash
mkdir -p ~/.config/vulntor/fingerprints/custom/
cp my-rules.yaml ~/.config/vulntor/fingerprints/custom/
```

Automatically loaded on scan.

### Scan-Specific Rules

Use `--fingerprint-rules` flag:

```bash
vulntor scan --targets 192.168.1.100 --fingerprint-rules /path/to/custom.yaml
```

### Config File

Reference in config:

```yaml
fingerprint:
  custom_rules:
    - ~/.config/vulntor/fingerprints/custom/webapp.yaml
    - /etc/vulntor/fingerprints/internal-services.yaml
```

## Examples

### Sync Latest Fingerprints

```bash
vulntor fingerprint sync --force
```

### Search for Web Server Fingerprints

```bash
vulntor fingerprint list --category http --search server
```

### View Specific Fingerprint

```bash
vulntor fingerprint show nginx
```

### Validate Custom Rules

```bash
vulntor fingerprint validate my-custom-rules.yaml
```

### Test Rule Against Sample

Create test banner:
```bash
echo "HTTP/1.1 200 OK
Server: MyApp/2.1.0
X-Powered-By: CustomFramework/3.0
" > test-response.txt
```

Test fingerprint:
```bash
vulntor fingerprint test custom-app.yaml test-response.txt
```

### Add Custom Rule

```bash
# Create custom rule
cat > internal-app.yaml <<EOF
fingerprints:
  - name: internal_webapp
    category: http
    patterns:
      - type: http_header
        header: Server
        regex: 'InternalApp/([0-9.]+)'
        version_group: 1
        confidence: 95
EOF

# Add to Vulntor
vulntor fingerprint add internal-app.yaml

# Use in scan
vulntor scan --targets 192.168.1.100
```

## See Also

- Fingerprinting System - How fingerprinting works
- Custom Fingerprints Guide - Advanced rule writing
- [Scan Command](./scan.md) - Using fingerprints in scans
