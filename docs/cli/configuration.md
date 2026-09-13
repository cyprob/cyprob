# CLI Configuration

Learn how to configure Vulntor CLI using configuration files, environment variables, and command-line flags.

## Configuration Precedence

Configuration loaded in order (later overrides earlier):

1. Builtin defaults
2. System config: `/etc/vulntor/config.yaml`
3. User config: `~/.config/vulntor/config.yaml`
4. Storage config: `<storage>/config/vulntor.yaml`
5. Custom config: `--config /path/to/config.yaml`
6. Environment variables: `VULNTOR_*`
7. CLI flags: `--flag value`

## Global Flags

Available on all commands:

```bash
--config string          Config file path (default: ~/.config/vulntor/config.yaml)
--storage-dir string    Storage directory (default: OS-specific)
--no-storage            Disable storage persistence
--log-level string      Logging level: debug, info, warn, error (default: info)
--log-format string     Log format: json, text (default: text)
--verbosity int         Increase logging verbosity (0-3)
--quiet                 Suppress non-error output
--no-color              Disable colored output
--help, -h              Show help
--version, -v           Show version
```

## Environment Variables

Override config and flags:

```bash
VULNTOR_CONFIG           # Config file path
VULNTOR_STORAGE_DIR      # Storage directory
VULNTOR_LOG_LEVEL        # Logging level
VULNTOR_SERVER           # Server URL for remote mode
VULNTOR_API_TOKEN        # API authentication token
```

## Config File Format

YAML format:

```yaml
# ~/.config/vulntor/config.yaml
storage:
  dir: ~/.local/share/vulntor
  enabled: true

scanner:
  default_profile: standard
  rate: 1000
  timeout: 3s

fingerprint:
  cache_dir: ${storage}/cache/fingerprints
  catalog:
    remote_url: https://catalog.vulntor.io/fingerprints.yaml

logging:
  level: info
  format: text

server:
  bind: 0.0.0.0:8080
  workers: 4
```

See Configuration Overview for complete schema.

## Shell Completion

Generate shell completion scripts:

### Bash

```bash
vulntor completion bash > /etc/bash_completion.d/vulntor
source /etc/bash_completion.d/vulntor
```

### Zsh

```bash
vulntor completion zsh > ~/.zsh/completion/_vulntor
# Add to ~/.zshrc:
fpath=(~/.zsh/completion $fpath)
autoload -U compinit && compinit
```

### Fish

```bash
vulntor completion fish > ~/.config/fish/completions/vulntor.fish
```

### PowerShell

```powershell
vulntor completion powershell | Out-String | Invoke-Expression
```

## Debugging

### Enable Debug Logging

```bash
vulntor scan --targets 192.168.1.100 --log-level debug
```

### Log to File

```bash
vulntor scan --targets 192.168.1.100 2> scan-debug.log
```

### Trace Execution

Show detailed execution flow:

```bash
vulntor scan --targets 192.168.1.100 --log-level trace --log-format json | jq
```

### Dry Run

Validate configuration without executing:

```bash
vulntor scan --targets 192.168.1.100 --dry-run
```

Shows what would be executed without actually running the scan.
