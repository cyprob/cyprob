// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package format

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Summary represents operation results for consistent formatting
type Summary struct {
	Operation   string        // Operation name: "install", "update", "uninstall", etc.
	Success     int           // Successful operation count
	Skipped     int           // Skipped operation count
	Failed      int           // Failed operation count
	Errors      []ErrorDetail // First N errors (truncated for display)
	TotalErrors int           // Total error count (for truncation message)
}

// ErrorDetail represents a single error with context
type ErrorDetail struct {
	PluginID  string // Plugin identifier
	Error     string // Error message
	ErrorCode string // Error code for suggestion mapping
}

const (
	maxErrorsToShow = 5 // Maximum errors to display before truncating
)

// PrintSuccessSummary prints a standardized success message
// Examples:
//   - "✓ Installed ssh-weak-cipher v1.0.0"
//   - "✓ Uninstalled 3 plugins"
func (f *formatter) PrintSuccessSummary(operation, pluginID, version string) error {
	if f.quiet {
		// Quiet mode: minimal output
		if pluginID != "" && version != "" {
			_, err := fmt.Fprintf(f.stdout, "%s v%s\n", pluginID, version)
			return err
		}
		return nil
	}

	if f.mode == ModeJSON {
		// JSON mode: structured output
		return f.PrintJSON(map[string]any{
			"success":   true,
			"operation": operation,
			"plugin_id": pluginID,
			"version":   version,
		})
	}

	// Table mode: user-friendly message
	var message string
	if pluginID != "" && version != "" {
		message = fmt.Sprintf("✓ %s %s v%s", capitalize(operation), pluginID, version)
	} else {
		message = fmt.Sprintf("✓ %s completed successfully", capitalize(operation))
	}

	if f.color {
		_, err := color.New(color.FgGreen).Fprintln(f.stdout, message)
		return err
	}

	_, err := fmt.Fprintln(f.stdout, message)
	return err
}

// PrintPartialFailureSummary prints partial failure with counts, errors, and suggestions
// Example output:
//
//	Summary:
//	  ✓ Updated: 3 plugins
//	  ⚠ Skipped: 1 plugin
//	  ✗ Failed:  2 plugins
//
//	Failed plugins:
//	  - ssh-weak-cipher: Remote repository unavailable
//	  - ssh-cve-2024-6387: Checksum mismatch
//
//	💡 Suggestions:
//	  → Retry with different source:  vulntor plugin update --source github
//	  → Force re-download:            vulntor plugin update --force
func (f *formatter) PrintPartialFailureSummary(summary Summary) error {
	if f.quiet {
		// Quiet mode: suppress summary
		return nil
	}

	if f.mode == ModeJSON {
		// JSON mode: structured output
		return f.PrintJSON(map[string]any{
			"success":       false,
			"partial":       true,
			"operation":     summary.Operation,
			"success_count": summary.Success,
			"skipped_count": summary.Skipped,
			"failed_count":  summary.Failed,
			"errors":        summary.Errors,
		})
	}

	// Table mode: formatted summary
	var sb strings.Builder

	// Print counts
	sb.WriteString("\nSummary:\n")
	if summary.Success > 0 {
		if f.color {
			sb.WriteString(color.GreenString("  ✓ %s: %d\n", capitalize(getCountLabel(summary.Operation, summary.Success)), summary.Success))
		} else {
			sb.WriteString(fmt.Sprintf("  ✓ %s: %d\n", capitalize(getCountLabel(summary.Operation, summary.Success)), summary.Success))
		}
	}
	if summary.Skipped > 0 {
		if f.color {
			sb.WriteString(color.YellowString("  ⚠ Skipped: %d\n", summary.Skipped))
		} else {
			sb.WriteString(fmt.Sprintf("  ⚠ Skipped: %d\n", summary.Skipped))
		}
	}
	if summary.Failed > 0 {
		if f.color {
			sb.WriteString(color.RedString("  ✗ Failed:  %d\n", summary.Failed))
		} else {
			sb.WriteString(fmt.Sprintf("  ✗ Failed:  %d\n", summary.Failed))
		}
	}

	// Print first N errors
	if len(summary.Errors) > 0 {
		sb.WriteString("\nFailed plugins:\n")
		for i, err := range summary.Errors {
			if i >= maxErrorsToShow {
				remaining := summary.TotalErrors - maxErrorsToShow
				sb.WriteString(fmt.Sprintf("  ... and %d more (use --output json for full list)\n", remaining))
				break
			}
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", err.PluginID, err.Error))
		}

		// Print suggestions
		suggestions := collectSuggestions(summary.Errors, summary.Operation)
		if len(suggestions) > 0 {
			sb.WriteString("\n💡 Suggestions:\n")
			for _, s := range suggestions {
				sb.WriteString(fmt.Sprintf("  → %s\n", s))
			}
		}
	}

	_, err := f.stdout.Write([]byte(sb.String()))
	return err
}

// PrintTotalFailureSummary prints total failure with error and suggestions
// Example output:
//
//	✗ Failed to install ssh-weak-cipher: Plugin not found
//
//	💡 Suggestions:
//	  → List available plugins:  vulntor plugin list
//	  → Try GitHub source:       vulntor plugin install ssh-weak-cipher --source github
// The reported operation FAILED, so this returns that failure. Callers use it
// as `return formatter.PrintTotalFailureSummary(...)`, and returning nil there
// made every one of those paths exit 0 while printing "Failed to ...": a failed
// scan, a server that could not start and a validation that found errors all
// reported success to whatever ran them.
func (f *formatter) PrintTotalFailureSummary(operation string, err error, errorCode string) error {
	if f.quiet {
		// Quiet suppresses the summary, not the failure.
		return err
	}

	if f.mode == ModeJSON {
		// JSON mode: structured output
		if printErr := f.PrintJSON(map[string]any{
			"success":    false,
			"operation":  operation,
			"error":      err.Error(),
			"error_code": errorCode,
		}); printErr != nil {
			return printErr
		}
		return err
	}

	// Table mode: formatted error with suggestions
	var sb strings.Builder

	// Error message
	errorMsg := fmt.Sprintf("✗ Failed to %s: %v", operation, err)
	if f.color {
		sb.WriteString(color.RedString("%s\n", errorMsg))
	} else {
		sb.WriteString(fmt.Sprintf("%s\n", errorMsg))
	}

	// Suggestions based on error code
	suggestions := GetSuggestions(errorCode, operation)
	if len(suggestions) > 0 {
		sb.WriteString("\n💡 Suggestions:\n")
		for _, s := range suggestions {
			sb.WriteString(fmt.Sprintf("  → %s\n", s))
		}
	}

	if _, writeErr := f.stdout.Write([]byte(sb.String())); writeErr != nil {
		return writeErr
	}
	return err
}

var suggestionGenerators = map[string]func(string) []string{
	"PLUGIN_NOT_FOUND": func(operation string) []string {
		return []string{
			"List available plugins:  vulntor plugin list",
			fmt.Sprintf("Try GitHub source:       vulntor plugin %s <plugin> --source github", operation),
		}
	},
	"SERVICE_UNAVAILABLE": func(operation string) []string {
		return []string{
			fmt.Sprintf("Retry with GitHub:       vulntor plugin %s --source github", operation),
			"Check network connection",
		}
	},
	"CHECKSUM_MISMATCH": func(operation string) []string {
		return []string{
			fmt.Sprintf("Force re-download:       vulntor plugin %s --force", operation),
		}
	},
	"VERSION_CONFLICT": func(operation string) []string {
		return []string{
			"Uninstall first:         vulntor plugin uninstall <plugin>",
			fmt.Sprintf("Force reinstall:         vulntor plugin %s --force", operation),
		}
	},
	"PARTIAL_FAILURE": func(operation string) []string {
		return []string{
			fmt.Sprintf("See full details:        vulntor plugin %s --output json", operation),
		}
	},
	"NO_PLUGINS_FOUND": func(operation string) []string {
		return []string{
			"Check network connection",
			"Verify DNS resolution",
			fmt.Sprintf("Try GitHub source:       vulntor plugin %s <name> --source github", operation),
			fmt.Sprintf("Force re-download:       vulntor plugin %s --force", operation),
			"List cached plugins:     vulntor plugin list",
		}
	},
	"INVALID_CATEGORY": func(string) []string {
		return []string{
			"Valid categories: ssh, http, tls, database, network, web, iot, misc",
			"List plugins:     vulntor plugin list",
		}
	},
	"INVALID_SOURCE": func(string) []string {
		return []string{
			"Valid sources: official, github",
		}
	},
	"PLUGIN_NOT_INSTALLED": func(string) []string {
		return []string{
			"List installed:   vulntor plugin list",
			"Install plugin:   vulntor plugin install <plugin>",
		}
	},
	"INVALID_TARGET": func(string) []string {
		return []string{
			"Provide a target:           vulntor scan 192.168.1.0/24",
			"Scan multiple hosts:        vulntor scan 10.0.0.1 10.0.0.2",
		}
	},
	"CONFLICTING_DISCOVERY_FLAGS": func(string) []string {
		return []string{
			"Remove either --only-discover or --no-discover",
			"Run help for options:       vulntor scan --help",
		}
	},
	"SCAN_FAILURE": func(string) []string {
		return []string{
			"Retry with verbose logs:    vulntor scan <target> --verbose",
			"Enable progress output:     vulntor scan <target> --progress",
		}
	},
	"NO_RETENTION_POLICY": func(string) []string {
		return []string{
			"Set max scans:              vulntor storage gc --max-scans=100",
			"Set max age days:           vulntor storage gc --max-age-days=30",
		}
	},
	"INVALID_RETENTION_POLICY": func(string) []string {
		return []string{
			"Use non-negative numbers for retention flags",
			"Override config with flags: vulntor storage gc --max-scans=100",
		}
	},
	"WORKSPACE_INVALID": func(string) []string {
		return []string{
			"Set workspace dir:          vulntor storage gc --storage-dir <path>",
			"Ensure directory exists and is writable",
		}
	},
	"WORKSPACE_PERMISSION_DENIED": func(string) []string {
		return []string{
			"Fix permissions for the storage directory",
			"Run with appropriate user or adjust --storage-dir",
		}
	},
	"STORAGE_INVALID_INPUT": func(string) []string {
		return []string{
			"Review storage values in configuration file",
			"Override with CLI flags when running GC",
		}
	},
	"STORAGE_FAILURE": func(string) []string {
		return []string{
			"Retry with verbose logs:    vulntor storage gc --verbosity 1",
			"Check storage directory permissions",
		}
	},
	"SERVER_INVALID_PORT": func(string) []string {
		return []string{
			"Use a port between 1 and 65535",
			"Example:                 vulntor server start --port 8080",
		}
	},
	"SERVER_INVALID_CONCURRENCY": func(string) []string {
		return []string{
			"Set jobs concurrency to at least 1",
			"Example:                 vulntor server start --jobs-concurrency 4",
		}
	},
	"SERVER_FEATURES_DISABLED": func(string) []string {
		return []string{
			"Enable either UI or API flags",
			"Remove one of --no-ui / --no-api",
		}
	},
	"SERVER_CONFIG_UNAVAILABLE": func(string) []string {
		return []string{
			"Run via the vulntor CLI so AppManager initializes",
			"Avoid calling server start from custom scripts without init",
		}
	},
	"SERVER_INVALID_CONFIG": func(string) []string {
		return []string{
			"Check configuration values in config file",
			"Retry with --verbose for detailed validation errors",
		}
	},
	"SERVER_STORAGE_INIT_FAILED": func(string) []string {
		return []string{
			"Verify storage directory permissions",
			"Override storage root:     vulntor server start --storage-dir <path>",
		}
	},
	"SERVER_PLUGIN_INIT_FAILED": func(string) []string {
		return []string{
			"Check plugin cache directory access",
			"Retry after running:      vulntor plugin clean",
		}
	},
	"SERVER_INIT_FAILED": func(string) []string {
		return []string{
			"Retry with verbose logging: vulntor server start --verbose",
			"Review configuration for invalid values",
		}
	},
	"SERVER_RUNTIME_FAILED": func(string) []string {
		return []string{
			"Check server logs for runtime errors",
			"Ensure no other process is using the selected port",
		}
	},
	"FINGERPRINT_SOURCE_REQUIRED": func(string) []string {
		return []string{
			"Provide a source:          --file <path> or --url <address>",
			"Example:                   vulntor fingerprint sync --url https://example/catalog.yaml",
		}
	},
	"FINGERPRINT_SOURCE_CONFLICT": func(string) []string {
		return []string{
			"Use only one source flag",
			"Remove either --file or --url",
		}
	},
	"FINGERPRINT_STORAGE_DISABLED": func(string) []string {
		return []string{
			"Set cache directory:       vulntor fingerprint sync --cache-dir <path>",
			"Enable storage via CLI root command",
		}
	},
	"FINGERPRINT_SYNC_FAILED": func(string) []string {
		return []string{
			"Retry with --url pointing to a reachable catalog",
			"Check network connectivity and cache directory permissions",
		}
	},
	"DAG_LOAD_FAILED": func(string) []string {
		return []string{
			"Verify the DAG file path exists",
			"Ensure the file is valid YAML or JSON",
		}
	},
	"DAG_UNSUPPORTED_FORMAT": func(string) []string {
		return []string{
			"Use --format yaml or --format json",
		}
	},
	"DAG_MARSHAL_FAILED": func(string) []string {
		return []string{
			"Check DAG definition for syntax issues",
			"Retry exporting after fixing validation errors",
		}
	},
	"DAG_WRITE_FAILED": func(string) []string {
		return []string{
			"Ensure destination path is writable",
			"Retry without --output to print to stdout",
		}
	},
	"DAG_INVALID": func(string) []string {
		return []string{
			"Run vulntor dag validate on the export output",
			"Fix reported validation errors before exporting again",
		}
	},
}

func init() {
	suggestionGenerators["REMOTE_UNAVAILABLE"] = suggestionGenerators["SERVICE_UNAVAILABLE"]
}

// GetSuggestions returns actionable hints based on error code and operation.
func GetSuggestions(errorCode, operation string) []string {
	if generator, ok := suggestionGenerators[errorCode]; ok {
		return generator(operation)
	}
	return nil
}

// collectSuggestions gathers unique suggestions from multiple errors
func collectSuggestions(errors []ErrorDetail, operation string) []string {
	seen := make(map[string]bool)
	var suggestions []string

	for _, err := range errors {
		hints := GetSuggestions(err.ErrorCode, operation)
		for _, hint := range hints {
			if !seen[hint] {
				seen[hint] = true
				suggestions = append(suggestions, hint)
			}
		}
	}

	return suggestions
}

// capitalize capitalizes the first letter of a string
func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// getCountLabel returns the appropriate label for count display
// Examples: "Updated 3" -> "Updated", "Installed 1" -> "Installed"
func getCountLabel(operation string, count int) string {
	switch operation {
	case "install":
		return "installed"
	case "update":
		return "updated"
	case "uninstall":
		return "removed"
	case "clean":
		return "removed"
	case "verify":
		return "verified"
	default:
		return operation
	}
}
