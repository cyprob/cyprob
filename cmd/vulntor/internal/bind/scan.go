package bind

import (
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/pkg/scanexec"
)

// BindScanOptions extracts and validates scan command flags.
//
// This function reads the scan-specific flags from the Cobra command and
// constructs a properly validated scanexec.Params struct for the service layer.
//
// Flags read:
//   - --ports: Port list or ranges (e.g., "22,80,443", "1-1024")
//   - --profile: Predefined scan profile name
//   - --level: Scan intensity level (light, default, comprehensive, intrusive)
//   - --tags: Include only modules with these tags
//   - --exclude-tags: Exclude modules with these tags
//   - --vuln: Enable vulnerability assessment
//   - --only-discover: Run only discovery phase
//   - --no-discover: Skip discovery phase
//   - --progress: Print live progress updates
//   - --fingerprint-cache: Fingerprint catalog cache directory
//   - --output: Output format (text, json, yaml)
//   - --timeout: Network operation timeout
//   - --concurrency: Parallel operation concurrency
//   - --ping: Enable ICMP host discovery
//   - --ping-count: Number of ICMP pings per host
//   - --allow-loopback: Allow scanning loopback addresses
//
// Returns an error if validation fails (e.g., conflicting flags).
func BindScanOptions(cmd *cobra.Command, targets []string) (scanexec.Params, error) {
	ports, _ := cmd.Flags().GetString("ports")
	profile, _ := cmd.Flags().GetString("profile")
	level, _ := cmd.Flags().GetString("level")
	includeTags, _ := cmd.Flags().GetStringSlice("tags")
	excludeTags, _ := cmd.Flags().GetStringSlice("exclude-tags")
	vuln, _ := cmd.Flags().GetBool("vuln")
	onlyDiscover, _ := cmd.Flags().GetBool("only-discover")
	skipDiscover, _ := cmd.Flags().GetBool("no-discover")
	progress, _ := cmd.Flags().GetBool("progress")
	fingerprintCache, _ := cmd.Flags().GetString("fingerprint-cache")
	output, _ := cmd.Flags().GetString("output")
	timeout, _ := cmd.Flags().GetString("timeout")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	ping, _ := cmd.Flags().GetBool("ping")
	pingCount, _ := cmd.Flags().GetInt("ping-count")
	allowLoopback, _ := cmd.Flags().GetBool("allow-loopback")

	// Validate conflicting flags
	if onlyDiscover && skipDiscover {
		return scanexec.Params{}, scanexec.ErrConflictingDiscoveryFlags
	}

	// If only-discover is set, disable vuln automatically
	enableVuln := vuln
	if onlyDiscover {
		enableVuln = false
	}

	// Build params
	params := scanexec.Params{
		Targets:       targets,
		Ports:         ports,
		Profile:       profile,
		Level:         level,
		IncludeTags:   includeTags,
		ExcludeTags:   excludeTags,
		EnableVuln:    enableVuln,
		OnlyDiscover:  onlyDiscover,
		SkipDiscover:  skipDiscover,
		OutputFormat:  output,
		CustomTimeout: timeout,
		Concurrency:   concurrency,
		EnablePing:    ping,
		PingCount:     pingCount,
		AllowLoopback: allowLoopback,
	}

	// Store additional flags in RawInputs for potential use
	params.RawInputs = map[string]any{
		"progress":          progress,
		"fingerprint-cache": fingerprintCache,
	}

	return params, nil
}
