package plugin

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/plugin"
)

func newVerifyCommand() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify plugin checksums",
		Long: `Verify the integrity of installed plugins by checking their SHA-256 checksums.

By default, verifies all installed plugins. Use --plugin to verify a specific plugin.

Exit codes:
  0 - All plugins verified successfully
  1 - One or more plugins failed verification or error occurred`,
		Example: `  # Verify all installed plugins
  vulntor plugin verify

  # Verify a specific plugin
  vulntor plugin verify --plugin ssh-cve-2024-6387

  # Verify plugins in custom cache directory
  vulntor plugin verify --cache-dir /custom/path

  # JSON output
  vulntor plugin verify --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeVerifyCommand(cmd, cacheDir)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Plugin cache directory (default: platform-specific, see storage config)")
	cmd.Flags().String("plugin", "", "Verify specific plugin by name")

	return cmd
}

// executeVerifyCommand orchestrates the verify command execution
func executeVerifyCommand(cmd *cobra.Command, cacheDir string) error {
	// Setup structured logger
	logger := log.With().
		Str("component", "plugin.cli").
		Str("op", "verify").
		Logger()

	start := time.Now()
	defer func() {
		logger.Info().
			Dur("duration_ms", time.Since(start)).
			Msg("verify completed")
	}()

	// Setup dependencies
	formatter := getFormatter(cmd)
	svc, err := getPluginService(cmd, cacheDir)
	if err != nil {
		return err
	}

	// Bind flags to options
	opts, err := bind.BindVerifyOptions(cmd)
	if err != nil {
		return err
	}

	// Log operation start with request snapshot
	logger.Info().
		Str("plugin_id", opts.PluginID).
		Msg("verify started")

		// Call service layer
	result, err := svc.Verify(cmd.Context(), opts)
	if err != nil {
		return formatter.PrintTotalFailureSummary("verify", err, plugin.ErrorCode(err))
	}

	// Log success with metrics
	logger.Info().
		Int("total_count", result.TotalCount).
		Int("failed_count", result.FailedCount).
		Bool("all_valid", result.FailedCount == 0).
		Msg("verify succeeded")

	// Print results
	if err := printVerifyResult(formatter, result); err != nil {
		return err
	}

	// Return error if any plugins failed
	if result.FailedCount > 0 {
		logger.Warn().
			Int("failed_count", result.FailedCount).
			Msg("verification failed for some plugins")
		return fmt.Errorf("verification failed for %d plugin(s)", result.FailedCount)
	}

	return nil
}

// printVerifyResult formats and prints the verify result
func printVerifyResult(f format.Formatter, result *plugin.VerifyResult) error {
	if f.IsJSON() {
		return printVerifyJSON(f, result)
	}

	// No plugins to verify
	if result.TotalCount == 0 {
		return f.PrintSummary("No plugins installed to verify.")
	}

	// Print header
	if err := f.PrintSummary(fmt.Sprintf("Verifying %d plugin(s)...", result.TotalCount)); err != nil {
		return err
	}

	// Build and print table
	rows := buildVerifyTable(result)
	if err := f.PrintTable([]string{"Plugin", "Version", "Status"}, rows); err != nil {
		return err
	}

	// Print summary
	if result.FailedCount == 0 {
		return f.PrintSummary(fmt.Sprintf("✓ All %d plugin(s) verified successfully", result.TotalCount))
	}

	return f.PrintSummary(fmt.Sprintf("✗ %d plugin(s) failed verification", result.FailedCount))
}

// printVerifyJSON outputs verify result as JSON
func printVerifyJSON(f format.Formatter, result *plugin.VerifyResult) error {
	jsonResult := map[string]any{
		"results":      result.Results,
		"total_count":  result.TotalCount,
		"failed_count": result.FailedCount,
		"success":      result.FailedCount == 0,
	}
	return f.PrintJSON(jsonResult)
}

// buildVerifyTable builds table rows for verify results
func buildVerifyTable(result *plugin.VerifyResult) [][]string {
	var rows [][]string
	for _, r := range result.Results {
		status := "✓ OK"
		if !r.Valid {
			switch r.ErrorType {
			case "missing":
				status = "✗ File not found"
			case "checksum":
				status = "✗ Checksum mismatch"
			case "error":
				status = fmt.Sprintf("✗ Error: %v", r.Error)
			default:
				status = "✗ Failed"
			}
		}
		rows = append(rows, []string{r.ID, r.Version, status})
	}
	return rows
}
