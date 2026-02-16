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

func newCleanCommand() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean unused plugin cache entries",
		Long: `Remove old or unused plugin cache entries.

Removes cached plugins older than the specified duration.
Use --dry-run to preview what would be deleted without actually deleting.`,
		Example: `  # Clean cache entries older than 30 days
  vulntor plugin clean --older-than 720h

  # Preview what would be deleted
  vulntor plugin clean --older-than 720h --dry-run

  # Clean custom cache directory
  vulntor plugin clean --older-than 168h --cache-dir /custom/path

  # JSON output
  vulntor plugin clean --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeCleanCommand(cmd, cacheDir)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Plugin cache directory (default: platform-specific, see storage config)")
	cmd.Flags().Bool("dry-run", false, "Preview what would be deleted without actually deleting")
	cmd.Flags().String("older-than", "720h", "Remove cache entries older than this duration (e.g., 720h for 30 days)")

	return cmd
}

// executeCleanCommand orchestrates the clean command execution
func executeCleanCommand(cmd *cobra.Command, cacheDir string) error {
	// Setup structured logger
	logger := log.With().
		Str("component", "plugin.cli").
		Str("op", "clean").
		Logger()

	start := time.Now()
	defer func() {
		logger.Info().
			Dur("duration_ms", time.Since(start)).
			Msg("clean completed")
	}()

	// Setup dependencies
	formatter := getFormatter(cmd)
	svc, err := getPluginService(cmd, cacheDir)
	if err != nil {
		return err
	}

	// Bind flags to options
	opts, err := bind.BindCleanOptions(cmd)
	if err != nil {
		return err
	}

	// Log operation start with request snapshot
	logger.Info().
		Str("older_than", opts.OlderThan.String()).
		Bool("dry_run", opts.DryRun).
		Msg("clean started")

	// Print header
	if err := printCleanHeader(formatter, cacheDir, opts); err != nil {
		return err
	}

	// Call service layer
	result, err := svc.Clean(cmd.Context(), opts)
	if err != nil {
		return formatter.PrintTotalFailureSummary("clean", err, plugin.ErrorCode(err))
	}

	// Log success with metrics
	logger.Info().
		Int("removed_count", result.RemovedCount).
		Int64("freed_bytes", result.Freed).
		Bool("dry_run", opts.DryRun).
		Msg("clean succeeded")

	// Print results
	return printCleanResult(formatter, result, opts.DryRun)
}

// printCleanHeader prints the clean command header
func printCleanHeader(f format.Formatter, cacheDir string, opts plugin.CleanOptions) error {
	if err := f.PrintSummary(fmt.Sprintf("Cleaning plugin cache: %s", cacheDir)); err != nil {
		return err
	}
	if err := f.PrintSummary(fmt.Sprintf("Removing entries older than: %s", opts.OlderThan)); err != nil {
		return err
	}
	if opts.DryRun {
		return f.PrintSummary("(Dry run - no files will be deleted)")
	}
	return nil
}

// printCleanResult formats and prints the clean result
func printCleanResult(f format.Formatter, result *plugin.CleanResult, dryRun bool) error {
	if f.IsJSON() {
		return printCleanJSON(f, result, dryRun)
	}

	// No old entries found
	if result.RemovedCount == 0 {
		return f.PrintSummary("No old plugin cache entries found to remove.")
	}

	// Dry run mode
	if dryRun {
		summary := fmt.Sprintf("[DRY RUN] Would remove %d cache entries", result.RemovedCount)
		if result.Freed > 0 {
			summary += fmt.Sprintf(", would free %s", formatBytes(result.Freed))
		}
		if err := f.PrintSummary(summary); err != nil {
			return err
		}
		return f.PrintSummary("Run without --dry-run to actually delete these files.")
	}

	// Actual clean completed
	summary := fmt.Sprintf("Removed %d cache entries", result.RemovedCount)
	if result.Freed > 0 {
		summary += fmt.Sprintf(", freed %s", formatBytes(result.Freed))
	}
	return f.PrintSummary(summary)
}

// printCleanJSON outputs clean result as JSON
func printCleanJSON(f format.Formatter, result *plugin.CleanResult, dryRun bool) error {
	jsonResult := map[string]any{
		"removed_count": result.RemovedCount,
		"freed_bytes":   result.Freed,
		"dry_run":       dryRun,
		"success":       true,
	}
	return f.PrintJSON(jsonResult)
}
