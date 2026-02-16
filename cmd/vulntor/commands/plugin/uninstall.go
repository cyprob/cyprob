package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/plugin"
)

func newUninstallCommand() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:     "uninstall <plugin-name>",
		Aliases: []string{"remove", "rm"},
		Short:   "Uninstall plugins",
		Long: `Uninstall (remove) plugins from the local cache.

This command removes plugins from the cache directory. You can uninstall specific plugins by name,
all plugins in a category, or all plugins at once.`,
		Example: `  # Uninstall specific plugin
  vulntor plugin uninstall ssh-cve-2024-6387

  # Uninstall all SSH plugins
  vulntor plugin uninstall --category ssh

  # Uninstall all plugins
  vulntor plugin uninstall --all

  # Alternative commands (aliases)
  vulntor plugin remove ssh-cve-2024-6387
  vulntor plugin rm ssh-cve-2024-6387

  # JSON output
  vulntor plugin uninstall ssh --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var target string
			if len(args) > 0 {
				target = args[0]
			}
			return executeUninstallCommand(cmd, target, cacheDir)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Plugin cache directory (default: platform-specific, see storage config)")
	cmd.Flags().Bool("all", false, "Uninstall all plugins")
	cmd.Flags().String("category", "", "Uninstall all plugins from category (ssh, http, tls, database, network)")

	return cmd
}

// executeUninstallCommand orchestrates the uninstall command execution
func executeUninstallCommand(cmd *cobra.Command, target, cacheDir string) error {
	ctx := context.Background()

	// Setup structured logger
	logger := log.With().
		Str("component", "plugin.cli").
		Str("op", "uninstall").
		Logger()

	start := time.Now()
	defer func() {
		logger.Info().
			Dur("duration_ms", time.Since(start)).
			Msg("uninstall completed")
	}()

	// Setup dependencies
	formatter := getFormatter(cmd)
	svc, err := getPluginService(cmd, cacheDir)
	if err != nil {
		return err
	}

	// Bind flags to options
	opts, err := bind.BindUninstallOptions(cmd)
	if err != nil {
		return err
	}

	// Log operation start with request snapshot
	logger.Info().
		Str("target", target).
		Str("category", string(opts.Category)).
		Bool("all", opts.All).
		Msg("uninstall started")

	// Call service layer
	result, err := svc.Uninstall(ctx, target, opts)

	// Handle partial failure (exit code 8)
	if handleErr := handlePartialFailure(err, formatter, func() error {
		return printUninstallResult(formatter, result)
	}); handleErr != nil {
		return handleErr
	}

	// Handle total failure
	if err != nil {
		return formatter.PrintTotalFailureSummary("uninstall", err, plugin.ErrorCode(err))
	}

	// Log success with metrics
	logger.Info().
		Int("removed_count", result.RemovedCount).
		Int("failed_count", result.FailedCount).
		Int("remaining_count", result.RemainingCount).
		Msg("uninstall succeeded")

	// Print results
	return printUninstallResult(formatter, result)
}

// printUninstallResult formats and prints the uninstall result
func printUninstallResult(f format.Formatter, result *plugin.UninstallResult) error {
	if f.IsJSON() {
		return printUninstallJSON(f, result)
	}

	// Success case: no failures
	if result.FailedCount == 0 && result.RemovedCount > 0 {
		if result.RemainingCount == 0 {
			return f.PrintSuccessSummary("uninstalled", "All plugins", "")
		}
		// Multiple plugins uninstalled
		return f.PrintSuccessSummary("uninstalled", fmt.Sprintf("%d plugin(s)", result.RemovedCount), "")
	}

	// Partial failure case: some succeeded, some failed
	if result.RemovedCount > 0 && result.FailedCount > 0 {
		errorDetails := convertPluginErrors(result.Errors)
		summary := format.Summary{
			Operation:   "uninstall",
			Success:     result.RemovedCount,
			Skipped:     0, // uninstall doesn't have skipped count
			Failed:      result.FailedCount,
			Errors:      errorDetails,
			TotalErrors: len(result.Errors),
		}
		return f.PrintPartialFailureSummary(summary)
	}

	// Total failure case: all failed
	if result.FailedCount > 0 && result.RemovedCount == 0 {
		if len(result.Errors) == 1 {
			e := result.Errors[0]
			return f.PrintTotalFailureSummary("uninstall", fmt.Errorf("%s", e.Error), e.Code)
		}
		// Multiple errors - show as partial failure summary
		errorDetails := convertPluginErrors(result.Errors)
		summary := format.Summary{
			Operation:   "uninstall",
			Success:     0,
			Skipped:     0,
			Failed:      result.FailedCount,
			Errors:      errorDetails,
			TotalErrors: len(result.Errors),
		}
		return f.PrintPartialFailureSummary(summary)
	}

	return nil
}

// printUninstallJSON outputs uninstall result as JSON
func printUninstallJSON(f format.Formatter, result *plugin.UninstallResult) error {
	jsonResult := map[string]any{
		"removed_count":   result.RemovedCount,
		"failed_count":    result.FailedCount,
		"remaining_count": result.RemainingCount,
		"success":         result.FailedCount == 0,
		"partial_failure": result.FailedCount > 0 && result.RemovedCount > 0,
		"errors":          result.Errors,
	}
	return f.PrintJSON(jsonResult)
}
