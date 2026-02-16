package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/plugin"
)

func newListCommand() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all installed plugins",
		Long: `List all plugins currently installed in the cache.

Displays plugin name, version, and installation status for each plugin
found in the plugin cache directory.`,
		Example: `  # List all installed plugins
  vulntor plugin list

  # List plugins with detailed information
  vulntor plugin list --verbose

  # List plugins from custom cache directory
  vulntor plugin list --cache-dir /custom/path

  # JSON output
  vulntor plugin list --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use global persistent --verbose flag
			verbose, _ := cmd.Flags().GetBool("verbose")
			return executeListCommand(cmd, cacheDir, verbose)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Plugin cache directory (default: platform-specific, see storage config)")
	// Note: --verbose is a global persistent flag, not defined locally

	return cmd
}

// executeListCommand orchestrates the list command execution
func executeListCommand(cmd *cobra.Command, cacheDir string, verbose bool) error {
	ctx := context.Background()

	// Setup structured logger
	logger := log.With().
		Str("component", "plugin.cli").
		Str("op", "list").
		Logger()

	start := time.Now()
	defer func() {
		logger.Info().
			Dur("duration_ms", time.Since(start)).
			Msg("list completed")
	}()

	// Log operation start
	logger.Info().
		Bool("verbose", verbose).
		Msg("list started")

	// Setup dependencies
	formatter := getFormatter(cmd)
	svc, err := getPluginService(cmd, cacheDir)
	if err != nil {
		return err
	}

	// Call service layer
	plugins, err := svc.List(ctx)
	if err != nil {
		return formatter.PrintTotalFailureSummary("list", err, plugin.ErrorCode(err))
	}

	// Log success with metrics
	logger.Info().
		Int("count", len(plugins)).
		Msg("list succeeded")

	// Print results
	return printListResult(formatter, plugins, verbose)
}

// printListResult formats and prints the list result
func printListResult(f format.Formatter, plugins []*plugin.PluginInfo, verbose bool) error {
	if f.IsJSON() {
		return printListJSON(f, plugins)
	}

	// Empty list
	if len(plugins) == 0 {
		return printEmptyPluginList(f)
	}

	// Build and print table
	headers, rows := buildListTable(plugins, verbose)
	if err := f.PrintTable(headers, rows); err != nil {
		return err
	}

	// Print summary
	return f.PrintSummary(fmt.Sprintf("Found %d plugin(s)", len(plugins)))
}

// printListJSON outputs list result as JSON
func printListJSON(f format.Formatter, plugins []*plugin.PluginInfo) error {
	result := map[string]any{
		"plugins": plugins,
		"count":   len(plugins),
	}
	return f.PrintJSON(result)
}

// printEmptyPluginList prints message when no plugins are installed
func printEmptyPluginList(f format.Formatter) error {
	if err := f.PrintSummary("No plugins installed."); err != nil {
		return err
	}
	if err := f.PrintSummary(""); err != nil {
		return err
	}
	if err := f.PrintSummary("To install plugins, use:"); err != nil {
		return err
	}
	return f.PrintSummary("  vulntor plugin install <plugin-name>")
}

// buildListTable builds table headers and rows for plugin list
func buildListTable(plugins []*plugin.PluginInfo, verbose bool) ([]string, [][]string) {
	var headers []string
	var rows [][]string

	if verbose {
		headers = []string{"Name", "Version", "Checksum", "Download URL"}
		for _, p := range plugins {
			rows = append(rows, []string{
				p.Name,
				p.Version,
				truncateChecksum(p.Checksum),
				truncateURL(p.DownloadURL),
			})
		}
	} else {
		headers = []string{"Name", "Version"}
		for _, p := range plugins {
			rows = append(rows, []string{p.ID, p.Version})
		}
	}

	return headers, rows
}

// truncateChecksum truncates checksum for display (shows first 12 chars)
func truncateChecksum(checksum string) string {
	if len(checksum) > 12 {
		return checksum[:12] + "..."
	}
	return checksum
}

// truncateURL truncates URL for display (shows last 40 chars)
func truncateURL(url string) string {
	if len(url) > 40 {
		return "..." + url[len(url)-37:]
	}
	return url
}
