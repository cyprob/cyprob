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

func newInfoCommand() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "info <plugin-name>",
		Short: "Show detailed information about a plugin",
		Long: `Display detailed information about an installed plugin.

Shows plugin metadata including name, version, checksum, download URL,
installation path, and cache size.`,
		Example: `  # Show info for a specific plugin
  vulntor plugin info ssh-cve-2024-6387

  # Use custom cache directory
  vulntor plugin info ssh-cve-2024-6387 --cache-dir /custom/path

  # JSON output
  vulntor plugin info ssh-cve-2024-6387 --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeInfoCommand(cmd, args[0], cacheDir)
		},
	}

	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Plugin cache directory (default: platform-specific, see storage config)")

	return cmd
}

// executeInfoCommand orchestrates the info command execution
func executeInfoCommand(cmd *cobra.Command, pluginName, cacheDir string) error {
	ctx := context.Background()

	// Setup structured logger
	logger := log.With().
		Str("component", "plugin.cli").
		Str("op", "info").
		Logger()

	start := time.Now()
	defer func() {
		logger.Info().
			Dur("duration_ms", time.Since(start)).
			Msg("info completed")
	}()

	// Log operation start with request snapshot
	logger.Info().
		Str("plugin_name", pluginName).
		Msg("info started")

	// Setup dependencies
	formatter := getFormatter(cmd)
	svc, err := getPluginService(cmd, cacheDir)
	if err != nil {
		return err
	}

	// Call service layer
	info, err := svc.GetInfo(ctx, pluginName)
	if err != nil {
		if err == plugin.ErrPluginNotFound {
			return formatter.PrintTotalFailureSummary("info", fmt.Errorf("plugin '%s' not found", pluginName), plugin.ErrorCode(err))
		}
		return formatter.PrintTotalFailureSummary("info", err, plugin.ErrorCode(err))
	}

	// Log success
	logger.Info().
		Str("plugin_name", info.Name).
		Str("version", info.Version).
		Msg("info succeeded")

	// Print results
	return printPluginInfo(formatter, info)
}

// printPluginInfo formats and prints the plugin information
func printPluginInfo(f format.Formatter, info *plugin.PluginInfo) error {
	// Build key-value table
	rows := [][]string{
		{"Name", info.Name},
		{"Version", info.Version},
		{"Checksum", info.Checksum},
		{"Download URL", info.DownloadURL},
		{"Installed", info.InstalledAt.Format("2006-01-02 15:04:05")},
	}

	if info.CacheDir != "" {
		rows = append(rows, []string{"Location", info.CacheDir})
		if info.CacheSize > 0 {
			rows = append(rows, []string{"Size", formatBytes(info.CacheSize)})
		}
	}

	return f.PrintTable([]string{"Property", "Value"}, rows)
}
