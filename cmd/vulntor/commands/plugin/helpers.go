package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/output"
	"github.com/cyprob/cyprob/pkg/output/subscribers"
	"github.com/cyprob/cyprob/pkg/plugin"
	"github.com/cyprob/cyprob/pkg/storage"
)

const (
	outputFormatJSON = "json"
)

// getFormatter creates a formatter from command flags
func getFormatter(cmd *cobra.Command) format.Formatter {
	outputMode := format.ParseMode(cmd.Flag("output").Value.String())
	quiet, _ := cmd.Flags().GetBool("quiet")
	noColor, _ := cmd.Flags().GetBool("no-color")
	return format.New(os.Stdout, os.Stderr, outputMode, quiet, !noColor)
}

// getPluginService creates a plugin service with the given cache directory and output format
// If cacheDir is empty, uses the default platform-specific cache directory
// Suppresses service layer info logs in text mode (JSON mode keeps them for observability)
func getPluginService(cmd *cobra.Command, cacheDir string) (*plugin.Service, error) {
	if cacheDir == "" {
		storageConfig, err := storage.DefaultConfig()
		if err != nil {
			return nil, fmt.Errorf("get storage config: %w", err)
		}
		cacheDir = filepath.Join(storageConfig.WorkspaceRoot, "plugins", "cache")
	}

	// Create logger based on output format
	// Text mode: suppress info logs (Output pipeline handles user messaging)
	// JSON mode: keep info logs (structured observability)
	outputFormat, _ := cmd.Flags().GetString("output")
	logger := log.With().Str("component", "plugin.service").Logger()
	if outputFormat != outputFormatJSON {
		// Suppress info-level logs in text mode (only show warnings and errors)
		logger = logger.Level(zerolog.WarnLevel)
	}

	svc, err := plugin.NewService(
		plugin.WithCacheDir(cacheDir),
		plugin.WithLogger(logger),
	)
	if err != nil {
		return nil, fmt.Errorf("create plugin service: %w", err)
	}
	return svc, nil
}

// handlePartialFailure handles partial failure errors by printing results and exiting with code 8
func handlePartialFailure(err error, formatter format.Formatter, printFunc func() error) error {
	if err != nil && errors.Is(err, plugin.ErrPartialFailure) {
		// Print result even on partial failure
		if printErr := printFunc(); printErr != nil {
			return printErr
		}
		// Exit with code 8 for partial failure
		os.Exit(plugin.ExitCode(err))
	}
	return nil
}

// convertPluginErrors converts plugin errors to format.ErrorDetail
func convertPluginErrors(errors []plugin.PluginError) []format.ErrorDetail {
	errorDetails := make([]format.ErrorDetail, 0, len(errors))
	for _, e := range errors {
		errorDetails = append(errorDetails, format.ErrorDetail{
			PluginID:  e.PluginID,
			Error:     e.Error,
			ErrorCode: e.Code,
		})
	}
	return errorDetails
}

// buildPluginTable builds table rows for plugin list
// Used by install and update commands
func buildPluginTable(plugins []*plugin.PluginInfo) [][]string {
	var rows [][]string
	for _, p := range plugins {
		categoryStr := ""
		if len(p.Tags) > 0 {
			categoryStr = p.Tags[0]
		}
		rows = append(rows, []string{p.Name, p.Version, categoryStr})
	}
	return rows
}

// formatBytes formats bytes as human-readable string (e.g., "1.5 MiB")
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// setupPluginOutputPipeline creates an Output pipeline for plugin commands
// Handles both human-friendly and JSON output based on --output flag
// Uses global -v count for verbosity level (consistent with scan command)
func setupPluginOutputPipeline(cmd *cobra.Command) output.Output {
	stream := output.NewOutputEventStream()

	// Determine output format
	outputFormat, _ := cmd.Flags().GetString("output")
	noColor, _ := cmd.Flags().GetBool("no-color")

	if outputFormat == outputFormatJSON {
		// JSON output mode
		stream.Subscribe(subscribers.NewJSONFormatter(os.Stdout))
	} else {
		// Human-friendly output mode with optional color
		colorEnabled := !noColor
		stream.Subscribe(subscribers.NewHumanFormatter(os.Stdout, os.Stderr, colorEnabled))
	}

	// Add diagnostic subscriber based on global verbosity counter
	// Only for text mode (JSON mode should not have styled diagnostic output)
	// Uses global persistent -v flag (same as scan command)
	// -v (1): Verbose, -vv (2): Debug, -vvv (3): Trace
	if outputFormat != outputFormatJSON {
		verbosityCount, _ := cmd.Flags().GetCount("verbosity")
		if verbosityCount > 0 {
			level := output.OutputLevel(verbosityCount)
			stream.Subscribe(subscribers.NewDiagnosticSubscriber(level, os.Stderr))
		}
	}

	return output.NewDefaultOutput(stream)
}
