package commands

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	dagCmd "github.com/vulntor/vulntor/cmd/vulntor/commands/dag"
	pluginCmd "github.com/vulntor/vulntor/cmd/vulntor/commands/plugin"
	serverCmd "github.com/vulntor/vulntor/cmd/vulntor/commands/server"
	storageCmd "github.com/vulntor/vulntor/cmd/vulntor/commands/storage"
	"github.com/vulntor/vulntor/pkg/appctx"
	"github.com/vulntor/vulntor/pkg/cli"
	"github.com/vulntor/vulntor/pkg/config"
	"github.com/vulntor/vulntor/pkg/engine"
	// Register all available modules for DAG execution
	_ "github.com/vulntor/vulntor/pkg/modules/evaluation" // Vulnerability evaluation modules
	_ "github.com/vulntor/vulntor/pkg/modules/parse"      // Protocol parser modules
	_ "github.com/vulntor/vulntor/pkg/modules/reporting"  // Reporting modules
	_ "github.com/vulntor/vulntor/pkg/modules/scan"       // Scanner modules
	"github.com/vulntor/vulntor/pkg/storage"
)

const cliExecutable = "vulntor"

// NewCommand constructs the top-level vulntor CLI command, wiring global flags,
// AppManager lifecycle, and shared workspace preparation.
func NewCommand() *cobra.Command {
	var (
		configFile      string
		storageDir      string
		storageDisabled bool
		appManager      engine.Manager
		verbosityCount  int
		verbose         bool
	)

	cmd := &cobra.Command{
		Use:   cliExecutable,
		Short: "Vulntor is a fast and flexible network scanner",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			factory := &engine.DefaultAppManagerFactory{}

			mgr, err := factory.Create(cmd.Flags(), configFile)
			if err != nil {
				return fmt.Errorf("initialize AppManager: %w", err)
			}
			appManager = mgr

			ctx := context.WithValue(cmd.Context(), engine.AppManagerKey, appManager)
			ctx = appctx.WithConfig(ctx, appManager.Config())

			if !storageDisabled {
				storageConfig, err := storage.DefaultConfig()
				if err != nil {
					return fmt.Errorf("get storage config: %w", err)
				}
				if storageDir != "" {
					storageConfig.WorkspaceRoot = storageDir
				}
				ctx = storage.WithConfig(ctx, storageConfig)
				log.Info().Str("storage_root", storageConfig.WorkspaceRoot).Msg("storage ready")
			} else {
				log.Info().Msg("storage disabled for this run")
			}

			// Configure global log level based on verbosity flags
			// If explicit --verbose is set, show debug and above
			// Else use -v count: 0=>Error, 1=>Info, 2+=>Debug
			if verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			} else {
				switch {
				case verbosityCount <= 0:
					zerolog.SetGlobalLevel(zerolog.ErrorLevel)
				case verbosityCount == 1:
					zerolog.SetGlobalLevel(zerolog.InfoLevel)
				default:
					zerolog.SetGlobalLevel(zerolog.DebugLevel)
				}
			}

			cmd.SetContext(ctx)
			if root := cmd.Root(); root != nil && root != cmd {
				root.SetContext(ctx)
			}
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if appManager != nil {
				appManager.Shutdown()
			}
			return nil
		},
	}

	cmd.SilenceUsage = true

	cmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file path")
	cmd.PersistentFlags().StringVar(&storageDir, "storage-dir", "", "Override storage root directory")
	cmd.PersistentFlags().BoolVar(&storageDisabled, "no-storage", false, "Disable storage persistence for this run")
	cmd.PersistentFlags().CountVarP(&verbosityCount, "verbosity", "v", "Increase logging verbosity (repeatable)")
	cmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging (shows service layer logs)")

	config.BindFlags(cmd.PersistentFlags())

	cmd.AddGroup(&cobra.Group{ID: "scan", Title: "Scan Commands"})
	cmd.AddGroup(&cobra.Group{ID: "core", Title: "Core Commands"})

	cmd.AddCommand(dagCmd.NewCommand())
	cmd.AddCommand(pluginCmd.NewCommand())
	cmd.AddCommand(serverCmd.NewCommand())
	cmd.AddCommand(storageCmd.NewStorageCommand())
	cmd.AddCommand(cli.NewVersionCommand(cliExecutable))
	cmd.AddCommand(ScanCmd)
	cmd.AddCommand(NewScanDebugCommand())
	cmd.AddCommand(NewFingerprintCommand())
	cmd.AddCommand(NewStatsCommand())

	return cmd
}
