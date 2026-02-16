// Package server provides the Cobra command implementation for the Vulntor server lifecycle.
// It wires CLI flags to the server runtime and handles the start/stop commands.
package server

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/appctx"
	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/logging"
	"github.com/cyprob/cyprob/pkg/plugin"
	serversvc "github.com/cyprob/cyprob/pkg/server"
	"github.com/cyprob/cyprob/pkg/server/api"
	"github.com/cyprob/cyprob/pkg/server/app"
	"github.com/cyprob/cyprob/pkg/storage"
)

// stubWorkspace is a temporary workspace implementation.
// TODO: Replace with real workspace implementation from pkg/workspace
type stubWorkspace struct{}

func (s *stubWorkspace) ListScans() ([]api.ScanMetadata, error) {
	return []api.ScanMetadata{}, nil
}

func (s *stubWorkspace) GetScan(id string) (*api.ScanDetail, error) {
	return nil, fmt.Errorf("scan not found: %s", id)
}

// newStartServerCommand creates and returns the 'vulntor server start' command.
//
// This command initializes the Vulntor server runtime, which includes:
//   - HTTP API server with REST endpoints (/api/v1/scans, etc.)
//   - Static UI asset serving (/ui/*)
//   - Health and readiness endpoints (/healthz, /readyz)
//   - Background job workers (scan execution, scheduling, notifications)
//
// The server runs until interrupted (SIGINT/SIGTERM) or context cancellation,
// then performs graceful shutdown (HTTP close → jobs stop).
//
// Configuration is loaded from:
//   - Global flags (--workspace-dir, --config, etc.)
//   - Server-specific flags (--addr, --port, --no-ui, --no-api, --jobs-concurrency)
//   - Environment variables (VULNTOR_*)
//   - Config file (vulntor.yaml)
//
// Example usage:
//
//	vulntor server start
//	vulntor server start --addr 0.0.0.0 --port 8080
//	vulntor server start --workspace-dir /data/vulntor --jobs-concurrency 10
//
// See NOTES.md#30 for detailed server architecture design.
func newStartServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the Vulntor server",
		Long: `Start the Vulntor server process.

The server hosts multiple components in a single runtime:
  - HTTP API (REST endpoints for scan management and workspace queries)
  - Web UI (static SPA with client-side routing)
  - Background workers (job queue, scheduler, notifier)

The server runs until interrupted (Ctrl+C) or killed, performing graceful
shutdown to drain in-flight requests and complete running jobs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := format.FromCommand(cmd)

			// Bind flags to options using centralized binder
			opts, err := bind.BindServerOptions(cmd)
			if err != nil {
				return formatter.PrintTotalFailureSummary("start server", err, serversvc.ErrorCode(err))
			}

			// Build server config
			cfg := config.ServerConfig{
				Addr:         opts.Addr,
				Port:         opts.Port,
				UIEnabled:    !opts.NoUI,
				APIEnabled:   !opts.NoAPI,
				JobsEnabled:  true,
				Concurrency:  opts.Concurrency,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				UI: config.UIConfig{
					AssetsPath: opts.UIAssetsPath,
				},
				Auth: config.AuthConfig{
					Mode: "none", // TODO: Add auth flags when auth system is implemented
				},
			}

			// Validate configuration
			if err := cfg.Validate(); err != nil {
				wrapped := serversvc.WrapInvalidConfig(err)
				return formatter.PrintTotalFailureSummary("start server", wrapped, serversvc.ErrorCode(wrapped))
			}

			// Get config manager from context
			cfgMgr, ok := appctx.Config(cmd.Context())
			if !ok {
				err := serversvc.ErrConfigUnavailable
				return formatter.PrintTotalFailureSummary("start server", err, serversvc.ErrorCode(err))
			}

			// Create storage backend
			storageConfig, err := storage.DefaultConfig()
			if err != nil {
				wrapped := serversvc.WrapStorageInit(err)
				return formatter.PrintTotalFailureSummary("start server", wrapped, serversvc.ErrorCode(wrapped))
			}

			storageBackend, err := storage.NewBackend(cmd.Context(), storageConfig)
			if err != nil {
				wrapped := serversvc.WrapStorageInit(err)
				return formatter.PrintTotalFailureSummary("start server", wrapped, serversvc.ErrorCode(wrapped))
			}

			// TODO: Keep stub workspace for backward compatibility during transition
			// Remove this when all code paths use storage
			ws := &stubWorkspace{}

			// Create plugin service for API endpoints
			// Use storage config's WorkspaceRoot for plugin cache
			pluginCacheDir := filepath.Join(storageConfig.WorkspaceRoot, "plugins", "cache")
			pluginService, err := plugin.NewService(plugin.WithCacheDir(pluginCacheDir))
			if err != nil {
				wrapped := serversvc.WrapPluginInit(err)
				return formatter.PrintTotalFailureSummary("start server", wrapped, serversvc.ErrorCode(wrapped))
			}

			// Create logger for server
			logger := logging.NewLogger("server", zerolog.InfoLevel)

			// Start manifest file watcher to auto-reload when CLI makes changes (Issue #27)
			// This ensures server API immediately reflects CLI plugin install/uninstall
			go func() {
				if err := pluginService.StartManifestWatcher(cmd.Context()); err != nil {
					// Log error but don't fail server startup (watcher is optional enhancement)
					logger.Warn().
						Err(err).
						Msg("Manifest watcher failed (server will work but won't auto-sync with CLI changes)")
				}
			}()

			// Build dependencies
			deps := &app.Deps{
				Storage:       storageBackend,
				Workspace:     ws,
				PluginService: pluginService,
				Config:        cfgMgr,
				Logger:        logger,
			}

			// Create server app
			serverApp, err := app.New(cmd.Context(), cfg, deps)
			if err != nil {
				wrapped := serversvc.WrapAppInit(err)
				return formatter.PrintTotalFailureSummary("start server", wrapped, serversvc.ErrorCode(wrapped))
			}

			// Run server (blocks until shutdown)
			runErr := serverApp.Run(cmd.Context())
			if runErr != nil {
				wrapped := serversvc.WrapRuntime(runErr)
				return formatter.PrintTotalFailureSummary("start server", wrapped, serversvc.ErrorCode(wrapped))
			}

			return nil
		},
	}

	// Server-specific flags
	cmd.Flags().String("addr", "127.0.0.1", "Server listen address")
	cmd.Flags().Int("port", 8080, "Server listen port")
	cmd.Flags().Bool("no-ui", false, "Disable UI static serving")
	cmd.Flags().Bool("no-api", false, "Disable REST API endpoints")
	cmd.Flags().Int("jobs-concurrency", 4, "Number of concurrent background workers")
	cmd.Flags().String("ui-assets-path", "", "UI assets directory (dev mode: serve from disk)")

	return cmd
}
