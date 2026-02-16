package bind

import (
	"github.com/spf13/cobra"

	srv "github.com/cyprob/cyprob/pkg/server"
)

// ServerOptions holds configuration options for the server start command.
type ServerOptions struct {
	Addr         string
	Port         int
	NoUI         bool
	NoAPI        bool
	Concurrency  int
	UIAssetsPath string
}

// BindServerOptions extracts and validates server command flags.
//
// This function reads the server-specific flags from the Cobra command and
// constructs a properly validated ServerOptions struct.
//
// Flags read:
//   - --addr: Server listen address (e.g., "127.0.0.1", "0.0.0.0")
//   - --port: Server listen port (1-65535)
//   - --no-ui: Disable UI static serving
//   - --no-api: Disable REST API endpoints
//   - --jobs-concurrency: Number of concurrent background workers
//   - --ui-assets-path: UI assets directory (dev mode)
//
// Returns an error if validation fails (e.g., invalid port range, invalid concurrency).
func BindServerOptions(cmd *cobra.Command) (ServerOptions, error) {
	addr, _ := cmd.Flags().GetString("addr")
	port, _ := cmd.Flags().GetInt("port")
	noUI, _ := cmd.Flags().GetBool("no-ui")
	noAPI, _ := cmd.Flags().GetBool("no-api")
	concurrency, _ := cmd.Flags().GetInt("jobs-concurrency")
	uiAssetsPath, _ := cmd.Flags().GetString("ui-assets-path")

	// Validate port range
	if port < 1 || port > 65535 {
		return ServerOptions{}, srv.NewInvalidPortError(port)
	}

	// Validate concurrency
	if concurrency < 1 {
		return ServerOptions{}, srv.NewInvalidConcurrencyError(concurrency)
	}

	// Validate that at least UI or API is enabled
	if noUI && noAPI {
		return ServerOptions{}, srv.NewFeaturesDisabledError()
	}

	opts := ServerOptions{
		Addr:         addr,
		Port:         port,
		NoUI:         noUI,
		NoAPI:        noAPI,
		Concurrency:  concurrency,
		UIAssetsPath: uiAssetsPath,
	}

	return opts, nil
}
