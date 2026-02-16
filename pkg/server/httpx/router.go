package httpx

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/server/api"
	v1 "github.com/cyprob/cyprob/pkg/server/api/v1"
	"github.com/cyprob/cyprob/pkg/ui"
)

// NewRouter creates and configures the main HTTP router.
// It mounts health endpoints, API, and UI based on the configuration.
//
// The router uses Go 1.22+ enhanced pattern matching for cleaner routes.
// Routes are mounted conditionally based on cfg.APIEnabled and cfg.UIEnabled.
//
// Health endpoints are always enabled for liveness/readiness checks.
func NewRouter(cfg config.ServerConfig, deps *api.Deps) *http.ServeMux {
	mux := http.NewServeMux()

	// Health endpoints (always enabled)
	mux.HandleFunc("GET /healthz", HealthzHandler)
	mux.HandleFunc("GET /readyz", v1.ReadyzHandler(deps.Ready))

	// API endpoints (conditional)
	if cfg.APIEnabled {
		// Scan endpoints
		mux.HandleFunc("GET /api/v1/scans", v1.ListScansHandler(deps))
		mux.HandleFunc("GET /api/v1/scans/{id}", v1.GetScanHandler(deps))

		// Plugin endpoints (only if PluginService is available)
		if deps.PluginService != nil {
			// Type assert to v1.PluginService (the actual type will be *plugin.Service)
			if pluginSvc, ok := deps.PluginService.(v1.PluginService); ok {
				log.Info().
					Str("component", "httpx.router").
					Msg("mounting plugin API routes")
				mux.HandleFunc("POST /api/v1/plugins/install", v1.InstallPluginHandler(pluginSvc, deps.Config))
				mux.HandleFunc("POST /api/v1/plugins/update", v1.UpdatePluginsHandler(pluginSvc, deps.Config))
				mux.HandleFunc("GET /api/v1/plugins", v1.ListPluginsHandler(pluginSvc))
				mux.HandleFunc("GET /api/v1/plugins/{id}", v1.GetPluginHandler(pluginSvc))
				mux.HandleFunc("DELETE /api/v1/plugins/{id}", v1.UninstallPluginHandler(pluginSvc, deps.Config))
			} else {
				log.Warn().
					Str("component", "httpx.router").
					Str("actual_type", fmt.Sprintf("%T", deps.PluginService)).
					Msg("PluginService type assertion failed - plugin API routes NOT mounted")
			}
		} else {
			log.Info().
				Str("component", "httpx.router").
				Msg("PluginService not provided - skipping plugin API routes")
		}
	}

	// UI static serving (conditional)
	if cfg.UIEnabled {
		uiHandler := ui.NewHandler(cfg)
		mux.Handle("/", uiHandler)
	}

	return mux
}

// HealthzHandler responds with 200 OK if the server process is alive.
// This endpoint is used by load balancers and orchestrators for liveness checks.
//
// It does not check dependencies (database, jobs, etc.) - just process health.
// For comprehensive readiness checks, use /readyz instead.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
