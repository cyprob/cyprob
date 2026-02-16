// pkg/plugin/context.go
// Package plugin defines shared context for plugin execution.
package plugin

import (
	"github.com/rs/zerolog"

	"github.com/cyprob/cyprob/pkg/hook"
)

// PluginContext carries execution context for plugins.
type PluginContext struct {
	Target   string         // IP or hostname to scan
	ScanID   string         // Unique scan ID
	Logger   zerolog.Logger // Plugin-specific logger
	Settings map[string]any // Optional plugin-specific config
	Hooks    *hook.Manager
}
