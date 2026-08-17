// pkg/config/types.go
package config

import "time"

// Config is the root configuration structure for the Cyprob application.
// It aggregates all other specific configuration structs.
type Config struct {
	Log    LogConfig    `description:"Logging configuration" koanf:"log"`   // Logging configuration
	Server ServerConfig `description:"Server configuration" koanf:"server"` // Server configuration
}

// LogConfig holds logging related configuration.
type LogConfig struct {
	Level  string `description:"Log level set to cyprob logs." koanf:"level"`   // Log level (e.g., "debug", "info", "warn", "error")
	Format string `description:"Cyprob log format: json | text" koanf:"format"` // Log format (e.g., "json", "text")
	File   string `description:"Log file path" koanf:"file"`                    // Log file path (optional)
}

// ServerConfig holds configuration for the Cyprob server runtime.
// Used by 'cyprob server start' command.
type ServerConfig struct {
	// Network settings
	Addr string `description:"Server listen address" koanf:"addr"`
	Port int    `description:"Server listen port" koanf:"port"`

	// Component toggles
	UIEnabled   bool `description:"Enable UI static serving" koanf:"ui_enabled"`
	APIEnabled  bool `description:"Enable REST API endpoints" koanf:"api_enabled"`
	JobsEnabled bool `description:"Enable background job workers" koanf:"jobs_enabled"`

	// Paths
	WorkspaceDir string `description:"Workspace root directory" koanf:"workspace_dir"`

	// Performance
	Concurrency int `description:"Number of concurrent background workers" koanf:"concurrency"`

	// HTTP timeouts
	ReadTimeout  time.Duration `description:"HTTP read timeout" koanf:"read_timeout"`
	WriteTimeout time.Duration `description:"HTTP write timeout" koanf:"write_timeout"`

	// Sub-configurations
	UI   UIConfig   `description:"UI configuration" koanf:"ui"`
	Auth AuthConfig `description:"Authentication configuration" koanf:"auth"`
}

// UIConfig holds UI-specific configuration.
type UIConfig struct {
	AssetsPath string `description:"Override embedded assets with disk path (for development)" koanf:"assets_path"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Mode  string `description:"Authentication mode: none|token|oidc" koanf:"mode"`
	Token string `description:"Static bearer token (required for token mode)" koanf:"token"`
}
