// pkg/config/config.go
package config

import (
	"fmt"
	"sort"
	"sync"

	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// Global Koanf instance, initialized once at startup.
var (
	k    *koanf.Koanf
	once sync.Once
)

// InitGlobalKoanf initializes the global Koanf instance.
// This should be called early in the application lifecycle, before Load.
func InitGlobalConfig() {
	once.Do(func() {
		k = koanf.New(".")
	})
}

// ConfigManager handles loading and accessing application configuration.
type Manager struct {
	koanfInstance *koanf.Koanf
	currentConfig Config
	mu            sync.RWMutex // To protect currentConfig during runtime updates
}

// NewManager creates a new ConfigManager.
// It initializes the global Koanf instance if not already done.
func NewManager( /*dbProvider dbprovider.Provider*/ ) *Manager { // Pass DB provider if used
	InitGlobalConfig() // Ensure global k is initialized
	// Initialize the Koanf instance if it hasn't been done already
	return &Manager{
		koanfInstance: k, // Use the global instance
		// dbProvider:    dbProvider,
	}
}

// DefaultConfig returns a new Config struct populated with hardcoded default values.
// These serve as the baseline configuration if no other sources override them.
func DefaultConfig() Config {
	return Config{
		Log: LogConfig{
			Level:  "info", // Default log level
			Format: "text", // Default log format
			File:   "",     // Default log file path
		},
		Server: DefaultServerConfig(),
	}
}

// Load loads configuration from various sources based on precedence.
// It populates the manager's currentConfig.
//
// Configuration precedence (highest to lowest):
//  1. Command-line flags (--log.level=debug)
//  2. Environment variables (CYPROB_LOG_LEVEL=debug)
//  3. Config file (YAML)
//  4. Default values
//
// Environment variables use the CYPROB_ prefix and underscore-to-dot mapping
// (the former VULNTOR_ prefix is still read as a deprecated fallback):
//
//	CYPROB_LOG_LEVEL      -> log.level
//	CYPROB_SERVER_PORT    -> server.port
//
// For custom source ordering, use LoadWithSources() instead.
func (m *Manager) Load(flags *pflag.FlagSet, customConfigFilePath string) error {
	// Check debug flag before creating sources
	debug := false
	if flags != nil {
		debugFlag := flags.Lookup("debug")
		if debugFlag != nil && debugFlag.Value.String() == "true" {
			debug = true
		}
	}

	sources := DefaultSources(customConfigFilePath, flags, debug)
	return m.LoadWithSources(sources)
}

// LoadWithSources loads configuration from the provided sources in priority order.
// Sources with lower priority values are loaded first, higher priority sources
// override lower priority values.
//
// This method allows custom source ordering and additional sources (e.g., system
// config, secrets manager) to be inserted into the loading chain.
func (m *Manager) LoadWithSources(sources []ConfigSource) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Sort sources by priority (lowest first)
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].Priority() < sources[j].Priority()
	})

	// Load each source in order
	for _, src := range sources {
		if err := src.Load(m.koanfInstance); err != nil {
			return fmt.Errorf("error loading config from %s: %w", src.Name(), err)
		}
	}

	// Unmarshal the final merged configuration into m.currentConfig
	var newCfg Config
	if err := m.koanfInstance.UnmarshalWithConf("", &newCfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
		return fmt.Errorf("error unmarshaling final config: %w", err)
	}
	m.currentConfig = newCfg

	// Apply any post-load processing or validation.
	m.postProcessConfig()

	return nil
}

// Get returns a copy of the current configuration.
func (m *Manager) Get() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a copy to prevent modification of the internal state.
	// For deep copies, you might need a library or manual copying if structs are complex.
	// For this example, a shallow copy is shown.
	cfgCopy := m.currentConfig
	return cfgCopy
}

// GetValue retrieves a configuration value by key path.
// Example: GetValue("modules.tcp-port-discovery.concurrency")
// Returns nil if key doesn't exist.
func (m *Manager) GetValue(key string) any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.koanfInstance.Get(key)
}

// UpdateRuntimeValue updates a specific configuration value at runtime.
// This is a simplified example; a more robust solution would involve:
// - Validating the key and value.
// - Potentially re-unmarshaling or selectively updating m.currentConfig.
// - Notifying other parts of the application about the change (e.g., via an event bus).
func (m *Manager) UpdateRuntimeValue(key string, value any) error {
	return nil
}

// postProcessConfig handles any adjustments needed after loading and unmarshaling.
func (m *Manager) postProcessConfig() {}

// DefaultConfigAsMap converts the DefaultConfig struct to a map[string]interface{}
// for Koanf's confmap.Provider. This is a bit manual but ensures Koanf knows all keys.
func DefaultConfigAsMap() map[string]any {
	def := DefaultConfig()
	// This can be done more elegantly with reflection or a library if the struct is very large.
	return map[string]any{
		// Log configuration
		"log.level":  def.Log.Level,
		"log.format": def.Log.Format,
		"log.file":   def.Log.File,

		// Server configuration
		"server.addr":          def.Server.Addr,
		"server.port":          def.Server.Port,
		"server.ui_enabled":    def.Server.UIEnabled,
		"server.api_enabled":   def.Server.APIEnabled,
		"server.jobs_enabled":  def.Server.JobsEnabled,
		"server.workspace_dir": def.Server.WorkspaceDir,
		"server.concurrency":   def.Server.Concurrency,
		"server.read_timeout":  def.Server.ReadTimeout,
		"server.write_timeout": def.Server.WriteTimeout,

		// UI configuration
		"server.ui.assets_path": def.Server.UI.AssetsPath,

		// Auth configuration
		"server.auth.mode":  def.Server.Auth.Mode,
		"server.auth.token": def.Server.Auth.Token,
	}
}

// BindFlags defines command-line flags corresponding to configuration settings.
// These flags allow overriding config file / environment variable settings.
// This function should be called when setting up Cobra commands.
func BindFlags(flags *pflag.FlagSet) {
	// Get default config to provide default values for flags' help text
	// defaults := DefaultConfig()

	// Log flags
	// flags.String("log.level", defaults.Log.Level, "Log level (debug, info, warn, error)")
	// flags.String("log.format", defaults.Log.Format, "Log format (text, json)")
	// flags.String("log.file", defaults.Log.File, "Path to log file (optional, leave empty for stdout)")

	var flagvar bool
	flags.BoolVar(&flagvar, "debug", false, "Enable debug logging")

	// Note: The main --config / -c flag for specifying the config file path
	// is typically defined directly on the root Cobra command's PersistentFlags.
}
