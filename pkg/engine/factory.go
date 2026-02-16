// pkg/engine/factory.go
package engine

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/event"
	"github.com/cyprob/cyprob/pkg/hook"
	"github.com/cyprob/cyprob/pkg/logging"
)

// Factory is responsible for constructing an AppManager instance with all required components.
type AppManagerFactory interface {
	CreateWithConfig(flags *pflag.FlagSet, configFile string) (*AppManager, error)
}

// DefaultAppManagerFactory is a factory type responsible for creating instances of the default application manager.
// It provides methods to instantiate and configure application managers with default settings.
type DefaultAppManagerFactory struct{}

// Create initializes a new AppManager instance with a cancellable context and the current application version.
// It returns a pointer to the created AppManager.
// Create initializes and returns a new AppManager instance.
// It configures global logging based on the provided flags, loads configuration
// from the specified configFile, and sets up a cancellable context for the AppManager.
// Returns an error if logging configuration or configuration loading fails.
//
// Parameters:
//   - flags:      A pflag.FlagSet containing runtime flags, may be nil.
//   - configFile: Path to the configuration file.
//
// Returns:
//   - *AppManager: A pointer to the initialized AppManager.
//   - error:       An error if initialization fails.
func (f *DefaultAppManagerFactory) Create(flags *pflag.FlagSet, configFile string) (*AppManager, error) {
	logLevel := f.GetRuntimeLogLevel(flags)

	// Configure global logging for CLI
	// Colors are auto-detected based on TTY (see logging.ConfigureGlobal)
	logging.ConfigureGlobal(logLevel)

	ConfigManager := config.NewManager()
	if err := ConfigManager.Load(flags, configFile); err != nil {
		return nil, err
	}

	context, cancel := context.WithCancel(context.Background())

	return &AppManager{
		ctx:           context,
		cancel:        cancel,
		ConfigManager: ConfigManager,
		EventManager:  event.NewManager(),
		HookManager:   hook.NewManager(),
	}, nil
}

// CreateWithConfig creates a new AppManager instance using the provided pflag.FlagSet and configuration file.
// It delegates the creation process to the Create method of DefaultAppManagerFactory.
// Returns a pointer to the created AppManager and an error if the creation fails.
func (f *DefaultAppManagerFactory) CreateWithConfig(flags *pflag.FlagSet, configFile string) (*AppManager, error) {
	return f.Create(flags, configFile)
}

// CreateWithNoConfig creates a new AppManager instance without any configuration.
// It calls the Create method with nil configuration and an empty string as parameters.
// Returns the created AppManager and any error encountered during creation.
func (f *DefaultAppManagerFactory) CreateWithNoConfig() (*AppManager, error) {
	return f.Create(nil, "")
}

// GetRuntimeLogLevel determines the runtime log level based on the provided flag set.
// If the "debug" flag is set to "true", it returns "debug"; otherwise, it defaults to "info".
func (f *DefaultAppManagerFactory) GetRuntimeLogLevel(flags *pflag.FlagSet) zerolog.Level {
	logLevel := zerolog.DebugLevel // Default log level
	if flags != nil {
		verbosityLevel, err := flags.GetCount("verbosity")
		if err == nil {
			// If verbosity is set, we can adjust the log level accordingly.
			switch verbosityLevel {
			case 1:
				logLevel = zerolog.InfoLevel
			case 2:
				logLevel = zerolog.DebugLevel
			case 3:
				logLevel = zerolog.TraceLevel
			default:
				logLevel = zerolog.WarnLevel // Default to warn if unknown verbosity
			}
		}
	}
	return logLevel
}
