// pkg/config/source.go
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// ConfigSource represents a configuration source that can load values into koanf.
// Sources are loaded in priority order (lowest first), with higher priority sources
// overriding lower priority values.
//
// Built-in sources and their priorities:
//   - DefaultSource (10): Hardcoded default values
//   - FileSource (20): Config file (e.g., ~/.config/cyprob/config.yaml)
//   - EnvSource (30): Environment variables (VULNTOR_*)
//   - FlagSource (40): Command-line flags
//
// Custom sources can use priorities between these values to insert
// additional configuration layers (e.g., system config at 15, secrets at 25).
type ConfigSource interface {
	// Name returns a human-readable name for this source (for logging/debugging)
	Name() string

	// Priority returns the load priority. Lower values are loaded first,
	// higher values override lower ones.
	Priority() int

	// Load loads configuration values into the provided koanf instance.
	// Returns an error if loading fails.
	Load(k *koanf.Koanf) error
}

// DefaultSource provides hardcoded default configuration values.
// Priority: 10 (lowest, loaded first)
type DefaultSource struct{}

func (s *DefaultSource) Name() string  { return "defaults" }
func (s *DefaultSource) Priority() int { return 10 }

func (s *DefaultSource) Load(k *koanf.Koanf) error {
	defaultCfgMap := DefaultConfigAsMap()
	if err := k.Load(confmap.Provider(defaultCfgMap, "."), nil); err != nil {
		return fmt.Errorf("error loading defaults: %w", err)
	}
	return nil
}

// FileSource loads configuration from a YAML file.
// Priority: 20
type FileSource struct {
	Path     string // Path to config file
	Required bool   // If true, error when file doesn't exist (for --config flag)
}

func (s *FileSource) Name() string  { return "file:" + s.Path }
func (s *FileSource) Priority() int { return 20 }

func (s *FileSource) Load(k *koanf.Koanf) error {
	if s.Path == "" {
		return nil // No file specified, skip silently
	}

	if _, err := os.Stat(s.Path); err != nil {
		if os.IsNotExist(err) {
			if s.Required {
				return fmt.Errorf("config file not found: %s", s.Path)
			}
			return nil // File doesn't exist, skip silently
		}
		return fmt.Errorf("error checking config file %s: %w", s.Path, err)
	}

	if err := k.Load(file.Provider(s.Path), yaml.Parser()); err != nil {
		return fmt.Errorf("error loading config file %s: %w", s.Path, err)
	}
	return nil
}

// EnvSource loads configuration from environment variables.
// Variables must have VULNTOR_ prefix. Underscores map to dots:
//
//	VULNTOR_LOG_LEVEL -> log.level
//	VULNTOR_SERVER_PORT -> server.port
//
// Priority: 30
type EnvSource struct {
	Prefix string // Environment variable prefix (default: "VULNTOR_")
}

func (s *EnvSource) Name() string  { return "env" }
func (s *EnvSource) Priority() int { return 30 }

func (s *EnvSource) Load(k *koanf.Koanf) error {
	prefix := s.Prefix
	if prefix == "" {
		prefix = "VULNTOR_"
	}

	if err := k.Load(env.Provider(prefix, ".", func(key string) string {
		return strings.ReplaceAll(strings.ToLower(
			strings.TrimPrefix(key, prefix)), "_", ".")
	}), nil); err != nil {
		return fmt.Errorf("error loading environment variables: %w", err)
	}
	return nil
}

// FlagSource loads configuration from command-line flags.
// Priority: 40 (highest, overrides all other sources)
type FlagSource struct {
	Flags *pflag.FlagSet
	Debug bool // If true, set log.level to "debug"
}

func (s *FlagSource) Name() string  { return "flags" }
func (s *FlagSource) Priority() int { return 40 }

func (s *FlagSource) Load(k *koanf.Koanf) error {
	if s.Flags != nil {
		if err := k.Load(posflag.Provider(s.Flags, ".", k), nil); err != nil {
			return fmt.Errorf("error loading command-line flags: %w", err)
		}
	}

	// Handle --debug flag specially (can be set even without flags)
	if s.Debug {
		_ = k.Set("log.level", "debug")
	}

	return nil
}

// DefaultSources returns the standard configuration sources.
// Order: defaults -> file -> env -> flags
func DefaultSources(configPath string, flags *pflag.FlagSet, debug bool) []ConfigSource {
	return []ConfigSource{
		&DefaultSource{},
		&FileSource{Path: configPath, Required: configPath != ""},
		&EnvSource{Prefix: "VULNTOR_"},
		&FlagSource{Flags: flags, Debug: debug},
	}
}
