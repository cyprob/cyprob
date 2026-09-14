package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSource_Priority(t *testing.T) {
	src := &DefaultSource{}
	assert.Equal(t, 10, src.Priority())
	assert.Equal(t, "defaults", src.Name())
}

func TestDefaultSource_Load(t *testing.T) {
	k := koanf.New(".")
	src := &DefaultSource{}

	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "info", k.String("log.level"))
	assert.Equal(t, "text", k.String("log.format"))
}

func TestFileSource_Priority(t *testing.T) {
	src := &FileSource{Path: "/tmp/test.yaml"}
	assert.Equal(t, 20, src.Priority())
	assert.Equal(t, "file:/tmp/test.yaml", src.Name())
}

func TestFileSource_Load_EmptyPath(t *testing.T) {
	k := koanf.New(".")
	src := &FileSource{Path: ""}

	err := src.Load(k)
	require.NoError(t, err, "Empty path should skip silently")
}

func TestFileSource_Load_NonExistentFile(t *testing.T) {
	k := koanf.New(".")
	src := &FileSource{Path: "/nonexistent/path/config.yaml"}

	err := src.Load(k)
	require.NoError(t, err, "Non-existent file should skip silently")
}

func TestFileSource_Load_NonExistentFile_Required(t *testing.T) {
	k := koanf.New(".")
	src := &FileSource{Path: "/nonexistent/path/config.yaml", Required: true}

	err := src.Load(k)
	require.Error(t, err, "Non-existent required file should error")
	assert.Contains(t, err.Error(), "config file not found")
}

func TestFileSource_Load_ValidFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
log:
  level: warn
  format: json
server:
  port: 9999
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	k := koanf.New(".")
	src := &FileSource{Path: configPath}

	err = src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "warn", k.String("log.level"))
	assert.Equal(t, "json", k.String("log.format"))
	assert.Equal(t, 9999, k.Int("server.port"))
}

func TestEnvSource_Priority(t *testing.T) {
	src := &EnvSource{}
	assert.Equal(t, 30, src.Priority())
	assert.Equal(t, "env", src.Name())
}

func TestEnvSource_Load(t *testing.T) {
	t.Setenv("CYPROB_LOG_LEVEL", "error")
	t.Setenv("CYPROB_SERVER_PORT", "8888")

	k := koanf.New(".")
	src := &EnvSource{Prefix: "CYPROB_"}

	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "error", k.String("log.level"))
	assert.Equal(t, 8888, k.Int("server.port"))
}

func TestEnvSource_Load_DefaultPrefix(t *testing.T) {
	t.Setenv("CYPROB_LOG_FORMAT", "json")

	k := koanf.New(".")
	src := &EnvSource{} // No prefix specified, should default to CYPROB_

	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "json", k.String("log.format"))
}

func TestEnvSource_Load_LegacyPrefixFallback(t *testing.T) {
	t.Setenv("VULNTOR_LOG_FORMAT", "json")

	k := koanf.New(".")
	src := &EnvSource{} // default: CYPROB_ primary, VULNTOR_ legacy

	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "json", k.String("log.format"))
}

func TestEnvSource_Load_PrimaryWinsOverLegacy(t *testing.T) {
	t.Setenv("CYPROB_LOG_LEVEL", "error")
	t.Setenv("VULNTOR_LOG_LEVEL", "debug")

	k := koanf.New(".")
	src := &EnvSource{}

	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "error", k.String("log.level"))
}

func TestFlagSource_Priority(t *testing.T) {
	src := &FlagSource{}
	assert.Equal(t, 40, src.Priority())
	assert.Equal(t, "flags", src.Name())
}

func TestFlagSource_Load_NilFlags(t *testing.T) {
	k := koanf.New(".")
	src := &FlagSource{Flags: nil}

	err := src.Load(k)
	require.NoError(t, err, "Nil flags should skip silently")
}

func TestFlagSource_Load(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("log.level", "info", "")
	_ = flags.Set("log.level", "debug")

	k := koanf.New(".")
	// Load defaults first so koanf knows the keys
	_ = k.Load(nil, nil)

	src := &FlagSource{Flags: flags}
	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "debug", k.String("log.level"))
}

func TestFlagSource_Load_DebugFlag(t *testing.T) {
	k := koanf.New(".")

	src := &FlagSource{Flags: nil, Debug: true}
	err := src.Load(k)
	require.NoError(t, err)

	assert.Equal(t, "debug", k.String("log.level"))
}

func TestDefaultSources_Order(t *testing.T) {
	sources := DefaultSources("/tmp/config.yaml", nil, false)

	require.Len(t, sources, 4)
	assert.Equal(t, "defaults", sources[0].Name())
	assert.Equal(t, "file:/tmp/config.yaml", sources[1].Name())
	assert.Equal(t, "env", sources[2].Name())
	assert.Equal(t, "flags", sources[3].Name())
}

func TestDefaultSources_Priorities(t *testing.T) {
	sources := DefaultSources("", nil, false)

	// Verify priorities are in ascending order
	for i := 1; i < len(sources); i++ {
		assert.Greater(t, sources[i].Priority(), sources[i-1].Priority(),
			"Source %s should have higher priority than %s",
			sources[i].Name(), sources[i-1].Name())
	}
}

func TestLoadWithSources_CustomSource(t *testing.T) {
	resetGlobalConfig()

	// Create a custom source that inserts between file and env
	customSource := &mockConfigSource{
		name:     "custom",
		priority: 25, // Between file (20) and env (30)
		loadFunc: func(k *koanf.Koanf) error {
			return k.Set("log.level", "custom-level")
		},
	}

	manager := NewManager()
	sources := []ConfigSource{
		&DefaultSource{},
		customSource,
		&EnvSource{Prefix: "CYPROB_"},
	}

	err := manager.LoadWithSources(sources)
	require.NoError(t, err)

	cfg := manager.Get()
	// ENV should override custom source if set, otherwise custom-level
	// Since we didn't set CYPROB_LOG_LEVEL, custom-level should remain
	assert.Equal(t, "custom-level", cfg.Log.Level)
}

func TestLoadWithSources_PriorityOrdering(t *testing.T) {
	resetGlobalConfig()
	t.Setenv("CYPROB_LOG_LEVEL", "from-env")

	manager := NewManager()
	sources := []ConfigSource{
		&EnvSource{Prefix: "CYPROB_"}, // priority 30
		&DefaultSource{},              // priority 10 - should be loaded first despite order
	}

	err := manager.LoadWithSources(sources)
	require.NoError(t, err)

	cfg := manager.Get()
	// ENV (priority 30) should override defaults (priority 10)
	assert.Equal(t, "from-env", cfg.Log.Level)
}

// mockConfigSource is a test helper for custom config sources
type mockConfigSource struct {
	name     string
	priority int
	loadFunc func(k *koanf.Koanf) error
}

func (m *mockConfigSource) Name() string  { return m.name }
func (m *mockConfigSource) Priority() int { return m.priority }
func (m *mockConfigSource) Load(k *koanf.Koanf) error {
	if m.loadFunc != nil {
		return m.loadFunc(k)
	}
	return nil
}
