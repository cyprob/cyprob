package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsetEnv removes key for the duration of the test and restores any value it
// had before. t.Setenv registers the restore; os.Unsetenv then clears the key,
// because an empty CYPROB_ value would still load and override the fallback.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	require.NoError(t, os.Unsetenv(key))
}

// A deployment that exports only the former prefix must keep its configuration
// after upgrade. The guarantee is exercised through Manager.Load, which builds
// its sources with DefaultSources, so it fails if that wiring stops passing the
// legacy prefix, not only if EnvSource itself regresses.
func TestManagerLoad_FormerPrefixOnly(t *testing.T) {
	resetGlobalConfig()
	unsetEnv(t, "CYPROB_LOG_LEVEL")
	unsetEnv(t, "CYPROB_LOG_FORMAT")
	t.Setenv("VULNTOR_LOG_LEVEL", "warn")
	t.Setenv("VULNTOR_LOG_FORMAT", "json")

	manager := NewManager()
	require.NoError(t, manager.Load(nil, ""))

	cfg := manager.Get()
	assert.Equal(t, "warn", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
}

// With both prefixes set on the same path, the new prefix wins.
func TestManagerLoad_NewPrefixWinsOverFormer(t *testing.T) {
	resetGlobalConfig()
	t.Setenv("CYPROB_LOG_LEVEL", "error")
	t.Setenv("VULNTOR_LOG_LEVEL", "debug")

	manager := NewManager()
	require.NoError(t, manager.Load(nil, ""))

	assert.Equal(t, "error", manager.Get().Log.Level)
}
