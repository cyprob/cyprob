package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the config directory for Cyprob.
// Order: XDG_CONFIG_HOME/cyprob, platform-specific fallback.
func ConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "cyprob")
	}
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("AppData"); appData != "" {
			return filepath.Join(appData, "Cyprob")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cyprob")
}

// DataDir returns the data directory for Cyprob.
// Order: XDG_DATA_HOME/cyprob, platform-specific fallback.
func DataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "cyprob")
	}
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("AppData"); appData != "" {
			return filepath.Join(appData, "Cyprob")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "cyprob")
}

// CacheDir returns the cache directory for Cyprob.
// Order: XDG_CACHE_HOME/cyprob, platform-specific fallback.
func CacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "cyprob")
	}
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LocalAppData"); localAppData != "" {
			return filepath.Join(localAppData, "Cyprob", "Cache")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "cyprob")
}
