package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigDir(t *testing.T) {
	t.Run("XDGOverride", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")
		got := ConfigDir()
		want := filepath.Join("/tmp/xdg-config", "cyprob")
		if got != want {
			t.Fatalf("ConfigDir() = %s, want %s", got, want)
		}
	})

	t.Run("PlatformDefault", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		switch runtime.GOOS {
		case "windows":
			t.Setenv("AppData", `C:\AppData`)
			want := filepath.Join(`C:\AppData`, "Cyprob")
			if got := ConfigDir(); got != want {
				t.Fatalf("ConfigDir() = %s, want %s", got, want)
			}
		default:
			t.Setenv("HOME", "/home/tester")
			want := filepath.Join("/home/tester", ".config", "cyprob")
			if got := ConfigDir(); got != want {
				t.Fatalf("ConfigDir() = %s, want %s", got, want)
			}
		}
	})
}

func TestDataDir(t *testing.T) {
	t.Run("XDGOverride", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "/tmp/xdg-data")
		got := DataDir()
		want := filepath.Join("/tmp/xdg-data", "cyprob")
		if got != want {
			t.Fatalf("DataDir() = %s, want %s", got, want)
		}
	})

	t.Run("PlatformDefault", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "")
		switch runtime.GOOS {
		case "windows":
			t.Setenv("AppData", `C:\AppData`)
			want := filepath.Join(`C:\AppData`, "Cyprob")
			if got := DataDir(); got != want {
				t.Fatalf("DataDir() = %s, want %s", got, want)
			}
		default:
			t.Setenv("HOME", "/home/tester")
			want := filepath.Join("/home/tester", ".local", "share", "cyprob")
			if got := DataDir(); got != want {
				t.Fatalf("DataDir() = %s, want %s", got, want)
			}
		}
	})
}

func TestCacheDir(t *testing.T) {
	t.Run("XDGOverride", func(t *testing.T) {
		t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-cache")
		got := CacheDir()
		want := filepath.Join("/tmp/xdg-cache", "cyprob")
		if got != want {
			t.Fatalf("CacheDir() = %s, want %s", got, want)
		}
	})

	t.Run("PlatformDefault", func(t *testing.T) {
		t.Setenv("XDG_CACHE_HOME", "")
		switch runtime.GOOS {
		case "windows":
			t.Setenv("LocalAppData", `C:\LocalAppData`)
			want := filepath.Join(`C:\LocalAppData`, "Cyprob", "Cache")
			if got := CacheDir(); got != want {
				t.Fatalf("CacheDir() = %s, want %s", got, want)
			}
		default:
			t.Setenv("HOME", "/home/tester")
			want := filepath.Join("/home/tester", ".cache", "cyprob")
			if got := CacheDir(); got != want {
				t.Fatalf("CacheDir() = %s, want %s", got, want)
			}
		}
	})
}
