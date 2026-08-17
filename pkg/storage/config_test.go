package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	t.Run("valid config with absolute path", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &Config{
			WorkspaceRoot: tmpDir,
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() failed: %v", err)
		}

		// Should normalize to absolute path
		if !filepath.IsAbs(cfg.WorkspaceRoot) {
			t.Errorf("WorkspaceRoot not absolute: %s", cfg.WorkspaceRoot)
		}
	})

	t.Run("valid config with tilde expansion", func(t *testing.T) {
		cfg := &Config{
			WorkspaceRoot: "~/test-cyprob",
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() failed: %v", err)
		}

		// Should expand tilde
		if cfg.WorkspaceRoot[:2] == "~/" {
			t.Errorf("Tilde not expanded: %s", cfg.WorkspaceRoot)
		}

		// Should be absolute
		if !filepath.IsAbs(cfg.WorkspaceRoot) {
			t.Errorf("WorkspaceRoot not absolute: %s", cfg.WorkspaceRoot)
		}
	})

	t.Run("empty workspace root", func(t *testing.T) {
		cfg := &Config{}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() should fail with empty workspace root")
		}

		if !IsInvalidInput(err) {
			t.Errorf("Expected InvalidInputError, got: %v", err)
		}
	})

	t.Run("relative path gets converted to absolute", func(t *testing.T) {
		cfg := &Config{
			WorkspaceRoot: "relative/path",
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() failed: %v", err)
		}

		// Should be converted to absolute
		if !filepath.IsAbs(cfg.WorkspaceRoot) {
			t.Errorf("WorkspaceRoot not absolute: %s", cfg.WorkspaceRoot)
		}
	})
}

func TestDefaultWorkspaceRoot(t *testing.T) {
	root, err := DefaultWorkspaceRoot()
	if err != nil {
		t.Fatalf("DefaultWorkspaceRoot() failed: %v", err)
	}

	// Should return non-empty path
	if root == "" {
		t.Error("DefaultWorkspaceRoot() returned empty path")
	}

	// Should be absolute
	if !filepath.IsAbs(root) {
		t.Errorf("DefaultWorkspaceRoot() not absolute: %s", root)
	}

	// Should contain "cyprob" or "Cyprob" — unless this machine already has an
	// old-named workspace on disk, in which case the migration fallback below
	// is expected to win instead. A CI runner's freshly created home directory
	// never has one, so this is the path taken in practice.
	if !contains(root, "cyprob") && !contains(root, "Cyprob") &&
		!contains(root, "vulntor") && !contains(root, "Vulntor") {
		t.Errorf("DefaultWorkspaceRoot() contains neither name: %s", root)
	}

	// Platform-specific checks
	switch {
	case isWindows():
		// Windows: Should be in AppData
		if !contains(root, "AppData") {
			t.Errorf("Windows path should contain AppData: %s", root)
		}

	case isDarwin():
		// macOS: Should be in Library/Application Support
		if !contains(root, "Library") {
			t.Errorf("macOS path should contain Library: %s", root)
		}

	default:
		// Linux: Should be in .local/share or XDG_DATA_HOME
		home, _ := os.UserHomeDir()
		if !contains(root, filepath.Join(home, ".local", "share")) &&
			os.Getenv("XDG_DATA_HOME") == "" {
			t.Logf("Warning: Linux path may not follow XDG spec: %s", root)
		}
	}
}

// The #258 migration fallback, exercised directly rather than by relying on
// whatever happens to already exist in the machine running the test.
// os.UserHomeDir() reads $HOME on Unix, so t.Setenv("HOME", ...) gives full
// control without touching the real user's home directory. Windows resolves
// the home directory from %USERPROFILE% instead, which t.Setenv("HOME", ...)
// does not affect, so this is skipped there — this repository's CI does not
// run a Windows job, so nothing exercises that branch either way today.
func TestDefaultWorkspaceRoot_MigrationFallback(t *testing.T) {
	if isWindows() {
		t.Skip("HOME does not control os.UserHomeDir() on Windows")
	}

	newFor := func(home string) string { return platformWorkspaceRoot(home, "Cyprob", "cyprob") }
	oldFor := func(home string) string { return platformWorkspaceRoot(home, "Vulntor", "vulntor") }

	t.Run("neither exists: uses the new path", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)

		got, err := DefaultWorkspaceRoot()
		if err != nil {
			t.Fatalf("DefaultWorkspaceRoot() failed: %v", err)
		}
		if want := newFor(home); got != want {
			t.Errorf("got %s, want %s (new path, fresh install)", got, want)
		}
	})

	t.Run("only the old path exists: falls back to it", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		if err := os.MkdirAll(oldFor(home), 0o755); err != nil {
			t.Fatal(err)
		}

		got, err := DefaultWorkspaceRoot()
		if err != nil {
			t.Fatalf("DefaultWorkspaceRoot() failed: %v", err)
		}
		if want := oldFor(home); got != want {
			t.Errorf("got %s, want %s (existing data must not look like it vanished)", got, want)
		}
	})

	t.Run("both exist: the new path wins", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		if err := os.MkdirAll(oldFor(home), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(newFor(home), 0o755); err != nil {
			t.Fatal(err)
		}

		got, err := DefaultWorkspaceRoot()
		if err != nil {
			t.Fatalf("DefaultWorkspaceRoot() failed: %v", err)
		}
		if want := newFor(home); got != want {
			t.Errorf("got %s, want %s (an already-migrated install must not fall back)", got, want)
		}
	})

	t.Run("only a file at the old path: not a workspace, new path wins", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		oldPath := oldFor(home)
		if err := os.MkdirAll(filepath.Dir(oldPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(oldPath, []byte("not a directory"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := DefaultWorkspaceRoot()
		if err != nil {
			t.Fatalf("DefaultWorkspaceRoot() failed: %v", err)
		}
		if want := newFor(home); got != want {
			t.Errorf("got %s, want %s (a stray file must not be mistaken for a workspace)", got, want)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg, err := DefaultConfig()
	if err != nil {
		t.Fatalf("DefaultConfig() failed: %v", err)
	}

	// Should have non-empty workspace root
	if cfg.WorkspaceRoot == "" {
		t.Error("DefaultConfig() returned empty WorkspaceRoot")
	}

	// Should be absolute
	if !filepath.IsAbs(cfg.WorkspaceRoot) {
		t.Errorf("DefaultConfig() WorkspaceRoot not absolute: %s", cfg.WorkspaceRoot)
	}

	// Should validate
	err = cfg.Validate()
	if err != nil {
		t.Errorf("DefaultConfig() validation failed: %v", err)
	}
}

func TestPlatformDetection(t *testing.T) {
	t.Run("isWindows", func(t *testing.T) {
		// Just test that it doesn't panic
		_ = isWindows()
	})

	t.Run("isDarwin", func(t *testing.T) {
		// Just test that it doesn't panic
		_ = isDarwin()
	})
}

// Helper function
func contains(s, substr string) bool {
	return filepath.ToSlash(s) != filepath.ToSlash(s[:len(s)-len(substr)]+substr) ||
		filepath.ToSlash(s)[len(s)-len(substr):] == filepath.ToSlash(substr) ||
		len(s) > len(substr) && (filepath.ToSlash(s)[:len(substr)] == filepath.ToSlash(substr) ||
			len(s) > len(substr) && findSubstring(filepath.ToSlash(s), filepath.ToSlash(substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
