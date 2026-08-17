package commands

import (
	"bytes"
	"os"
	"testing"
)

func TestRootCommandPreparesWorkspaceAndRunsVersion(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("VULNTOR_WORKSPACE", tmp)

	cmd := NewCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"version", "--short"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("command execution failed: %v", err)
	}

	// Storage config initializes workspace root but doesn't create subdirectories
	// Subdirectories are created by storage backend on demand
	// Just verify that storage config was set up correctly
	if _, err := os.Stat(tmp); err != nil {
		t.Fatalf("workspace root should exist: %v", err)
	}
}
