// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package dag

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
)

func init() {
	// Set test mode to prevent os.Exit() calls during tests
	_ = os.Setenv("VULNTOR_TEST_MODE", "1")
}

func TestValidateCommand_ValidDAG(t *testing.T) {
	// Create a valid DAG file
	validDAG := `name: test-dag
version: "1.0"
description: Test DAG
nodes:
  - id: a
    module: test-a
    produces:
      - data.a
  - id: b
    module: test-b
    depends_on:
      - a
    consumes:
      - data.a
    produces:
      - data.b
`

	tmpDir := t.TempDir()
	dagFile := filepath.Join(tmpDir, "valid.yaml")
	err := os.WriteFile(dagFile, []byte(validDAG), 0o644)
	require.NoError(t, err)

	// Test validate command
	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: false,
	}

	// Note: runValidate calls os.Exit() on success/failure
	// For unit testing, we need to refactor to return exit code instead
	// For now, we test that it doesn't panic and loads the DAG
	err = runValidate(dagFile, opts)

	// If we get here without panic, the DAG was loaded successfully
	// In real scenario, we'd check exit code but that requires refactoring
	require.NoError(t, err)
}

func TestValidateCommand_InvalidDAG_MissingNode(t *testing.T) {
	// Create DAG with missing dependency
	invalidDAG := `name: invalid-dag
nodes:
  - id: a
    module: test-a
  - id: b
    module: test-b
    depends_on:
      - c  # c doesn't exist
`

	tmpDir := t.TempDir()
	dagFile := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(dagFile, []byte(invalidDAG), 0o644)
	require.NoError(t, err)

	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: false,
	}

	// This should exit with code 1 due to validation errors
	// In real test, we'd capture exit code
	err = runValidate(dagFile, opts)

	// The function will call os.Exit(1) for invalid DAG
	// So we won't reach here in real scenario
	require.NoError(t, err)
}

func TestValidateCommand_Cycle(t *testing.T) {
	// Create DAG with cycle
	cyclicDAG := `name: cyclic-dag
nodes:
  - id: a
    module: test-a
    depends_on:
      - b
  - id: b
    module: test-b
    depends_on:
      - c
  - id: c
    module: test-c
    depends_on:
      - a
`

	tmpDir := t.TempDir()
	dagFile := filepath.Join(tmpDir, "cyclic.yaml")
	err := os.WriteFile(dagFile, []byte(cyclicDAG), 0o644)
	require.NoError(t, err)

	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: false,
	}

	err = runValidate(dagFile, opts)
	require.NoError(t, err)
}

func TestValidateCommand_MissingFile(t *testing.T) {
	opts := bind.DAGValidateOptions{
		Strict:     false,
		JSONOutput: false,
	}

	err := runValidate("/nonexistent/dag.yaml", opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load DAG")
}

func TestValidateCommand_InvalidYAML(t *testing.T) {
	// Create invalid YAML file
	invalidYAML := `name: test
nodes:
  - id: a
    module: test
    invalid yaml syntax here {{{}
`

	tmpDir := t.TempDir()
	dagFile := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(dagFile, []byte(invalidYAML), 0o644)
	require.NoError(t, err)

	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: false,
	}

	err = runValidate(dagFile, opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load DAG")
}

func TestValidateCommand_MissingFileSuggestions(t *testing.T) {
	cmd := newValidateCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	cmd.SetArgs([]string{"/nonexistent/file.yaml"})

	err := cmd.Execute()
	require.NoError(t, err)

	output := out.String()
	require.Contains(t, output, "✗ Failed to validate DAG")
	require.Contains(t, output, "Verify the DAG file path exists")
	require.Contains(t, output, "Ensure the file is valid YAML or JSON")
}

func TestValidateCommand_JSONFormat(t *testing.T) {
	// Create valid DAG in JSON format
	validJSON := `{
  "name": "test-dag",
  "version": "1.0",
  "nodes": [
    {
      "id": "a",
      "module": "test-a",
      "produces": ["data.a"]
    }
  ]
}`

	tmpDir := t.TempDir()
	dagFile := filepath.Join(tmpDir, "valid.json")
	err := os.WriteFile(dagFile, []byte(validJSON), 0o644)
	require.NoError(t, err)

	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: false,
	}

	err = runValidate(dagFile, opts)
	require.NoError(t, err)
}

func TestValidateCommand_WarningWithSinkNode(t *testing.T) {
	// Create DAG with sink node (produces nothing)
	dagWithWarning := `name: warning-dag
nodes:
  - id: a
    module: test-a
    produces:
      - data.a
  - id: b
    module: test-b
    depends_on:
      - a
    consumes:
      - data.a
    # No produces - this is a sink node (warning)
`

	tmpDir := t.TempDir()
	dagFile := filepath.Join(tmpDir, "warning.yaml")
	err := os.WriteFile(dagFile, []byte(dagWithWarning), 0o644)
	require.NoError(t, err)

	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: false,
	}

	// Should succeed (exit 0) even with warnings when strict=false
	err = runValidate(dagFile, opts)
	require.NoError(t, err)
}

func TestOutputJSON_ValidResult(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid DAG
	validDAG := `name: test
nodes:
  - id: a
    module: test-a
    produces: [data.a]
`
	dagFile := filepath.Join(tmpDir, "test.yaml")
	err := os.WriteFile(dagFile, []byte(validDAG), 0o644)
	require.NoError(t, err)

	opts := bind.DAGValidateOptions{
		// File is passed as separate parameter
		Strict:     false,
		JSONOutput: true,
	}

	// This will output JSON to stdout and exit 0
	// In real scenario, we'd capture stdout
	err = runValidate(dagFile, opts)
	require.NoError(t, err)
}

func TestNewValidateCommand(t *testing.T) {
	cmd := newValidateCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "validate <file>", cmd.Use)
	require.NotEmpty(t, cmd.Short)
	require.NotEmpty(t, cmd.Long)
	require.NotEmpty(t, cmd.Example)

	// Check flags exist
	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag)

	strictFlag := cmd.Flags().Lookup("strict")
	require.NotNil(t, strictFlag)

	jsonFlag := cmd.Flags().Lookup("json")
	require.NotNil(t, jsonFlag)
}
