// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package format

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/plugin"
)

func TestNew(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, false, false)
	require.NotNil(t, f)
}

func TestPrintJSON(t *testing.T) {
	tests := []struct {
		name     string
		data     any
		expected string
	}{
		{
			name: "simple object",
			data: map[string]string{
				"name":    "test-plugin",
				"version": "1.0.0",
			},
			expected: `{
  "name": "test-plugin",
  "version": "1.0.0"
}
`,
		},
		{
			name: "array",
			data: []string{"plugin1", "plugin2"},
			expected: `[
  "plugin1",
  "plugin2"
]
`,
		},
		{
			name:     "nil",
			data:     nil,
			expected: "null\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			f := New(&stdout, &stderr, ModeJSON, false, false)

			err := f.PrintJSON(tt.data)
			require.NoError(t, err)
			require.Equal(t, tt.expected, stdout.String())
			require.Empty(t, stderr.String())
		})
	}
}

func TestPrintTable(t *testing.T) {
	tests := []struct {
		name    string
		mode    OutputMode
		headers []string
		rows    [][]string
		wantErr bool
	}{
		{
			name:    "table mode",
			mode:    ModeTable,
			headers: []string{"Name", "Version"},
			rows: [][]string{
				{"plugin1", "1.0.0"},
				{"plugin2", "2.0.0"},
			},
			wantErr: false,
		},
		{
			name:    "json mode",
			mode:    ModeJSON,
			headers: []string{"Name", "Version"},
			rows: [][]string{
				{"plugin1", "1.0.0"},
				{"plugin2", "2.0.0"},
			},
			wantErr: false,
		},
		{
			name:    "empty table",
			mode:    ModeTable,
			headers: []string{"Name", "Version"},
			rows:    [][]string{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			f := New(&stdout, &stderr, tt.mode, false, false)

			err := f.PrintTable(tt.headers, tt.rows)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, stdout.String())

			// JSON mode should output valid JSON
			if tt.mode == ModeJSON {
				var items []map[string]string
				err := json.Unmarshal(stdout.Bytes(), &items)
				require.NoError(t, err)
				require.Len(t, items, len(tt.rows))
			} else {
				// Table mode should contain headers
				output := stdout.String()
				for _, header := range tt.headers {
					require.Contains(t, output, header)
				}
			}
		})
	}
}

func TestPrintSummary(t *testing.T) {
	tests := []struct {
		name           string
		mode           OutputMode
		quiet          bool
		message        string
		expectStdout   bool
		expectStderr   bool
		checkStderrMsg bool
	}{
		{
			name:         "table mode - normal",
			mode:         ModeTable,
			quiet:        false,
			message:      "Operation successful",
			expectStdout: true,
			expectStderr: false,
		},
		{
			name:         "table mode - quiet",
			mode:         ModeTable,
			quiet:        true,
			message:      "Operation successful",
			expectStdout: false,
			expectStderr: false,
		},
		{
			name:           "json mode - normal",
			mode:           ModeJSON,
			quiet:          false,
			message:        "Operation successful",
			expectStdout:   false,
			expectStderr:   true,
			checkStderrMsg: true,
		},
		{
			name:         "json mode - quiet",
			mode:         ModeJSON,
			quiet:        true,
			message:      "Operation successful",
			expectStdout: false,
			expectStderr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			f := New(&stdout, &stderr, tt.mode, tt.quiet, false)

			err := f.PrintSummary(tt.message)
			require.NoError(t, err)

			if tt.expectStdout {
				require.Contains(t, stdout.String(), tt.message)
			} else {
				require.Empty(t, stdout.String())
			}

			if tt.expectStderr {
				if tt.checkStderrMsg {
					require.Contains(t, stderr.String(), tt.message)
				} else {
					require.NotEmpty(t, stderr.String())
				}
			} else if !tt.checkStderrMsg {
				require.Empty(t, stderr.String())
			}
		})
	}
}

func TestPrintError(t *testing.T) {
	tests := []struct {
		name         string
		mode         OutputMode
		err          error
		expectStdout bool
		expectStderr bool
		checkJSON    bool
	}{
		{
			name:         "table mode - error",
			mode:         ModeTable,
			err:          errors.New("operation failed"),
			expectStdout: false,
			expectStderr: true,
		},
		{
			name:         "table mode - nil error",
			mode:         ModeTable,
			err:          nil,
			expectStdout: false,
			expectStderr: false,
		},
		{
			name:         "json mode - error",
			mode:         ModeJSON,
			err:          errors.New("operation failed"),
			expectStdout: true,
			expectStderr: false,
			checkJSON:    true,
		},
		{
			name:         "json mode - nil error",
			mode:         ModeJSON,
			err:          nil,
			expectStdout: false,
			expectStderr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			f := New(&stdout, &stderr, tt.mode, false, false)

			err := f.PrintError(tt.err)
			require.NoError(t, err)

			if tt.expectStdout {
				require.NotEmpty(t, stdout.String())
				if tt.checkJSON {
					var result map[string]any
					err := json.Unmarshal(stdout.Bytes(), &result)
					require.NoError(t, err)
					require.False(t, result["success"].(bool))
					require.Contains(t, result["error"], tt.err.Error())
					// New fields: code and suggestion should be present for JSON errors
					_, hasCode := result["code"]
					require.True(t, hasCode, "expected 'code' in JSON error output")
					_, hasSuggestion := result["suggestion"]
					require.True(t, hasSuggestion, "expected 'suggestion' in JSON error output")
				}
			} else {
				require.Empty(t, stdout.String())
			}

			if tt.expectStderr {
				require.Contains(t, stderr.String(), "Error:")
				require.Contains(t, stderr.String(), tt.err.Error())
			} else {
				require.Empty(t, stderr.String())
			}
		})
	}
}

func TestPrintError_JSON_IncludesCodeAndSuggestion_ForVariousErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "not found", err: plugin.ErrPluginNotFound},
		{name: "invalid input", err: plugin.ErrInvalidInput},
		{name: "service unavailable", err: plugin.ErrUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			f := New(&stdout, &stderr, ModeJSON, false, false)

			require.NoError(t, f.PrintError(tc.err))

			var result map[string]any
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, false, result["success"].(bool))
			require.Contains(t, result["error"], tc.err.Error())

			// Exact code should match plugin.ErrorCode
			require.Equal(t, plugin.ErrorCode(tc.err), result["code"].(string))

			// Suggestion should be present (non-empty string)
			sugg, _ := result["suggestion"].(string)
			require.NotEmpty(t, sugg)
		})
	}
}

func TestValidateMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{
			name:    "valid json",
			mode:    "json",
			wantErr: false,
		},
		{
			name:    "valid table",
			mode:    "table",
			wantErr: false,
		},
		{
			name:    "invalid mode",
			mode:    "xml",
			wantErr: true,
		},
		{
			name:    "empty mode",
			mode:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMode(tt.mode)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid output mode")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected OutputMode
	}{
		{
			name:     "json lowercase",
			input:    "json",
			expected: ModeJSON,
		},
		{
			name:     "json uppercase",
			input:    "JSON",
			expected: ModeJSON,
		},
		{
			name:     "table lowercase",
			input:    "table",
			expected: ModeTable,
		},
		{
			name:     "table uppercase",
			input:    "TABLE",
			expected: ModeTable,
		},
		{
			name:     "invalid defaults to table",
			input:    "invalid",
			expected: ModeTable,
		},
		{
			name:     "empty defaults to table",
			input:    "",
			expected: ModeTable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMode(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSuggestionsNewCodes(t *testing.T) {
	t.Run("invalid target", func(t *testing.T) {
		suggestions := GetSuggestions("INVALID_TARGET", "scan")
		require.NotEmpty(t, suggestions)
		require.Contains(t, suggestions[0], "vulntor scan")
	})

	t.Run("no retention policy", func(t *testing.T) {
		suggestions := GetSuggestions("NO_RETENTION_POLICY", "garbage collection")
		require.NotEmpty(t, suggestions)
		require.Contains(t, suggestions[0], "vulntor storage gc")
	})
}

func TestPrintTableColorSupport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, false, true) // color enabled

	headers := []string{"Name", "Version"}
	rows := [][]string{{"plugin1", "1.0.0"}}

	err := f.PrintTable(headers, rows)
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String())
}

func TestPrintSummaryColorSupport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, false, true) // color enabled

	err := f.PrintSummary("Success message")
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String())
	// Color codes are added, but we don't check exact codes (platform-dependent)
}

func TestPrintErrorColorSupport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, false, true) // color enabled

	err := f.PrintError(errors.New("test error"))
	require.NoError(t, err)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "Error:")
	require.Contains(t, stderr.String(), "test error")
}

func TestJSONModeStdoutStderrSeparation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeJSON, false, false)

	// PrintJSON should go to stdout
	err := f.PrintJSON(map[string]string{"key": "value"})
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String())
	require.Empty(t, stderr.String())

	stdout.Reset()
	stderr.Reset()

	// PrintSummary in JSON mode should go to stderr
	err = f.PrintSummary("Summary message")
	require.NoError(t, err)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "Summary message")

	stdout.Reset()
	stderr.Reset()

	// PrintError in JSON mode should go to stdout (as JSON)
	err = f.PrintError(errors.New("error message"))
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String())
	require.Empty(t, stderr.String())

	var result map[string]any
	err = json.Unmarshal(stdout.Bytes(), &result)
	require.NoError(t, err)
	require.False(t, result["success"].(bool))
}

func TestTableModeStdoutStderrSeparation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, false, false)

	// PrintTable should go to stdout
	err := f.PrintTable([]string{"Header"}, [][]string{{"Value"}})
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String())
	require.Empty(t, stderr.String())

	stdout.Reset()
	stderr.Reset()

	// PrintSummary in table mode should go to stdout
	err = f.PrintSummary("Summary message")
	require.NoError(t, err)
	require.Contains(t, stdout.String(), "Summary message")
	require.Empty(t, stderr.String())

	stdout.Reset()
	stderr.Reset()

	// PrintError in table mode should go to stderr
	err = f.PrintError(errors.New("error message"))
	require.NoError(t, err)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "Error:")
	require.Contains(t, stderr.String(), "error message")
}

func TestQuietModeSuppression(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, true, false) // quiet mode

	// PrintSummary should be suppressed in quiet mode
	err := f.PrintSummary("This should not appear")
	require.NoError(t, err)
	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())

	// PrintError should still work in quiet mode
	err = f.PrintError(errors.New("error"))
	require.NoError(t, err)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "Error:")
}

func TestPrintTable_MismatchedRowLength(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeTable, false, false)

	headers := []string{"Name", "Version", "Author"}
	rows := [][]string{
		{"plugin1", "1.0.0", "author1"},
		{"plugin2", "2.0.0"}, // Missing author field
		{"plugin3"},          // Missing version and author
	}

	err := f.PrintTable(headers, rows)
	require.NoError(t, err)
	require.NotEmpty(t, stdout.String())
}

func TestPrintTable_JSONModeWithMismatchedRows(t *testing.T) {
	var stdout, stderr bytes.Buffer
	f := New(&stdout, &stderr, ModeJSON, false, false)

	headers := []string{"Name", "Version"}
	rows := [][]string{
		{"plugin1", "1.0.0"},
		{"plugin2"}, // Missing version
	}

	err := f.PrintTable(headers, rows)
	require.NoError(t, err)

	var items []map[string]string
	err = json.Unmarshal(stdout.Bytes(), &items)
	require.NoError(t, err)
	require.Len(t, items, 2)

	// First item should have both fields
	require.Equal(t, "plugin1", items[0]["Name"])
	require.Equal(t, "1.0.0", items[0]["Version"])

	// Second item should have only Name
	require.Equal(t, "plugin2", items[1]["Name"])
	_, hasVersion := items[1]["Version"]
	require.False(t, hasVersion)
}

func TestOutputModeString(t *testing.T) {
	require.Equal(t, "json", string(ModeJSON))
	require.Equal(t, "table", string(ModeTable))
}

func TestIsJSON(t *testing.T) {
	tests := []struct {
		name     string
		mode     OutputMode
		expected bool
	}{
		{
			name:     "JSON mode",
			mode:     ModeJSON,
			expected: true,
		},
		{
			name:     "Table mode",
			mode:     ModeTable,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			f := New(&stdout, &stderr, tt.mode, false, false)
			require.Equal(t, tt.expected, f.IsJSON())
		})
	}
}
