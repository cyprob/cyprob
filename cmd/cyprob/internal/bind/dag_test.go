package bind

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestBindDAGValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    DAGValidateOptions
		wantErr bool
	}{
		{
			name: "all flags set",
			flags: map[string]any{
				"format": "yaml",
				"strict": true,
				"json":   true,
			},
			want: DAGValidateOptions{
				Format:     "yaml",
				Strict:     true,
				JSONOutput: true,
			},
			wantErr: false,
		},
		{
			name: "defaults",
			flags: map[string]any{
				"format": "",
				"strict": false,
				"json":   false,
			},
			want: DAGValidateOptions{
				Format:     "",
				Strict:     false,
				JSONOutput: false,
			},
			wantErr: false,
		},
		{
			name: "strict mode only",
			flags: map[string]any{
				"format": "",
				"strict": true,
				"json":   false,
			},
			want: DAGValidateOptions{
				Format:     "",
				Strict:     true,
				JSONOutput: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupDAGValidateCommand(tt.flags)
			got, err := BindDAGValidateOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBindDAGExportOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    DAGExportOptions
		wantErr bool
	}{
		{
			name: "all flags set",
			flags: map[string]any{
				"output":      "/tmp/dag.yaml",
				"format":      "yaml",
				"targets":     "192.168.1.0/24",
				"ports":       "22,80,443",
				"vuln":        true,
				"no-discover": true,
			},
			want: DAGExportOptions{
				Output:     "/tmp/dag.yaml",
				Format:     "yaml",
				Targets:    "192.168.1.0/24",
				Ports:      "22,80,443",
				Vuln:       true,
				NoDiscover: true,
			},
			wantErr: false,
		},
		{
			name: "defaults",
			flags: map[string]any{
				"output":      "",
				"format":      "yaml",
				"targets":     "192.168.1.1",
				"ports":       "22,80,443",
				"vuln":        false,
				"no-discover": false,
			},
			want: DAGExportOptions{
				Output:     "",
				Format:     "yaml",
				Targets:    "192.168.1.1",
				Ports:      "22,80,443",
				Vuln:       false,
				NoDiscover: false,
			},
			wantErr: false,
		},
		{
			name: "json format with vuln",
			flags: map[string]any{
				"output":      "/output/dag.json",
				"format":      "json",
				"targets":     "10.0.0.1",
				"ports":       "1-1000",
				"vuln":        true,
				"no-discover": false,
			},
			want: DAGExportOptions{
				Output:     "/output/dag.json",
				Format:     "json",
				Targets:    "10.0.0.1",
				Ports:      "1-1000",
				Vuln:       true,
				NoDiscover: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupDAGExportCommand(tt.flags)
			got, err := BindDAGExportOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// setupDAGValidateCommand creates a mock command with dag validate flags
func setupDAGValidateCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("format", "", "Format")
	cmd.Flags().Bool("strict", false, "Strict")
	cmd.Flags().Bool("json", false, "JSON output")

	// Set flag values
	if format, ok := flags["format"].(string); ok {
		_ = cmd.Flags().Set("format", format)
	}
	if strict, ok := flags["strict"].(bool); ok && strict {
		_ = cmd.Flags().Set("strict", "true")
	}
	if jsonOut, ok := flags["json"].(bool); ok && jsonOut {
		_ = cmd.Flags().Set("json", "true")
	}

	return cmd
}

// setupDAGExportCommand creates a mock command with dag export flags
func setupDAGExportCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("output", "", "Output")
	cmd.Flags().String("format", "yaml", "Format")
	cmd.Flags().String("targets", "192.168.1.1", "Targets")
	cmd.Flags().String("ports", "22,80,443", "Ports")
	cmd.Flags().Bool("vuln", false, "Vuln")
	cmd.Flags().Bool("no-discover", false, "No discover")

	// Set flag values
	if output, ok := flags["output"].(string); ok {
		_ = cmd.Flags().Set("output", output)
	}
	if format, ok := flags["format"].(string); ok {
		_ = cmd.Flags().Set("format", format)
	}
	if targets, ok := flags["targets"].(string); ok {
		_ = cmd.Flags().Set("targets", targets)
	}
	if ports, ok := flags["ports"].(string); ok {
		_ = cmd.Flags().Set("ports", ports)
	}
	if vuln, ok := flags["vuln"].(bool); ok && vuln {
		_ = cmd.Flags().Set("vuln", "true")
	}
	if noDiscover, ok := flags["no-discover"].(bool); ok && noDiscover {
		_ = cmd.Flags().Set("no-discover", "true")
	}

	return cmd
}
