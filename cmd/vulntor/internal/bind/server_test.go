package bind

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	srv "github.com/cyprob/cyprob/pkg/server"
)

func TestBindServerOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    ServerOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "all flags set",
			flags: map[string]any{
				"addr":             "0.0.0.0",
				"port":             8080,
				"no-ui":            false,
				"no-api":           false,
				"jobs-concurrency": 10,
				"ui-assets-path":   "/custom/ui",
			},
			want: ServerOptions{
				Addr:         "0.0.0.0",
				Port:         8080,
				NoUI:         false,
				NoAPI:        false,
				Concurrency:  10,
				UIAssetsPath: "/custom/ui",
			},
			wantErr: false,
		},
		{
			name: "defaults",
			flags: map[string]any{
				"addr":             "127.0.0.1",
				"port":             8080,
				"no-ui":            false,
				"no-api":           false,
				"jobs-concurrency": 4,
				"ui-assets-path":   "",
			},
			want: ServerOptions{
				Addr:         "127.0.0.1",
				Port:         8080,
				NoUI:         false,
				NoAPI:        false,
				Concurrency:  4,
				UIAssetsPath: "",
			},
			wantErr: false,
		},
		{
			name: "no-ui enabled",
			flags: map[string]any{
				"addr":             "127.0.0.1",
				"port":             9000,
				"no-ui":            true,
				"no-api":           false,
				"jobs-concurrency": 8,
				"ui-assets-path":   "",
			},
			want: ServerOptions{
				Addr:         "127.0.0.1",
				Port:         9000,
				NoUI:         true,
				NoAPI:        false,
				Concurrency:  8,
				UIAssetsPath: "",
			},
			wantErr: false,
		},
		{
			name: "invalid port - too low",
			flags: map[string]any{
				"addr":             "127.0.0.1",
				"port":             0,
				"no-ui":            false,
				"no-api":           false,
				"jobs-concurrency": 4,
				"ui-assets-path":   "",
			},
			want:    ServerOptions{},
			wantErr: true,
			errMsg:  "invalid port 0: must be between 1 and 65535",
		},
		{
			name: "invalid port - too high",
			flags: map[string]any{
				"addr":             "127.0.0.1",
				"port":             70000,
				"no-ui":            false,
				"no-api":           false,
				"jobs-concurrency": 4,
				"ui-assets-path":   "",
			},
			want:    ServerOptions{},
			wantErr: true,
			errMsg:  "invalid port 70000: must be between 1 and 65535",
		},
		{
			name: "invalid concurrency",
			flags: map[string]any{
				"addr":             "127.0.0.1",
				"port":             8080,
				"no-ui":            false,
				"no-api":           false,
				"jobs-concurrency": 0,
				"ui-assets-path":   "",
			},
			want:    ServerOptions{},
			wantErr: true,
			errMsg:  "invalid concurrency 0: must be at least 1",
		},
		{
			name: "both UI and API disabled",
			flags: map[string]any{
				"addr":             "127.0.0.1",
				"port":             8080,
				"no-ui":            true,
				"no-api":           true,
				"jobs-concurrency": 4,
				"ui-assets-path":   "",
			},
			want:    ServerOptions{},
			wantErr: true,
			errMsg:  "cannot disable both UI and API",
		},
		{
			name: "high concurrency",
			flags: map[string]any{
				"addr":             "0.0.0.0",
				"port":             443,
				"no-ui":            false,
				"no-api":           false,
				"jobs-concurrency": 100,
				"ui-assets-path":   "",
			},
			want: ServerOptions{
				Addr:         "0.0.0.0",
				Port:         443,
				NoUI:         false,
				NoAPI:        false,
				Concurrency:  100,
				UIAssetsPath: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupServerCommand(tt.flags)
			got, err := BindServerOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}

				switch tt.name {
				case "invalid port - too low", "invalid port - too high":
					require.ErrorIs(t, err, srv.ErrInvalidPort)
				case "invalid concurrency":
					require.ErrorIs(t, err, srv.ErrInvalidConcurrency)
				case "both UI and API disabled":
					require.ErrorIs(t, err, srv.ErrFeaturesDisabled)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// setupServerCommand creates a mock command with server flags
func setupServerCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("addr", "127.0.0.1", "Address")
	cmd.Flags().Int("port", 8080, "Port")
	cmd.Flags().Bool("no-ui", false, "No UI")
	cmd.Flags().Bool("no-api", false, "No API")
	cmd.Flags().Int("jobs-concurrency", 4, "Concurrency")
	cmd.Flags().String("ui-assets-path", "", "UI assets path")

	// Set flag values
	if addr, ok := flags["addr"].(string); ok {
		_ = cmd.Flags().Set("addr", addr)
	}
	if port, ok := flags["port"].(int); ok {
		_ = cmd.Flags().Set("port", fmt.Sprintf("%d", port))
	}
	if noUI, ok := flags["no-ui"].(bool); ok && noUI {
		_ = cmd.Flags().Set("no-ui", "true")
	}
	if noAPI, ok := flags["no-api"].(bool); ok && noAPI {
		_ = cmd.Flags().Set("no-api", "true")
	}
	if concurrency, ok := flags["jobs-concurrency"].(int); ok {
		_ = cmd.Flags().Set("jobs-concurrency", fmt.Sprintf("%d", concurrency))
	}
	if uiPath, ok := flags["ui-assets-path"].(string); ok {
		_ = cmd.Flags().Set("ui-assets-path", uiPath)
	}

	return cmd
}
