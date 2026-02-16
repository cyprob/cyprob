package bind

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/plugin"
)

func TestBindInstallOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    plugin.InstallOptions
		wantErr bool
	}{
		{
			name: "all flags set",
			flags: map[string]any{
				"source": "official",
				"force":  true,
			},
			want: plugin.InstallOptions{
				Source: "official",
				Force:  true,
			},
			wantErr: false,
		},
		{
			name: "only source set",
			flags: map[string]any{
				"source": "github",
				"force":  false,
			},
			want: plugin.InstallOptions{
				Source: "github",
				Force:  false,
			},
			wantErr: false,
		},
		{
			name: "invalid source",
			flags: map[string]any{
				"source": "custom",
				"force":  false,
			},
			want:    plugin.InstallOptions{},
			wantErr: true,
		},
		{
			name: "only force set",
			flags: map[string]any{
				"source": "",
				"force":  true,
			},
			want: plugin.InstallOptions{
				Source: "",
				Force:  true,
			},
			wantErr: false,
		},
		{
			name: "no flags set (defaults)",
			flags: map[string]any{
				"source": "",
				"force":  false,
			},
			want: plugin.InstallOptions{
				Source: "",
				Force:  false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupInstallCommand(tt.flags)
			got, err := BindInstallOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBindUpdateOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    plugin.UpdateOptions
		wantErr bool
	}{
		{
			name: "all flags set",
			flags: map[string]any{
				"category": "ssh",
				"source":   "official",
				"force":    true,
				"dry-run":  true,
			},
			want: plugin.UpdateOptions{
				Category: plugin.CategorySSH,
				Source:   "official",
				Force:    true,
				DryRun:   true,
			},
			wantErr: false,
		},
		{
			name: "only category set",
			flags: map[string]any{
				"category": "http",
				"source":   "",
				"force":    false,
				"dry-run":  false,
			},
			want: plugin.UpdateOptions{
				Category: plugin.CategoryHTTP,
				Source:   "",
				Force:    false,
				DryRun:   false,
			},
			wantErr: false,
		},
		{
			name: "no flags set (defaults)",
			flags: map[string]any{
				"category": "",
				"source":   "",
				"force":    false,
				"dry-run":  false,
			},
			want: plugin.UpdateOptions{
				Category: "",
				Source:   "",
				Force:    false,
				DryRun:   false,
			},
			wantErr: false,
		},
		{
			name: "dry-run only",
			flags: map[string]any{
				"category": "",
				"source":   "",
				"force":    false,
				"dry-run":  true,
			},
			want: plugin.UpdateOptions{
				Category: "",
				Source:   "",
				Force:    false,
				DryRun:   true,
			},
			wantErr: false,
		},
		{
			name: "invalid category",
			flags: map[string]any{
				"category": "invalid",
				"source":   "",
				"force":    false,
				"dry-run":  false,
			},
			want:    plugin.UpdateOptions{},
			wantErr: true,
		},
		{
			name: "invalid source",
			flags: map[string]any{
				"category": "",
				"source":   "custom",
				"force":    false,
				"dry-run":  false,
			},
			want:    plugin.UpdateOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupUpdateCommand(tt.flags)
			got, err := BindUpdateOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBindUninstallOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    plugin.UninstallOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "all flag set",
			flags: map[string]any{
				"all":      true,
				"category": "",
			},
			want: plugin.UninstallOptions{
				All:      true,
				Category: "",
			},
			wantErr: false,
		},
		{
			name: "category flag set",
			flags: map[string]any{
				"all":      false,
				"category": "ssh",
			},
			want: plugin.UninstallOptions{
				All:      false,
				Category: plugin.CategorySSH,
			},
			wantErr: false,
		},
		{
			name: "no flags set (defaults)",
			flags: map[string]any{
				"all":      false,
				"category": "",
			},
			want: plugin.UninstallOptions{
				All:      false,
				Category: "",
			},
			wantErr: false,
		},
		{
			name: "conflicting flags: all + category",
			flags: map[string]any{
				"all":      true,
				"category": "http",
			},
			want:    plugin.UninstallOptions{},
			wantErr: true,
			errMsg:  "cannot use --all and --category together",
		},
		{
			name: "invalid category",
			flags: map[string]any{
				"all":      false,
				"category": "invalid",
			},
			want:    plugin.UninstallOptions{},
			wantErr: true,
			errMsg:  "invalid category",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupUninstallCommand(tt.flags)
			got, err := BindUninstallOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// setupInstallCommand creates a mock command with install flags
func setupInstallCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("source", "", "Plugin source")
	cmd.Flags().Bool("force", false, "Force install")

	// Set flag values
	if source, ok := flags["source"].(string); ok {
		_ = cmd.Flags().Set("source", source)
	}
	if force, ok := flags["force"].(bool); ok {
		if force {
			_ = cmd.Flags().Set("force", "true")
		}
	}

	return cmd
}

// setupUpdateCommand creates a mock command with update flags
func setupUpdateCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("category", "", "Plugin category")
	cmd.Flags().String("source", "", "Plugin source")
	cmd.Flags().Bool("force", false, "Force download")
	cmd.Flags().Bool("dry-run", false, "Dry run")

	// Set flag values
	if category, ok := flags["category"].(string); ok {
		_ = cmd.Flags().Set("category", category)
	}
	if source, ok := flags["source"].(string); ok {
		_ = cmd.Flags().Set("source", source)
	}
	if force, ok := flags["force"].(bool); ok {
		if force {
			_ = cmd.Flags().Set("force", "true")
		}
	}
	if dryRun, ok := flags["dry-run"].(bool); ok {
		if dryRun {
			_ = cmd.Flags().Set("dry-run", "true")
		}
	}

	return cmd
}

// setupUninstallCommand creates a mock command with uninstall flags
func setupUninstallCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("all", false, "Uninstall all")
	cmd.Flags().String("category", "", "Plugin category")

	// Set flag values
	if all, ok := flags["all"].(bool); ok {
		if all {
			_ = cmd.Flags().Set("all", "true")
		}
	}
	if category, ok := flags["category"].(string); ok {
		_ = cmd.Flags().Set("category", category)
	}

	return cmd
}

func TestBindCleanOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    plugin.CleanOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "all flags set",
			flags: map[string]any{
				"older-than": "720h",
				"dry-run":    true,
			},
			want: plugin.CleanOptions{
				OlderThan: 720 * 60 * 60 * 1000000000, // 720 hours in nanoseconds
				DryRun:    true,
			},
			wantErr: false,
		},
		{
			name: "only older-than set (default dry-run)",
			flags: map[string]any{
				"older-than": "168h",
				"dry-run":    false,
			},
			want: plugin.CleanOptions{
				OlderThan: 168 * 60 * 60 * 1000000000, // 168 hours in nanoseconds
				DryRun:    false,
			},
			wantErr: false,
		},
		{
			name: "default older-than with dry-run",
			flags: map[string]any{
				"older-than": "720h",
				"dry-run":    true,
			},
			want: plugin.CleanOptions{
				OlderThan: 720 * 60 * 60 * 1000000000,
				DryRun:    true,
			},
			wantErr: false,
		},
		{
			name: "invalid duration format",
			flags: map[string]any{
				"older-than": "invalid",
				"dry-run":    false,
			},
			want:    plugin.CleanOptions{},
			wantErr: true,
			errMsg:  "invalid duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupCleanCommand(tt.flags)
			got, err := BindCleanOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBindVerifyOptions(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]any
		want    plugin.VerifyOptions
		wantErr bool
	}{
		{
			name: "plugin flag set",
			flags: map[string]any{
				"plugin": "ssh-cve-2024-6387",
			},
			want: plugin.VerifyOptions{
				PluginID: "ssh-cve-2024-6387",
			},
			wantErr: false,
		},
		{
			name: "no plugin flag (verify all)",
			flags: map[string]any{
				"plugin": "",
			},
			want: plugin.VerifyOptions{
				PluginID: "",
			},
			wantErr: false,
		},
		{
			name: "plugin with version",
			flags: map[string]any{
				"plugin": "http-weak-ssl@1.0.0",
			},
			want: plugin.VerifyOptions{
				PluginID: "http-weak-ssl@1.0.0",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupVerifyCommand(tt.flags)
			got, err := BindVerifyOptions(cmd)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// setupCleanCommand creates a mock command with clean flags
func setupCleanCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("older-than", "720h", "Duration")
	cmd.Flags().Bool("dry-run", false, "Dry run")

	// Set flag values
	if olderThan, ok := flags["older-than"].(string); ok {
		_ = cmd.Flags().Set("older-than", olderThan)
	}
	if dryRun, ok := flags["dry-run"].(bool); ok {
		if dryRun {
			_ = cmd.Flags().Set("dry-run", "true")
		}
	}

	return cmd
}

// setupVerifyCommand creates a mock command with verify flags
func setupVerifyCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("plugin", "", "Plugin name")

	// Set flag values
	if plugin, ok := flags["plugin"].(string); ok {
		_ = cmd.Flags().Set("plugin", plugin)
	}

	return cmd
}
