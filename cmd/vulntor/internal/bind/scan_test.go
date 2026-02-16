package bind

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/scanexec"
)

func TestBindScanOptions(t *testing.T) {
	tests := []struct {
		name    string
		targets []string
		flags   map[string]any
		want    scanexec.Params
		wantErr bool
		errMsg  string
	}{
		{
			name:    "all flags set",
			targets: []string{"192.168.1.0/24"},
			flags: map[string]any{
				"ports":             "22,80,443",
				"profile":           "quick",
				"level":             "comprehensive",
				"tags":              []string{"discovery", "scan"},
				"exclude-tags":      []string{"slow"},
				"vuln":              true,
				"only-discover":     false,
				"no-discover":       false,
				"progress":          true,
				"fingerprint-cache": "/tmp/cache",
				"output":            "json",
				"timeout":           "5s",
				"concurrency":       100,
				"ping":              true,
				"ping-count":        2,
				"allow-loopback":    true,
			},
			want: scanexec.Params{
				Targets:       []string{"192.168.1.0/24"},
				Ports:         "22,80,443",
				Profile:       "quick",
				Level:         "comprehensive",
				IncludeTags:   []string{"discovery", "scan"},
				ExcludeTags:   []string{"slow"},
				EnableVuln:    true,
				OnlyDiscover:  false,
				SkipDiscover:  false,
				OutputFormat:  "json",
				CustomTimeout: "5s",
				Concurrency:   100,
				EnablePing:    true,
				PingCount:     2,
				AllowLoopback: true,
			},
			wantErr: false,
		},
		{
			name:    "minimal flags (defaults)",
			targets: []string{"10.0.0.1"},
			flags: map[string]any{
				"ports":             "",
				"profile":           "",
				"level":             "default",
				"tags":              []string{},
				"exclude-tags":      []string{},
				"vuln":              false,
				"only-discover":     false,
				"no-discover":       false,
				"progress":          false,
				"fingerprint-cache": "",
				"output":            "text",
				"timeout":           "1s",
				"concurrency":       50,
				"ping":              true,
				"ping-count":        1,
				"allow-loopback":    false,
			},
			want: scanexec.Params{
				Targets:       []string{"10.0.0.1"},
				Ports:         "",
				Profile:       "",
				Level:         "default",
				IncludeTags:   []string{},
				ExcludeTags:   []string{},
				EnableVuln:    false,
				OnlyDiscover:  false,
				SkipDiscover:  false,
				OutputFormat:  "text",
				CustomTimeout: "1s",
				Concurrency:   50,
				EnablePing:    true,
				PingCount:     1,
				AllowLoopback: false,
			},
			wantErr: false,
		},
		{
			name:    "only-discover disables vuln automatically",
			targets: []string{"192.168.1.1"},
			flags: map[string]any{
				"ports":             "22",
				"profile":           "",
				"level":             "default",
				"tags":              []string{},
				"exclude-tags":      []string{},
				"vuln":              true, // This will be disabled by only-discover
				"only-discover":     true,
				"no-discover":       false,
				"progress":          false,
				"fingerprint-cache": "",
				"output":            "text",
				"timeout":           "1s",
				"concurrency":       50,
				"ping":              true,
				"ping-count":        1,
				"allow-loopback":    false,
			},
			want: scanexec.Params{
				Targets:       []string{"192.168.1.1"},
				Ports:         "22",
				Profile:       "",
				Level:         "default",
				IncludeTags:   []string{},
				ExcludeTags:   []string{},
				EnableVuln:    false, // Disabled by only-discover
				OnlyDiscover:  true,
				SkipDiscover:  false,
				OutputFormat:  "text",
				CustomTimeout: "1s",
				Concurrency:   50,
				EnablePing:    true,
				PingCount:     1,
				AllowLoopback: false,
			},
			wantErr: false,
		},
		{
			name:    "conflicting flags: only-discover + no-discover",
			targets: []string{"10.0.0.1"},
			flags: map[string]any{
				"ports":             "",
				"profile":           "",
				"level":             "default",
				"tags":              []string{},
				"exclude-tags":      []string{},
				"vuln":              false,
				"only-discover":     true,
				"no-discover":       true, // Conflict!
				"progress":          false,
				"fingerprint-cache": "",
				"output":            "text",
				"timeout":           "1s",
				"concurrency":       50,
				"ping":              true,
				"ping-count":        1,
				"allow-loopback":    false,
			},
			want:    scanexec.Params{},
			wantErr: true,
			errMsg:  "cannot use --only-discover and --no-discover together",
		},
		{
			name:    "multiple targets",
			targets: []string{"10.0.0.1", "10.0.0.2", "192.168.1.0/24"},
			flags: map[string]any{
				"ports":             "80,443",
				"profile":           "",
				"level":             "default",
				"tags":              []string{},
				"exclude-tags":      []string{},
				"vuln":              false,
				"only-discover":     false,
				"no-discover":       false,
				"progress":          false,
				"fingerprint-cache": "",
				"output":            "json",
				"timeout":           "2s",
				"concurrency":       25,
				"ping":              false,
				"ping-count":        1,
				"allow-loopback":    false,
			},
			want: scanexec.Params{
				Targets:       []string{"10.0.0.1", "10.0.0.2", "192.168.1.0/24"},
				Ports:         "80,443",
				Profile:       "",
				Level:         "default",
				IncludeTags:   []string{},
				ExcludeTags:   []string{},
				EnableVuln:    false,
				OnlyDiscover:  false,
				SkipDiscover:  false,
				OutputFormat:  "json",
				CustomTimeout: "2s",
				Concurrency:   25,
				EnablePing:    false,
				PingCount:     1,
				AllowLoopback: false,
			},
			wantErr: false,
		},
		{
			name:    "skip-discover with vuln enabled",
			targets: []string{"192.168.1.100"},
			flags: map[string]any{
				"ports":             "1-1000",
				"profile":           "",
				"level":             "default",
				"tags":              []string{},
				"exclude-tags":      []string{},
				"vuln":              true,
				"only-discover":     false,
				"no-discover":       true, // Skip discovery, go straight to scanning
				"progress":          false,
				"fingerprint-cache": "",
				"output":            "yaml",
				"timeout":           "3s",
				"concurrency":       75,
				"ping":              true,
				"ping-count":        1,
				"allow-loopback":    false,
			},
			want: scanexec.Params{
				Targets:       []string{"192.168.1.100"},
				Ports:         "1-1000",
				Profile:       "",
				Level:         "default",
				IncludeTags:   []string{},
				ExcludeTags:   []string{},
				EnableVuln:    true,
				OnlyDiscover:  false,
				SkipDiscover:  true,
				OutputFormat:  "yaml",
				CustomTimeout: "3s",
				Concurrency:   75,
				EnablePing:    true,
				PingCount:     1,
				AllowLoopback: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := setupScanCommand(tt.flags)
			got, err := BindScanOptions(cmd, tt.targets)

			if tt.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, scanexec.ErrConflictingDiscoveryFlags)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want.Targets, got.Targets)
			require.Equal(t, tt.want.Ports, got.Ports)
			require.Equal(t, tt.want.Profile, got.Profile)
			require.Equal(t, tt.want.Level, got.Level)
			require.Equal(t, tt.want.IncludeTags, got.IncludeTags)
			require.Equal(t, tt.want.ExcludeTags, got.ExcludeTags)
			require.Equal(t, tt.want.EnableVuln, got.EnableVuln)
			require.Equal(t, tt.want.OnlyDiscover, got.OnlyDiscover)
			require.Equal(t, tt.want.SkipDiscover, got.SkipDiscover)
			require.Equal(t, tt.want.OutputFormat, got.OutputFormat)
			require.Equal(t, tt.want.CustomTimeout, got.CustomTimeout)
			require.Equal(t, tt.want.Concurrency, got.Concurrency)
			require.Equal(t, tt.want.EnablePing, got.EnablePing)
			require.Equal(t, tt.want.PingCount, got.PingCount)
			require.Equal(t, tt.want.AllowLoopback, got.AllowLoopback)

			// Verify RawInputs is populated
			require.NotNil(t, got.RawInputs)
		})
	}
}

// setupScanCommand creates a mock command with scan flags
func setupScanCommand(flags map[string]any) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("ports", "", "Ports")
	cmd.Flags().String("profile", "", "Profile")
	cmd.Flags().String("level", "default", "Level")
	cmd.Flags().StringSlice("tags", []string{}, "Tags")
	cmd.Flags().StringSlice("exclude-tags", []string{}, "Exclude tags")
	cmd.Flags().Bool("vuln", false, "Enable vuln")
	cmd.Flags().Bool("only-discover", false, "Only discover")
	cmd.Flags().Bool("no-discover", false, "Skip discover")
	cmd.Flags().Bool("progress", false, "Progress")
	cmd.Flags().String("fingerprint-cache", "", "Fingerprint cache")
	cmd.Flags().String("output", "text", "Output format")
	cmd.Flags().String("timeout", "1s", "Timeout")
	cmd.Flags().Int("concurrency", 50, "Concurrency")
	cmd.Flags().Bool("ping", true, "Enable ping")
	cmd.Flags().Int("ping-count", 1, "Ping count")
	cmd.Flags().Bool("allow-loopback", false, "Allow loopback")

	// Set flag values
	if ports, ok := flags["ports"].(string); ok {
		_ = cmd.Flags().Set("ports", ports)
	}
	if profile, ok := flags["profile"].(string); ok {
		_ = cmd.Flags().Set("profile", profile)
	}
	if level, ok := flags["level"].(string); ok {
		_ = cmd.Flags().Set("level", level)
	}
	if tags, ok := flags["tags"].([]string); ok {
		for _, tag := range tags {
			_ = cmd.Flags().Set("tags", tag)
		}
	}
	if excludeTags, ok := flags["exclude-tags"].([]string); ok {
		for _, tag := range excludeTags {
			_ = cmd.Flags().Set("exclude-tags", tag)
		}
	}
	if vuln, ok := flags["vuln"].(bool); ok && vuln {
		_ = cmd.Flags().Set("vuln", "true")
	}
	if onlyDiscover, ok := flags["only-discover"].(bool); ok && onlyDiscover {
		_ = cmd.Flags().Set("only-discover", "true")
	}
	if skipDiscover, ok := flags["no-discover"].(bool); ok && skipDiscover {
		_ = cmd.Flags().Set("no-discover", "true")
	}
	if progress, ok := flags["progress"].(bool); ok && progress {
		_ = cmd.Flags().Set("progress", "true")
	}
	if cache, ok := flags["fingerprint-cache"].(string); ok {
		_ = cmd.Flags().Set("fingerprint-cache", cache)
	}
	if output, ok := flags["output"].(string); ok {
		_ = cmd.Flags().Set("output", output)
	}
	if timeout, ok := flags["timeout"].(string); ok {
		_ = cmd.Flags().Set("timeout", timeout)
	}
	if concurrency, ok := flags["concurrency"].(int); ok {
		_ = cmd.Flags().Set("concurrency", fmt.Sprintf("%d", concurrency))
	}
	if ping, ok := flags["ping"].(bool); ok {
		if ping {
			_ = cmd.Flags().Set("ping", "true")
		} else {
			_ = cmd.Flags().Set("ping", "false")
		}
	}
	if pingCount, ok := flags["ping-count"].(int); ok {
		_ = cmd.Flags().Set("ping-count", fmt.Sprintf("%d", pingCount))
	}
	if allowLoopback, ok := flags["allow-loopback"].(bool); ok && allowLoopback {
		_ = cmd.Flags().Set("allow-loopback", "true")
	}

	return cmd
}
