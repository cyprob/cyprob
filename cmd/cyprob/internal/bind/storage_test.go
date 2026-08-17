package bind

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestBindStorageGCOptions(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*cobra.Command)
		expected StorageGCOptions
	}{
		{
			name: "all flags set",
			setup: func(cmd *cobra.Command) {
				cmd.Flags().Bool("dry-run", false, "")
				cmd.Flags().String("org-id", "", "")
				cmd.Flags().Int("max-scans", 0, "")
				cmd.Flags().Int("max-age-days", 0, "")

				_ = cmd.Flags().Set("dry-run", "true")
				_ = cmd.Flags().Set("org-id", "test-org")
				_ = cmd.Flags().Set("max-scans", "100")
				_ = cmd.Flags().Set("max-age-days", "30")
			},
			expected: StorageGCOptions{
				DryRun:     true,
				OrgID:      "test-org",
				MaxScans:   100,
				MaxAgeDays: 30,
			},
		},
		{
			name: "dry-run only",
			setup: func(cmd *cobra.Command) {
				cmd.Flags().Bool("dry-run", false, "")
				cmd.Flags().String("org-id", "", "")
				cmd.Flags().Int("max-scans", 0, "")
				cmd.Flags().Int("max-age-days", 0, "")

				_ = cmd.Flags().Set("dry-run", "true")
			},
			expected: StorageGCOptions{
				DryRun:     true,
				OrgID:      "",
				MaxScans:   0,
				MaxAgeDays: 0,
			},
		},
		{
			name: "max-scans only",
			setup: func(cmd *cobra.Command) {
				cmd.Flags().Bool("dry-run", false, "")
				cmd.Flags().String("org-id", "", "")
				cmd.Flags().Int("max-scans", 0, "")
				cmd.Flags().Int("max-age-days", 0, "")

				_ = cmd.Flags().Set("max-scans", "50")
			},
			expected: StorageGCOptions{
				DryRun:     false,
				OrgID:      "",
				MaxScans:   50,
				MaxAgeDays: 0,
			},
		},
		{
			name: "max-age-days only",
			setup: func(cmd *cobra.Command) {
				cmd.Flags().Bool("dry-run", false, "")
				cmd.Flags().String("org-id", "", "")
				cmd.Flags().Int("max-scans", 0, "")
				cmd.Flags().Int("max-age-days", 0, "")

				_ = cmd.Flags().Set("max-age-days", "7")
			},
			expected: StorageGCOptions{
				DryRun:     false,
				OrgID:      "",
				MaxScans:   0,
				MaxAgeDays: 7,
			},
		},
		{
			name: "defaults (no flags set)",
			setup: func(cmd *cobra.Command) {
				cmd.Flags().Bool("dry-run", false, "")
				cmd.Flags().String("org-id", "", "")
				cmd.Flags().Int("max-scans", 0, "")
				cmd.Flags().Int("max-age-days", 0, "")
			},
			expected: StorageGCOptions{
				DryRun:     false,
				OrgID:      "",
				MaxScans:   0,
				MaxAgeDays: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			tt.setup(cmd)

			opts, err := BindStorageGCOptions(cmd)
			require.NoError(t, err)
			require.Equal(t, tt.expected, opts)
		})
	}
}
