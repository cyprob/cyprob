package bind

import "github.com/spf13/cobra"

// StorageGCOptions contains validated options for the storage gc command
type StorageGCOptions struct {
	DryRun     bool
	OrgID      string
	MaxScans   int
	MaxAgeDays int
}

// BindStorageGCOptions extracts and validates storage gc flags from the command
func BindStorageGCOptions(cmd *cobra.Command) (StorageGCOptions, error) {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	orgID, _ := cmd.Flags().GetString("org-id")
	maxScans, _ := cmd.Flags().GetInt("max-scans")
	maxAgeDays, _ := cmd.Flags().GetInt("max-age-days")

	return StorageGCOptions{
		DryRun:     dryRun,
		OrgID:      orgID,
		MaxScans:   maxScans,
		MaxAgeDays: maxAgeDays,
	}, nil
}
