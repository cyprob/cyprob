package storage

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/storage"
)

func newGCCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Run garbage collection on stored scans",
		Long: `Run garbage collection to clean up old scans based on retention policies.

Retention policies define how long scans are kept before being deleted:
  - max_scans: Maximum number of scans to retain (oldest deleted first)
  - max_age_days: Maximum age of scans in days (older scans deleted)

Both policies can be active simultaneously. Scans are deleted if they violate
EITHER condition (OR logic).

The command reads retention policies from:
  1. Command flags (--max-scans, --max-age-days) - highest priority
  2. Config file (storage.retention.max_scans, storage.retention.max_age_days)
  3. Environment variables (VULNTOR_RETENTION_MAX_SCANS, VULNTOR_RETENTION_MAX_AGE_DAYS)

Use --dry-run to preview which scans would be deleted without actually deleting them.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := format.FromCommand(cmd)
			ctx := cmd.Context()

			// Bind flags to options using centralized binder
			opts, err := bind.BindStorageGCOptions(cmd)
			if err != nil {
				return formatter.PrintTotalFailureSummary("garbage collection", err, storage.ErrorCode(err))
			}

			// Create storage backend
			storageConfig, err := storage.DefaultConfig()
			if err != nil {
				return formatter.PrintTotalFailureSummary("garbage collection", err, storage.ErrorCode(err))
			}

			// Apply retention policy overrides from flags
			if opts.MaxScans > 0 || opts.MaxAgeDays > 0 {
				// User provided flags - override config
				storageConfig.Retention = storage.RetentionConfig{
					MaxScans:   opts.MaxScans,
					MaxAgeDays: opts.MaxAgeDays,
				}
			}

			// Validate config
			if err := storageConfig.Validate(); err != nil {
				wrapped := storage.FormatRetentionValidationError(err)
				return formatter.PrintTotalFailureSummary("garbage collection", wrapped, storage.ErrorCode(wrapped))
			}

			backend, err := storage.NewBackend(ctx, storageConfig)
			if err != nil {
				return formatter.PrintTotalFailureSummary("garbage collection", err, storage.ErrorCode(err))
			}
			defer func() {
				if err := backend.Close(); err != nil {
					log.Warn().Err(err).Msg("Failed to close storage backend")
				}
			}()

			// Check if retention policy is enabled
			if !storageConfig.Retention.IsEnabled() {
				err := storage.ErrRetentionPolicyNotConfigured
				return formatter.PrintTotalFailureSummary("garbage collection", err, storage.ErrorCode(err))
			}

			// Log retention policy
			log.Info().
				Int("max_scans", storageConfig.Retention.MaxScans).
				Int("max_age_days", storageConfig.Retention.MaxAgeDays).
				Bool("dry_run", opts.DryRun).
				Str("org_id", opts.OrgID).
				Msg("Starting garbage collection")

			if opts.DryRun {
				fmt.Println("DRY RUN MODE - No scans will be deleted")
				fmt.Println()
			}

			// Print retention policy
			fmt.Printf("Retention Policy:\n")
			if storageConfig.Retention.MaxScans > 0 {
				fmt.Printf("  - Keep maximum %d scans (oldest deleted first)\n", storageConfig.Retention.MaxScans)
			}
			if storageConfig.Retention.MaxAgeDays > 0 {
				fmt.Printf("  - Keep scans from last %d days (older scans deleted)\n", storageConfig.Retention.MaxAgeDays)
			}
			fmt.Println()

			// Run GC
			result, err := backend.GarbageCollect(ctx, storage.GCOptions{
				DryRun: opts.DryRun,
				OrgID:  opts.OrgID,
			})
			if err != nil {
				return formatter.PrintTotalFailureSummary("garbage collection", err, storage.ErrorCode(err))
			}

			// Print results
			if result.ScansDeleted == 0 {
				fmt.Println("No scans to clean up")
			} else {
				if opts.DryRun {
					fmt.Printf("Would delete %d scan(s):\n", result.ScansDeleted)
				} else {
					fmt.Printf("Deleted %d scan(s):\n", result.ScansDeleted)
				}
				for _, scanID := range result.DeletedScanIDs {
					fmt.Printf("  - %s\n", scanID)
				}
			}

			// Print errors if any
			if len(result.Errors) > 0 {
				fmt.Printf("\nEncountered %d error(s):\n", len(result.Errors))
				for i, err := range result.Errors {
					fmt.Printf("  %d. %v\n", i+1, err)
				}
			}

			if opts.DryRun && result.ScansDeleted > 0 {
				fmt.Println()
				fmt.Println("To actually delete these scans, run without --dry-run:")
				fmt.Println("  vulntor storage gc")
			}

			return nil
		},
	}

	// Flags
	cmd.Flags().Bool("dry-run", false, "Preview scans to be deleted without actually deleting them")
	cmd.Flags().String("org-id", "", "Organization ID to clean up (default: all orgs)")
	cmd.Flags().Int("max-scans", 0, "Maximum number of scans to retain (0 = no limit)")
	cmd.Flags().Int("max-age-days", 0, "Maximum age of scans in days (0 = no limit)")
	cmd.Flags().String("output", "table", "Output format: json, table")
	cmd.Flags().Bool("quiet", false, "Suppress non-essential output")
	cmd.Flags().Bool("no-color", false, "Disable colored output")

	return cmd
}
