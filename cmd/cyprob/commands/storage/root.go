// Package storage provides CLI commands for managing Cyprob storage.
package storage

import (
	"github.com/spf13/cobra"
)

// NewStorageCommand creates and returns the 'cyprob storage' command.
//
// This command provides subcommands for storage management operations:
//   - gc: Garbage collection to clean up old scans
//
// Example usage:
//
//	cyprob storage gc
//	cyprob storage gc --dry-run
//	cyprob storage gc --max-scans=100
func NewStorageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Manage Cyprob storage",
		Long: `Manage Cyprob storage operations including garbage collection.

The storage command provides utilities for managing scan data persistence,
retention policies, and cleanup operations.`,
	}

	// Add subcommands
	cmd.AddCommand(newGCCommand())

	return cmd
}
