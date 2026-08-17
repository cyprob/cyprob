// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/cyprob/internal/format"
)

// NewCommand creates the plugin command with all subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Plugin management",
		Long: `Manage YAML-based vulnerability detection plugins.

Plugins extend Cyprob's vulnerability detection capabilities with custom rules.
Use these commands to list, inspect, verify, and maintain your plugin cache.`,
		Example: `  # List all installed plugins
  cyprob plugin list

  # Install plugins by category
  cyprob plugin install ssh

  # Install specific plugin
  cyprob plugin install ssh-cve-2024-6387

  # Uninstall plugin
  cyprob plugin uninstall ssh-cve-2024-6387

  # Show details for a specific plugin
  cyprob plugin info ssh-cve-2024-6387

  # Verify plugin checksums
  cyprob plugin verify

  # Clean unused cache entries
  cyprob plugin clean`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate global --output once for all subcommands
			output, _ := cmd.Flags().GetString("output")
			return format.ValidateMode(output)
		},
	}

	// Global flags inherited by subcommands
	cmd.PersistentFlags().String("output", "table", "Output format: json, table")
	cmd.PersistentFlags().Bool("quiet", false, "Suppress non-essential output")
	cmd.PersistentFlags().Bool("no-color", false, "Disable colored output")

	// Add subcommands
	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newEmbeddedCommand())
	cmd.AddCommand(newInstallCommand())
	cmd.AddCommand(newUninstallCommand())
	cmd.AddCommand(newUpdateCommand())
	cmd.AddCommand(newInfoCommand())
	cmd.AddCommand(newVerifyCommand())
	cmd.AddCommand(newCleanCommand())

	return cmd
}
