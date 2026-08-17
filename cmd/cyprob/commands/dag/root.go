// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package dag

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the dag command with all subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dag",
		Short: "DAG definition management",
		Long: `Manage, validate, and export DAG (Directed Acyclic Graph) definitions.

DAG definitions describe the execution flow of scan modules, their dependencies,
and data contracts. Use these commands to validate custom DAG files or export
the internal DAG structure for inspection.`,
		Example: `  # Validate a DAG definition file
  cyprob dag validate scan-dag.yaml

  # Export the internal scan DAG to YAML
  cyprob dag export --targets 192.168.1.0/24 --output scan.yaml

  # Strict validation (treat warnings as errors)
  cyprob dag validate dag.yaml --strict`,
	}

	// Add subcommands
	cmd.AddCommand(newValidateCommand())
	cmd.AddCommand(newExportCommand())

	return cmd
}
