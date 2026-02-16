// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package dag

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/engine"
)

func newValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a DAG definition file",
		Long: `Validate a DAG definition file (YAML or JSON format).

Checks for:
- Missing or duplicate node IDs
- Missing dependencies
- Circular dependencies (cycles)
- Data flow issues (consumes/produces contracts)
- Invalid configuration
- Self-dependencies

The command returns different exit codes based on validation results:
- 0: DAG is valid
- 1: Validation errors found
- 2: Warnings found (only with --strict flag)`,
		Example: `  # Validate a YAML DAG file
  vulntor dag validate scan-dag.yaml

  # Strict validation (treat warnings as errors)
  vulntor dag validate dag.yaml --strict

  # Output results as JSON (for CI/CD)
  vulntor dag validate dag.yaml --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := format.FromCommand(cmd)
			// Bind flags to options using centralized binder
			opts, err := bind.BindDAGValidateOptions(cmd)
			if err != nil {
				return formatter.PrintTotalFailureSummary("validate DAG", err, engine.ErrorCode(err))
			}

			file := args[0]
			if err := runValidate(file, opts); err != nil {
				return formatter.PrintTotalFailureSummary("validate DAG", err, engine.ErrorCode(err))
			}
			return nil
		},
	}

	cmd.Flags().String("format", "", "File format hint (yaml|json), auto-detect if not specified")
	cmd.Flags().Bool("strict", false, "Treat warnings as errors (exit code 2)")
	cmd.Flags().Bool("json", false, "Output results as JSON")

	return cmd
}

func runValidate(file string, opts bind.DAGValidateOptions) error {
	// Load DAG from file (skip validation during load, we'll validate explicitly)
	dag, err := engine.LoadDAGFromFile(file, true)
	if err != nil {
		return engine.WrapLoadError(err)
	}

	// Run validation
	result := dag.Validate()

	// Output results
	var exitCode int
	if opts.JSONOutput {
		exitCode = outputJSON(result)
	} else {
		exitCode = outputPretty(dag, result, opts.Strict)
	}

	// Exit with appropriate code (only in real CLI, not in tests)
	// Tests should check for errors in output, not exit codes
	if exitCode != 0 && os.Getenv("VULNTOR_TEST_MODE") == "" {
		os.Exit(exitCode)
	}

	return nil
}

func outputJSON(result *engine.ValidationResult) int {
	// Create JSON output structure
	output := map[string]any{
		"valid":    result.IsValid(),
		"errors":   result.Errors,
		"warnings": result.Warnings,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to marshal JSON: %v\n", err)
		return 1
	}

	fmt.Println(string(data))

	// Return exit code based on validation result
	if !result.IsValid() {
		return 1
	}

	return 0
}

func outputPretty(dag *engine.DAGSchema, result *engine.ValidationResult, strict bool) int {
	// Color setup
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	// Print header
	fmt.Printf("%s: %s\n", bold("DAG Name"), cyan(dag.Name))
	if dag.Version != "" {
		fmt.Printf("%s: %s\n", bold("Version"), dag.Version)
	}
	if dag.Description != "" {
		fmt.Printf("%s: %s\n", bold("Description"), dag.Description)
	}
	fmt.Printf("%s: %d\n\n", bold("Nodes"), len(dag.Nodes))

	// Check if valid
	hasErrors := len(result.Errors) > 0
	hasWarnings := len(result.Warnings) > 0

	if !hasErrors && !hasWarnings {
		fmt.Printf("%s DAG is valid!\n\n", green("✓"))

		// Print execution order
		printExecutionOrder(dag, bold)

		return 0
	}

	// Print errors
	if hasErrors {
		fmt.Printf("%s %s:\n", red("✗"), bold(fmt.Sprintf("%d Error(s)", len(result.Errors))))
		for i, err := range result.Errors {
			msg := err.Message
			if err.NodeID != "" {
				msg = fmt.Sprintf("[%s] %s", err.NodeID, err.Message)
			}
			if err.Fix != "" {
				msg = fmt.Sprintf("%s\n     → Fix: %s", msg, err.Fix)
			}
			fmt.Printf("  %d. %s\n", i+1, msg)
		}
		fmt.Println()
	}

	// Print warnings
	if hasWarnings {
		fmt.Printf("%s %s:\n", yellow("⚠"), bold(fmt.Sprintf("%d Warning(s)", len(result.Warnings))))
		for i, warn := range result.Warnings {
			msg := warn.Message
			if warn.NodeID != "" {
				msg = fmt.Sprintf("[%s] %s", warn.NodeID, warn.Message)
			}
			fmt.Printf("  %d. %s\n", i+1, msg)
		}
		fmt.Println()
	}

	// Print execution order if no errors (warnings are ok)
	if !hasErrors {
		printExecutionOrder(dag, bold)
	}

	// Return exit code
	if hasErrors {
		return 1
	}
	if strict && hasWarnings {
		return 2
	}

	return 0
}

func printExecutionOrder(dag *engine.DAGSchema, bold func(...any) string) {
	order, err := dag.GetExecutionOrder()
	if err != nil {
		// Don't fail on execution order error, it's informational
		return
	}

	if len(order) == 0 {
		return
	}

	fmt.Printf("%s:\n", bold("Execution Order"))
	for i, layer := range order {
		fmt.Printf("  Layer %d: %v\n", i+1, layer)
	}
	fmt.Println()
}
