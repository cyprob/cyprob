package bind

import (
	"github.com/spf13/cobra"
)

// DAGValidateOptions holds configuration options for the dag validate command.
type DAGValidateOptions struct {
	Format     string
	Strict     bool
	JSONOutput bool
}

// DAGExportOptions holds configuration options for the dag export command.
type DAGExportOptions struct {
	Output     string
	Format     string
	Targets    string
	Ports      string
	Vuln       bool
	NoDiscover bool
}

// BindDAGValidateOptions extracts and validates dag validate command flags.
//
// This function reads the validate-specific flags from the Cobra command and
// constructs a properly validated DAGValidateOptions struct.
//
// Flags read:
//   - --format: File format hint (yaml|json), auto-detect if not specified
//   - --strict: Treat warnings as errors (exit code 2)
//   - --json: Output results as JSON
//
// Returns an error if validation fails.
func BindDAGValidateOptions(cmd *cobra.Command) (DAGValidateOptions, error) {
	format, _ := cmd.Flags().GetString("format")
	strict, _ := cmd.Flags().GetBool("strict")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	opts := DAGValidateOptions{
		Format:     format,
		Strict:     strict,
		JSONOutput: jsonOutput,
	}

	return opts, nil
}

// BindDAGExportOptions extracts and validates dag export command flags.
//
// This function reads the export-specific flags from the Cobra command and
// constructs a properly validated DAGExportOptions struct.
//
// Flags read:
//   - --output: Output file (default: stdout)
//   - --format: Output format (yaml|json)
//   - --targets: Target hosts for scan
//   - --ports: Ports to scan
//   - --vuln: Include vulnerability evaluation modules
//   - --no-discover: Skip discovery modules
//
// Returns an error if validation fails.
func BindDAGExportOptions(cmd *cobra.Command) (DAGExportOptions, error) {
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	targets, _ := cmd.Flags().GetString("targets")
	ports, _ := cmd.Flags().GetString("ports")
	vuln, _ := cmd.Flags().GetBool("vuln")
	noDiscover, _ := cmd.Flags().GetBool("no-discover")

	opts := DAGExportOptions{
		Output:     output,
		Format:     format,
		Targets:    targets,
		Ports:      ports,
		Vuln:       vuln,
		NoDiscover: noDiscover,
	}

	return opts, nil
}
