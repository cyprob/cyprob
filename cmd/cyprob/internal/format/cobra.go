package format

import (
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// FromCommand builds a Formatter using cobra command output/error writers and common flags.
func FromCommand(cmd *cobra.Command) Formatter {
	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()

	outputMode := ModeTable
	if flag := cmd.Flags().Lookup("output"); flag != nil {
		outputMode = ParseMode(flag.Value.String())
	}

	quiet := false
	if flag := cmd.Flags().Lookup("quiet"); flag != nil {
		if val, err := strconv.ParseBool(flag.Value.String()); err == nil {
			quiet = val
		}
	}

	color := true
	if flag := cmd.Flags().Lookup("no-color"); flag != nil {
		if val, err := strconv.ParseBool(flag.Value.String()); err == nil && val {
			color = false
		}
	}

	// Cobra defaults to stderr being nil in some paths; ensure we have a fallback.
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	return New(stdout, stderr, outputMode, quiet, color)
}
