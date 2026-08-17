package format

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestFromCommandRespectsFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("output", "table", "")
	cmd.Flags().Bool("quiet", false, "")
	cmd.Flags().Bool("no-color", false, "")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	require.NoError(t, cmd.Flags().Set("output", "json"))
	require.NoError(t, cmd.Flags().Set("quiet", "true"))
	require.NoError(t, cmd.Flags().Set("no-color", "true"))

	formatter := FromCommand(cmd)
	require.True(t, formatter.IsJSON())

	require.NoError(t, formatter.PrintSummary("should be suppressed"))
	require.Equal(t, "", out.String())
}
