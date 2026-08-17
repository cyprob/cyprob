package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintSyncCommand_SourceRequiredSuggestions(t *testing.T) {
	cmd := NewFingerprintCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	cmd.SetArgs([]string{"sync"})

	err := cmd.Execute()
	// The command reports a failure, so it must also RETURN one: this is what
	// gives the process a non-zero exit code.
	require.Error(t, err)

	output := out.String()
	require.Contains(t, output, "✗ Failed to sync fingerprint catalog")
	require.Contains(t, output, "--file <path> or --url <address>")
	require.Contains(t, output, "cyprob fingerprint sync --url")
}
