package format

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var errSentinel = errors.New("sentinel")

func TestReported_MarksWithoutHidingTheCause(t *testing.T) {
	wrapped := Reported(errSentinel)

	require.True(t, IsAlreadyReported(wrapped))
	require.EqualError(t, wrapped, "sentinel")
	require.ErrorIs(t, wrapped, errSentinel,
		"a caller matching on its own sentinel must still find it through the marker")
}

func TestReported_NilStaysNil(t *testing.T) {
	require.NoError(t, Reported(nil), "marking must not invent a failure")
	require.False(t, IsAlreadyReported(nil))
	require.False(t, IsAlreadyReported(errSentinel), "an unprinted error is not reported")
}

// The printer shows the failure, so what it returns must say so: main prints
// only what nobody has shown yet, and the plugin commands rely on this to tell
// a reported failure apart from a problem writing to the terminal.
func TestPrintTotalFailureSummary_ReturnsTheFailureMarkedAsReported(t *testing.T) {
	out := &bytes.Buffer{}
	f := &formatter{stdout: out, mode: ModeTable}

	err := f.PrintTotalFailureSummary("install plugin", errSentinel, "PLUGIN_NOT_FOUND")

	require.Error(t, err, "a reported failure must still fail")
	require.ErrorIs(t, err, errSentinel)
	require.True(t, IsAlreadyReported(err))
	require.Contains(t, out.String(), "Failed to install plugin")
}

// Quiet suppresses the summary, not the failure — and the error is still
// marked. The user asked for silence, so nobody downstream should print it
// either, and the exit code is what carries the failure.
//
// The first version of this test asserted the opposite, and pinned the
// precondition for a real defect: an unmarked error made the plugin commands
// skip their ADR-0001 exit code under --quiet and leaked a line to stderr that
// --quiet had asked not to see.
func TestPrintTotalFailureSummary_QuietStaysSilentAndStillFails(t *testing.T) {
	out := &bytes.Buffer{}
	f := &formatter{stdout: out, mode: ModeTable, quiet: true}

	err := f.PrintTotalFailureSummary("install plugin", errSentinel, "PLUGIN_NOT_FOUND")

	require.ErrorIs(t, err, errSentinel, "quiet suppresses the summary, not the failure")
	require.True(t, IsAlreadyReported(err), "the user asked for silence, so nobody prints it")
	require.Empty(t, out.String())
}

func TestPrintTotalFailureSummary_JSONReportsAndFails(t *testing.T) {
	out := &bytes.Buffer{}
	f := &formatter{stdout: out, mode: ModeJSON}

	err := f.PrintTotalFailureSummary("install plugin", errSentinel, "PLUGIN_NOT_FOUND")

	require.ErrorIs(t, err, errSentinel)
	require.True(t, IsAlreadyReported(err))
	require.Contains(t, out.String(), `"success"`)
}
