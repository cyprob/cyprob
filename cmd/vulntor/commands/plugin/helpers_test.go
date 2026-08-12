package plugin

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/plugin"
)

// captureExit replaces the process exit so a test can read the code instead of
// ending the test binary.
func captureExit(t *testing.T) *int {
	t.Helper()
	original := exitProcess
	t.Cleanup(func() { exitProcess = original })

	var got int
	captured := &got
	exitProcess = func(code int) { *captured = code }
	return captured
}

// ADR-0001 gives partial failure its own exit code, and cmd/main.go cannot
// derive it: the error the printer returns no longer carries the sentinel, so
// the code has to come from the exit below the printer. A printer result that
// merely reports the failure must therefore not be mistaken for a failure to
// print, which would return early and skip it.
func TestHandlePartialFailure_ExitsWithTheADRCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		printed error
	}{
		{"summary printed", format.Reported(errors.New("1 of 1 failed"))},
		{"quiet, deliberately not printed", format.Reported(errors.New("1 of 1 failed"))},
		{"printer reported nothing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := captureExit(t)

			err := handlePartialFailure(plugin.ErrPartialFailure, nil, func() error {
				return tc.printed
			})

			require.NoError(t, err)
			require.Equal(t, 8, *code, "partial failure must exit 8, not fall through to 1")
		})
	}
}

// A genuine failure to write to the terminal is a different thing and must
// surface, rather than being swallowed by an exit that claims to know why.
func TestHandlePartialFailure_AWriteFailureIsReturned(t *testing.T) {
	code := captureExit(t)
	writeErr := errors.New("write /dev/stdout: broken pipe")

	err := handlePartialFailure(plugin.ErrPartialFailure, nil, func() error {
		return writeErr
	})

	require.ErrorIs(t, err, writeErr)
	require.Zero(t, *code, "an unprintable result must not be reported as partial failure")
}

func TestHandlePartialFailure_IgnoresOtherErrors(t *testing.T) {
	code := captureExit(t)
	called := false

	err := handlePartialFailure(errors.New("something else"), nil, func() error {
		called = true
		return nil
	})

	require.NoError(t, err)
	require.False(t, called, "only a partial failure is handled here")
	require.Zero(t, *code)
}

func TestHandlePartialFailure_NilErrorIsANoOp(t *testing.T) {
	code := captureExit(t)
	require.NoError(t, handlePartialFailure(nil, nil, func() error {
		t.Fatal("printer must not run without a failure")
		return nil
	}))
	require.Zero(t, *code)
}

// The seam exists so the exit code can be asserted; this pins that the marker
// the guard depends on is the one the printers actually produce, in both the
// visible and the quiet path.
func TestPrinterOutputIsMarkedInBothPaths(t *testing.T) {
	cause := errors.New("1 of 1 failed")

	loud := format.New(&bytes.Buffer{}, &bytes.Buffer{}, format.ModeTable, false, false)
	require.True(t, format.IsAlreadyReported(
		loud.PrintTotalFailureSummary("install plugin", cause, "PLUGIN_NOT_FOUND")))

	quiet := format.New(&bytes.Buffer{}, &bytes.Buffer{}, format.ModeTable, true, false)
	require.True(t, format.IsAlreadyReported(
		quiet.PrintTotalFailureSummary("install plugin", cause, "PLUGIN_NOT_FOUND")),
		"quiet still counts as handled: the user asked for silence")
}
