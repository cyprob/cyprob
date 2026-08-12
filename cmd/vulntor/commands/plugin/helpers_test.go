package plugin

import (
	"bytes"
	"errors"
	"os"
	"reflect"
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

// The ADR-0001 exit codes are reachable only through the sentinels, so an error
// that reports the right code on screen while dropping the sentinel exits with
// the wrong one. These commands construct their error by hand, which is exactly
// where the sentinel gets lost.
func TestCommandErrorsKeepTheirSentinel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		sentinel error
		wantCode int
	}{
		{
			name:     "info on a plugin that is not installed",
			args:     []string{"info", "no-such-plugin-xyz", "--cache-dir", t.TempDir()},
			sentinel: plugin.ErrPluginNotFound,
			wantCode: 4,
		},
		{
			name:     "embedded with a category that does not exist",
			args:     []string{"embedded", "--category", "no-such-category"},
			sentinel: plugin.ErrInvalidCategory,
			wantCode: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Built from the parent, because the output and quiet flags the
			// formatter reads are persistent flags on it.
			cmd := NewCommand()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tc.args)

			err := cmd.Execute()

			require.Error(t, err)
			require.ErrorIs(t, err, tc.sentinel,
				"the sentinel is what cmd/main.go maps to an exit code")
			require.Equal(t, tc.wantCode, plugin.ExitCode(err))
		})
	}
}

// The seam exists so a test can read the exit code. Nothing else pins that
// production still exits the process through it: replacing the variable with a
// no-op left the whole suite green, which means the seam was protecting the
// tests and not the behavior.
func TestExitProcessStillExitsTheProcess(t *testing.T) {
	require.Equal(t,
		reflect.ValueOf(os.Exit).Pointer(),
		reflect.ValueOf(exitProcess).Pointer(),
		"exitProcess must be os.Exit outside a test that deliberately captures it")
}
