package scanexec

import (
	"errors"
	"fmt"
)

// Sentinel errors for common CLI failures.
var (
	// ErrNoTargets indicates that no scan targets were supplied.
	ErrNoTargets = errors.New("no scan targets specified")

	// ErrConflictingDiscoveryFlags indicates conflicting discovery flags.
	ErrConflictingDiscoveryFlags = errors.New("cannot use --only-discover and --no-discover together")
)

// Error codes for scan failures used by CLI suggestion system.
const (
	errorCodeInvalidTarget        = "INVALID_TARGET"
	errorCodeConflictingDiscovery = "CONFLICTING_DISCOVERY_FLAGS"
	errorCodeScanFailure          = "SCAN_FAILURE"
)

// codedError wraps an error with an explicit error code.
type codedError struct {
	error
	code string
}

func (e *codedError) Error() string {
	return e.error.Error()
}

func (e *codedError) Unwrap() error {
	return e.error
}

func (e *codedError) Code() string {
	return e.code
}

// WithErrorCode wraps err with a specific CLI error code.
func WithErrorCode(err error, code string) error {
	if err == nil {
		return nil
	}
	return &codedError{error: err, code: code}
}

// ErrorCode resolves a cyprob scan error into a CLI error code.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}

	var coded interface{ Code() string }
	if errors.As(err, &coded) {
		if code := coded.Code(); code != "" {
			return code
		}
	}

	switch {
	case errors.Is(err, ErrNoTargets):
		return errorCodeInvalidTarget
	case errors.Is(err, ErrConflictingDiscoveryFlags):
		return errorCodeConflictingDiscovery
	}

	return errorCodeScanFailure
}

// ExitCode maps scan errors to CLI exit codes.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	switch ErrorCode(err) {
	case errorCodeInvalidTarget,
		errorCodeConflictingDiscovery:
		return 2
	default:
		return 1
	}
}

// HTTPStatus maps scan errors to HTTP status codes.
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch ErrorCode(err) {
	case errorCodeInvalidTarget,
		errorCodeConflictingDiscovery:
		return 400
	default:
		return 500
	}
}

// Suggestions provides CLI hints for scan errors.
func Suggestions(err error) []string {
	if err == nil {
		return nil
	}

	switch ErrorCode(err) {
	case errorCodeInvalidTarget:
		return []string{
			"Provide a target:           cyprob scan 192.168.1.0/24",
			"Scan multiple hosts:        cyprob scan 10.0.0.1 10.0.0.2",
		}
	case errorCodeConflictingDiscovery:
		return []string{
			"Remove either --only-discover or --no-discover",
			"Run help for options:       cyprob scan --help",
		}
	default:
		return []string{
			"Retry with verbose logs:    cyprob scan <target> --verbose",
			"Enable progress output:     cyprob scan <target> --progress",
		}
	}
}

// NewInvalidTargetError annotates an invalid target input with context.
func NewInvalidTargetError(input string, reason error) error {
	base := ErrNoTargets
	if input != "" {
		base = fmt.Errorf("invalid target %q: %w", input, reason)
	}
	return WithErrorCode(base, errorCodeInvalidTarget)
}
