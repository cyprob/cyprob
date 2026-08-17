package fingerprint

import (
	"errors"
	"fmt"
)

const (
	errorCodeSourceRequired  = "FINGERPRINT_SOURCE_REQUIRED"
	errorCodeSourceConflict  = "FINGERPRINT_SOURCE_CONFLICT"
	errorCodeStorageDisabled = "FINGERPRINT_STORAGE_DISABLED"
	errorCodeSyncFailed      = "FINGERPRINT_SYNC_FAILED"
)

var (
	// ErrSourceRequired indicates neither --file nor --url was provided.
	ErrSourceRequired = errors.New("source required")
	// ErrSourceConflict indicates both --file and --url were provided.
	ErrSourceConflict = errors.New("multiple sources provided")
	// ErrStorageDisabled indicates the CLI context lacks storage configuration.
	ErrStorageDisabled = errors.New("storage disabled")
)

type errorCoder interface {
	error
	Code() string
}

type withCodeError struct {
	error
	code string
}

func (e *withCodeError) Code() string {
	return e.code
}

func (e *withCodeError) Unwrap() error {
	return e.error
}

// WithErrorCode annotates err with a fingerprint error code.
func WithErrorCode(err error, code string) error {
	if err == nil {
		return nil
	}
	return &withCodeError{error: err, code: code}
}

// NewSourceRequiredError formats a missing source error.
func NewSourceRequiredError() error {
	return WithErrorCode(fmt.Errorf("%w: either --file or --url must be provided", ErrSourceRequired), errorCodeSourceRequired)
}

// NewSourceConflictError formats a conflicting source error.
func NewSourceConflictError() error {
	return WithErrorCode(fmt.Errorf("%w: only one of --file or --url may be provided at a time", ErrSourceConflict), errorCodeSourceConflict)
}

// NewStorageDisabledError formats a storage disabled error.
func NewStorageDisabledError() error {
	return WithErrorCode(fmt.Errorf("%w: storage disabled; specify --cache-dir", ErrStorageDisabled), errorCodeStorageDisabled)
}

// WrapSyncError annotates a sync failure.
func WrapSyncError(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(err, errorCodeSyncFailed)
}

// ErrorCode resolves an error to its fingerprint error code.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}

	var coded errorCoder
	if errors.As(err, &coded) {
		if code := coded.Code(); code != "" {
			return code
		}
	}

	switch {
	case errors.Is(err, ErrSourceRequired):
		return errorCodeSourceRequired
	case errors.Is(err, ErrSourceConflict):
		return errorCodeSourceConflict
	case errors.Is(err, ErrStorageDisabled):
		return errorCodeStorageDisabled
	default:
		return errorCodeSyncFailed
	}
}

// ExitCode maps fingerprint errors to CLI exit codes.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	switch {
	case errors.Is(err, ErrSourceRequired),
		errors.Is(err, ErrSourceConflict):
		return 2
	case errors.Is(err, ErrStorageDisabled):
		return 7
	default:
		return 1
	}
}

// HTTPStatus maps fingerprint errors to HTTP status codes.
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch {
	case errors.Is(err, ErrSourceRequired),
		errors.Is(err, ErrSourceConflict):
		return 400
	case errors.Is(err, ErrStorageDisabled):
		return 503
	default:
		return 500
	}
}

// Suggestions provides CLI hints for fingerprint errors.
func Suggestions(err error) []string {
	if err == nil {
		return nil
	}

	switch ErrorCode(err) {
	case errorCodeSourceRequired:
		return []string{
			"Provide a source:          --file <path> or --url <address>",
			"Example:                   cyprob fingerprint sync --url https://example/catalog.yaml",
		}
	case errorCodeSourceConflict:
		return []string{
			"Use only one source flag",
			"Remove either --file or --url",
		}
	case errorCodeStorageDisabled:
		return []string{
			"Set cache directory:       cyprob fingerprint sync --cache-dir <path>",
			"Enable storage via CLI root command",
		}
	case errorCodeSyncFailed:
		return []string{
			"Retry with --url pointing to a reachable catalog",
			"Check network connectivity and cache directory permissions",
		}
	default:
		return nil
	}
}
