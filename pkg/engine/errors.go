package engine

import (
	"errors"
	"fmt"
)

const (
	errorCodeLoadFailed        = "DAG_LOAD_FAILED"
	errorCodeUnsupportedFormat = "DAG_UNSUPPORTED_FORMAT"
	errorCodeMarshalFailed     = "DAG_MARSHAL_FAILED"
	errorCodeWriteFailed       = "DAG_WRITE_FAILED"
	errorCodeInvalidDAG        = "DAG_INVALID"
)

var (
	// ErrLoadFailed indicates the DAG definition could not be loaded.
	ErrLoadFailed = errors.New("dag load failed")

	// ErrUnsupportedFormat indicates an unsupported export format.
	ErrUnsupportedFormat = errors.New("unsupported dag export format")

	// ErrWriteFailed indicates a write to disk failed.
	ErrWriteFailed = errors.New("dag write failed")

	// ErrInvalidDAG indicates the generated DAG did not pass validation.
	ErrInvalidDAG = errors.New("dag invalid")
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

// WithErrorCode annotates err with a DAG error code.
func WithErrorCode(err error, code string) error {
	if err == nil {
		return nil
	}
	return &withCodeError{error: err, code: code}
}

// WrapLoadError annotates a DAG load failure.
func WrapLoadError(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(fmt.Errorf("%w: failed to load DAG: %w", ErrLoadFailed, err), errorCodeLoadFailed)
}

// NewUnsupportedFormatError formats an unsupported export format error.
func NewUnsupportedFormatError(format string) error {
	return WithErrorCode(fmt.Errorf("%w: unsupported format: %s (use yaml or json)", ErrUnsupportedFormat, format), errorCodeUnsupportedFormat)
}

// WrapMarshalError annotates marshal errors.
func WrapMarshalError(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(fmt.Errorf("failed to marshal DAG: %w", err), errorCodeMarshalFailed)
}

// WrapWriteError annotates output write failures.
func WrapWriteError(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(fmt.Errorf("%w: failed to write output file: %w", ErrWriteFailed, err), errorCodeWriteFailed)
}

// WrapInvalidDAG annotates invalid generated DAG errors.
func WrapInvalidDAG(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(fmt.Errorf("%w: %v", ErrInvalidDAG, err), errorCodeInvalidDAG)
}

// ErrorCode resolves an error to its DAG error code.
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
	case errors.Is(err, ErrLoadFailed):
		return errorCodeLoadFailed
	case errors.Is(err, ErrUnsupportedFormat):
		return errorCodeUnsupportedFormat
	case errors.Is(err, ErrWriteFailed):
		return errorCodeWriteFailed
	case errors.Is(err, ErrInvalidDAG):
		return errorCodeInvalidDAG
	default:
		return errorCodeMarshalFailed
	}
}

// ExitCode maps errors to CLI exit codes.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	switch {
	case errors.Is(err, ErrUnsupportedFormat):
		return 2
	case errors.Is(err, ErrLoadFailed):
		return 4
	case errors.Is(err, ErrWriteFailed):
		return 1
	case errors.Is(err, ErrInvalidDAG):
		return 2
	default:
		return 1
	}
}

// HTTPStatus maps errors to HTTP status codes (future-proof for API usage).
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch {
	case errors.Is(err, ErrUnsupportedFormat),
		errors.Is(err, ErrInvalidDAG):
		return 400
	case errors.Is(err, ErrLoadFailed):
		return 404
	case errors.Is(err, ErrWriteFailed):
		return 500
	default:
		return 500
	}
}

// Suggestions provides human readable guidance for CLI usage.
func Suggestions(err error) []string {
	if err == nil {
		return nil
	}

	code := ErrorCode(err)
	switch code {
	case errorCodeLoadFailed:
		return []string{
			"Verify the DAG file path exists",
			"Ensure the file is valid YAML or JSON",
		}
	case errorCodeUnsupportedFormat:
		return []string{
			"Use --format yaml or --format json",
		}
	case errorCodeWriteFailed:
		return []string{
			"Ensure destination path is writable",
			"Retry without --output to print to stdout",
		}
	case errorCodeInvalidDAG:
		return []string{
			"Run cyprob dag validate on the export output",
			"Fix reported validation errors before exporting again",
		}
	default:
		return nil
	}
}
