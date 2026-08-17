package server

import (
	"errors"
	"fmt"
)

const (
	errorCodeInvalidPort        = "SERVER_INVALID_PORT"
	errorCodeInvalidConcurrency = "SERVER_INVALID_CONCURRENCY"
	errorCodeFeaturesDisabled   = "SERVER_FEATURES_DISABLED"
	errorCodeConfigUnavailable  = "SERVER_CONFIG_UNAVAILABLE"
	errorCodeInvalidConfig      = "SERVER_INVALID_CONFIG"
	errorCodeStorageInitFailed  = "SERVER_STORAGE_INIT_FAILED"
	errorCodePluginInitFailed   = "SERVER_PLUGIN_INIT_FAILED"
	errorCodeAppInitFailed      = "SERVER_INIT_FAILED"
	errorCodeRuntimeFailed      = "SERVER_RUNTIME_FAILED"
)

var (
	// ErrInvalidPort indicates an invalid port flag value.
	ErrInvalidPort = errors.New("invalid port")
	// ErrInvalidConcurrency indicates an invalid jobs concurrency value.
	ErrInvalidConcurrency = errors.New("invalid jobs concurrency")
	// ErrFeaturesDisabled indicates UI and API were both disabled.
	ErrFeaturesDisabled = errors.New("ui and api disabled")
	// ErrConfigUnavailable indicates the CLI context lacked a config manager.
	ErrConfigUnavailable = errors.New("config manager unavailable")
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

// WithErrorCode annotates err with a server error code.
func WithErrorCode(err error, code string) error {
	if err == nil {
		return nil
	}
	return &withCodeError{error: err, code: code}
}

// NewInvalidPortError formats an invalid port error with context.
func NewInvalidPortError(port int) error {
	return WithErrorCode(fmt.Errorf("%w: invalid port %d: must be between 1 and 65535", ErrInvalidPort, port), errorCodeInvalidPort)
}

// NewInvalidConcurrencyError formats an invalid concurrency error.
func NewInvalidConcurrencyError(concurrency int) error {
	return WithErrorCode(fmt.Errorf("%w: invalid concurrency %d: must be at least 1", ErrInvalidConcurrency, concurrency), errorCodeInvalidConcurrency)
}

// NewFeaturesDisabledError reports mutually-disabled UI/API flags.
func NewFeaturesDisabledError() error {
	return WithErrorCode(fmt.Errorf("%w: cannot disable both UI and API: at least one must be enabled", ErrFeaturesDisabled), errorCodeFeaturesDisabled)
}

// WrapInvalidConfig annotates server config validation errors.
func WrapInvalidConfig(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(fmt.Errorf("invalid server configuration: %w", err), errorCodeInvalidConfig)
}

// WrapStorageInit annotates storage backend initialization failures.
func WrapStorageInit(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(err, errorCodeStorageInitFailed)
}

// WrapPluginInit annotates plugin service initialization failures.
func WrapPluginInit(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(err, errorCodePluginInitFailed)
}

// WrapAppInit annotates server app creation failures.
func WrapAppInit(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(err, errorCodeAppInitFailed)
}

// WrapRuntime annotates server runtime failures.
func WrapRuntime(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(err, errorCodeRuntimeFailed)
}

// ErrorCode resolves a server error to its error code.
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
	case errors.Is(err, ErrInvalidPort):
		return errorCodeInvalidPort
	case errors.Is(err, ErrInvalidConcurrency):
		return errorCodeInvalidConcurrency
	case errors.Is(err, ErrFeaturesDisabled):
		return errorCodeFeaturesDisabled
	case errors.Is(err, ErrConfigUnavailable):
		return errorCodeConfigUnavailable
	default:
		return errorCodeRuntimeFailed
	}
}

// ExitCode maps server errors to CLI exit codes.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	switch {
	case errors.Is(err, ErrInvalidPort),
		errors.Is(err, ErrInvalidConcurrency),
		errors.Is(err, ErrFeaturesDisabled):
		return 2
	case errors.Is(err, ErrConfigUnavailable):
		return 1
	case ErrorCode(err) == errorCodeStorageInitFailed,
		ErrorCode(err) == errorCodePluginInitFailed,
		ErrorCode(err) == errorCodeAppInitFailed:
		return 7
	default:
		return 1
	}
}

// HTTPStatus maps server errors to HTTP status codes.
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch {
	case errors.Is(err, ErrInvalidPort),
		errors.Is(err, ErrInvalidConcurrency),
		errors.Is(err, ErrFeaturesDisabled):
		return 400
	case errors.Is(err, ErrConfigUnavailable):
		return 500
	default:
		return 500
	}
}

// Suggestions provides CLI hints for server errors.
func Suggestions(err error) []string {
	if err == nil {
		return nil
	}

	switch ErrorCode(err) {
	case errorCodeInvalidPort:
		return []string{
			"Use a port between 1 and 65535",
			"Example:                 cyprob server start --port 8080",
		}
	case errorCodeInvalidConcurrency:
		return []string{
			"Set jobs concurrency to at least 1",
			"Example:                 cyprob server start --jobs-concurrency 4",
		}
	case errorCodeFeaturesDisabled:
		return []string{
			"Enable either UI or API flags",
			"Remove one of --no-ui / --no-api",
		}
	case errorCodeConfigUnavailable:
		return []string{
			"Run via the cyprob CLI so AppManager initializes",
			"Avoid calling server start from custom scripts without init",
		}
	case errorCodeInvalidConfig:
		return []string{
			"Check configuration values in config file",
			"Retry with --verbose for detailed validation errors",
		}
	case errorCodeStorageInitFailed:
		return []string{
			"Verify storage directory permissions",
			"Override storage root:     cyprob server start --storage-dir <path>",
		}
	case errorCodePluginInitFailed:
		return []string{
			"Check plugin cache directory access",
			"Retry after running:      cyprob plugin clean",
		}
	case errorCodeAppInitFailed:
		return []string{
			"Retry with verbose logging: cyprob server start --verbose",
			"Review configuration for invalid values",
		}
	case errorCodeRuntimeFailed:
		return []string{
			"Check server logs for runtime errors",
			"Ensure no other process is using the selected port",
		}
	default:
		return nil
	}
}
