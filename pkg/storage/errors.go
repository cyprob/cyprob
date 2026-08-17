package storage

import (
	"errors"
	"fmt"
	"os"
)

// Common errors returned by storage operations.
var (
	// ErrNotFound is returned when a requested resource does not exist.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists is returned when attempting to create a resource that already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrNotSupported is returned when an operation is not supported by the backend.
	// For example, OSS edition returns this for Enterprise-only features.
	ErrNotSupported = errors.New("operation not supported in this edition")

	// ErrInvalidInput is returned when input validation fails.
	ErrInvalidInput = errors.New("invalid input")

	// ErrClosed is returned when attempting to use a closed backend.
	ErrClosed = errors.New("backend is closed")

	// ErrRetentionPolicyNotConfigured indicates that GC was invoked without any retention policy.
	ErrRetentionPolicyNotConfigured = errors.New("no retention policy configured")
)

// NotFoundError wraps ErrNotFound with additional context.
type NotFoundError struct {
	ResourceType string // "scan", "org", "user", etc.
	ResourceID   string
}

// Error implements the error interface.
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s not found: %s", e.ResourceType, e.ResourceID)
}

// Unwrap returns the underlying error.
func (e *NotFoundError) Unwrap() error {
	return ErrNotFound
}

// Is checks if the error matches ErrNotFound.
func (e *NotFoundError) Is(target error) bool {
	return target == ErrNotFound
}

// AlreadyExistsError wraps ErrAlreadyExists with additional context.
type AlreadyExistsError struct {
	ResourceType string
	ResourceID   string
}

// Error implements the error interface.
func (e *AlreadyExistsError) Error() string {
	return fmt.Sprintf("%s already exists: %s", e.ResourceType, e.ResourceID)
}

// Unwrap returns the underlying error.
func (e *AlreadyExistsError) Unwrap() error {
	return ErrAlreadyExists
}

// Is checks if the error matches ErrAlreadyExists.
func (e *AlreadyExistsError) Is(target error) bool {
	return target == ErrAlreadyExists
}

// InvalidInputError wraps ErrInvalidInput with details.
type InvalidInputError struct {
	Field  string // Field name that failed validation
	Reason string // Why validation failed
}

// Error implements the error interface.
func (e *InvalidInputError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("invalid input for field %q: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("invalid input: %s", e.Reason)
}

// Unwrap returns the underlying error.
func (e *InvalidInputError) Unwrap() error {
	return ErrInvalidInput
}

// Is checks if the error matches ErrInvalidInput.
func (e *InvalidInputError) Is(target error) bool {
	return target == ErrInvalidInput
}

// Helper functions for creating errors.

// NewNotFoundError creates a NotFoundError.
func NewNotFoundError(resourceType, resourceID string) error {
	return &NotFoundError{
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

// NewAlreadyExistsError creates an AlreadyExistsError.
func NewAlreadyExistsError(resourceType, resourceID string) error {
	return &AlreadyExistsError{
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
}

// NewInvalidInputError creates an InvalidInputError.
func NewInvalidInputError(field, reason string) error {
	return &InvalidInputError{
		Field:  field,
		Reason: reason,
	}
}

// IsNotFound checks if an error is or wraps ErrNotFound.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsAlreadyExists checks if an error is or wraps ErrAlreadyExists.
func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

// IsNotSupported checks if an error is or wraps ErrNotSupported.
func IsNotSupported(err error) bool {
	return errors.Is(err, ErrNotSupported)
}

// IsInvalidInput checks if an error is or wraps ErrInvalidInput.
func IsInvalidInput(err error) bool {
	return errors.Is(err, ErrInvalidInput)
}

const (
	errorCodeNoRetention         = "NO_RETENTION_POLICY"
	errorCodeInvalidRetention    = "INVALID_RETENTION_POLICY"
	errorCodeWorkspaceInvalid    = "WORKSPACE_INVALID"
	errorCodeWorkspacePerm       = "WORKSPACE_PERMISSION_DENIED"
	errorCodeStorageFailure      = "STORAGE_FAILURE"
	errorCodeStorageInvalidInput = "STORAGE_INVALID_INPUT"
)

type errorCoder interface {
	Code() string
}

type storageCodeError struct {
	error
	code string
}

func (e *storageCodeError) Error() string {
	return e.error.Error()
}

func (e *storageCodeError) Unwrap() error {
	return e.error
}

func (e *storageCodeError) Code() string {
	return e.code
}

// WithErrorCode wraps an error with a storage error code.
func WithErrorCode(err error, code string) error {
	if err == nil {
		return nil
	}
	return &storageCodeError{error: err, code: code}
}

// ErrorCode resolves an error to its storage error code.
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
	case errors.Is(err, ErrRetentionPolicyNotConfigured):
		return errorCodeNoRetention
	case errors.Is(err, ErrInvalidInput):
		var invalid *InvalidInputError
		if errors.As(err, &invalid) {
			if invalid.Field == "workspace_root" {
				return errorCodeWorkspaceInvalid
			}
			return errorCodeStorageInvalidInput
		}
	case errors.Is(err, ErrNotSupported), errors.Is(err, ErrClosed):
		return errorCodeStorageFailure
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.Is(pathErr.Err, os.ErrPermission) {
			return errorCodeWorkspacePerm
		}
		return errorCodeWorkspaceInvalid
	}

	return errorCodeStorageFailure
}

// ExitCode maps storage errors to CLI exit codes.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	switch ErrorCode(err) {
	case errorCodeNoRetention,
		errorCodeInvalidRetention,
		errorCodeStorageInvalidInput:
		return 2
	case errorCodeWorkspacePerm,
		errorCodeWorkspaceInvalid,
		errorCodeStorageFailure:
		return 1
	default:
		return 1
	}
}

// HTTPStatus maps storage errors to HTTP status codes.
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch ErrorCode(err) {
	case errorCodeNoRetention,
		errorCodeInvalidRetention,
		errorCodeStorageInvalidInput:
		return 400
	case errorCodeWorkspacePerm:
		return 403
	case errorCodeWorkspaceInvalid:
		return 404
	default:
		return 500
	}
}

// Suggestions provides CLI hints for storage errors.
func Suggestions(err error) []string {
	if err == nil {
		return nil
	}

	switch ErrorCode(err) {
	case errorCodeNoRetention:
		return []string{
			"Set max scans:              cyprob storage gc --max-scans=100",
			"Set max age days:           cyprob storage gc --max-age-days=30",
		}
	case errorCodeInvalidRetention:
		return []string{
			"Use non-negative numbers for retention flags",
			"Override config with flags: cyprob storage gc --max-scans=100",
		}
	case errorCodeWorkspaceInvalid:
		return []string{
			"Set workspace dir:          cyprob storage gc --storage-dir <path>",
			"Ensure directory exists and is writable",
		}
	case errorCodeWorkspacePerm:
		return []string{
			"Fix permissions for the storage directory",
			"Run with appropriate user or adjust --storage-dir",
		}
	case errorCodeStorageInvalidInput:
		return []string{
			"Review storage values in configuration file",
			"Override with CLI flags when running GC",
		}
	case errorCodeStorageFailure:
		return []string{
			"Retry with verbose logs:    cyprob storage gc --verbosity 1",
			"Check storage directory permissions",
		}
	default:
		return nil
	}
}

// FormatRetentionValidationError converts retention validation failures into invalid input errors.
func FormatRetentionValidationError(err error) error {
	if err == nil {
		return nil
	}
	return WithErrorCode(fmt.Errorf("retention policy invalid: %w", err), errorCodeInvalidRetention)
}
