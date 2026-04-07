package apperrors

import (
	"errors"
	"fmt"
	"net/http"
)

// New creates a new AppError with the given code, status code, and message.
func New(code string, statusCode int, message string) *AppError {
	return &AppError{
		Code:       code,
		StatusCode: statusCode,
		Message:    message,
	}
}

// Newf creates a new AppError with the given code, status code, and a formatted message.
func Newf(code string, statusCode int, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:       code,
		StatusCode: statusCode,
		Message:    fmt.Sprintf(format, args...),
	}
}

// IsAppError reports whether any error in err's chain is an *AppError.
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// AsAppError extracts an *AppError from err's chain, returning it and true
// if found, or nil and false otherwise.
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

type AppError struct {
	// Code is a machine-readable error identifier (e.g., NOT_FOUND, TIMEOUT, VALIDATION_ERROR).
	Code string
	// StatusCode is the HTTP status code to return in API responses.
	StatusCode int
	// Message is a human-readable error description suitable for client display.
	Message string
	// Detail contains additional contextual information about the error (optional).
	Detail map[string]interface{}
	// Err holds the underlying error that caused this AppError (optional).
	Err error
}

// Error implements the error interface for AppError.
// It returns a formatted string containing the error code, message,
// and the underlying error if present.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}

	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error, enabling error unwrapping
// with errors.Is() and errors.As() for error chain inspection.
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetail adds a key-value pair to the error's Detail map and returns
// the AppError for method chaining. This is useful for building up
// contextual error information in a fluent style.
func (e *AppError) WithDetail(key string, value interface{}) *AppError {
	if e.Detail == nil {
		e.Detail = make(map[string]interface{})
	}
	e.Detail[key] = value
	return e
}

// WithError sets the underlying error and returns the AppError for method chaining.
// This allows attaching the original error that caused this AppError,
// enabling error chain inspection with errors.Is() and errors.As().
func (e *AppError) WithError(err error) *AppError {
	e.Err = err
	return e
}

// GetStatusCode returns the HTTP status code for this error.
// If StatusCode is not set (zero value), it defaults to http.StatusInternalServerError (500).
func (e *AppError) GetStatusCode() int {
	if e.StatusCode == 0 {
		return http.StatusInternalServerError
	}
	return e.StatusCode
}
