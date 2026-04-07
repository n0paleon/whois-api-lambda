package apperrors

import "net/http"

// Error codes
const (
	CodeNotFound                  = "NOT_FOUND"
	CodeTimeout                   = "TIMEOUT"
	CodeInternal                  = "INTERNAL_ERROR"
	CodeValidationError           = "VALIDATION_ERROR"
	CodeRateLimited               = "RATE_LIMITED"
	CodeUnauthorized              = "UNAUTHORIZED"
	CodeForbidden                 = "FORBIDDEN"
	CodeServiceUnavailable        = "SERVICE_UNAVAILABLE"
	CodeBadGateway                = "BAD_GATEWAY"
	CodeConflict                  = "CONFLICT"
	CodeNotImplemented            = "NOT_IMPLEMENTED"
	CodeRequestCanceled           = "REQUEST_CANCELED"
	CodePayloadTooLarge           = "PAYLOAD_TOO_LARGE"
	CodeDomainNotFound            = "DOMAIN_NOT_FOUND"
	CodeInvalidDomain             = "INVALID_DOMAIN"
	CodeDNSResolutionFailed       = "DNS_RESOLUTION_FAILED"
	CodeWhoisServerUnreachable    = "WHOIS_SERVER_UNREACHABLE"
	CodeNoValidPublicZone         = "NO_VALID_PUBLIC_ZONE"
	CodeNoValidWhoisServer        = "NO_VALID_WHOIS_SERVER"
	CodeNoResponseFromWhoisServer = "WHOIS_SERVER_NO_RESPONSE"
)

// Generic errors
var (
	ErrNotFound = &AppError{
		Code:       CodeNotFound,
		StatusCode: http.StatusNotFound,
		Message:    "The requested resource was not found.",
	}

	ErrTimeout = &AppError{
		Code:       CodeTimeout,
		StatusCode: http.StatusGatewayTimeout,
		Message:    "The request timed out. Please try again later.",
	}

	ErrWhoisServerTimeout = &AppError{
		Code:       CodeTimeout,
		StatusCode: http.StatusGatewayTimeout,
		Message:    "It looks like the target WHOIS server is down, please try again later.",
	}

	ErrInternal = &AppError{
		Code:       CodeInternal,
		StatusCode: http.StatusInternalServerError,
		Message:    "An internal server error occurred.",
	}

	ErrValidationError = &AppError{
		Code:       CodeValidationError,
		StatusCode: http.StatusBadRequest,
		Message:    "The request contains invalid input.",
	}

	ErrRateLimited = &AppError{
		Code:       CodeRateLimited,
		StatusCode: http.StatusTooManyRequests,
		Message:    "Too many requests. Please slow down and try again later.",
	}

	ErrUnauthorized = &AppError{
		Code:       CodeUnauthorized,
		StatusCode: http.StatusUnauthorized,
		Message:    "Authentication is required or the provided credentials are invalid.",
	}

	ErrForbidden = &AppError{
		Code:       CodeForbidden,
		StatusCode: http.StatusForbidden,
		Message:    "You do not have permission to perform this action.",
	}

	ErrServiceUnavailable = &AppError{
		Code:       CodeServiceUnavailable,
		StatusCode: http.StatusServiceUnavailable,
		Message:    "The service is temporarily unavailable. Please try again later.",
	}

	ErrBadGateway = &AppError{
		Code:       CodeBadGateway,
		StatusCode: http.StatusBadGateway,
		Message:    "An invalid response was received from an upstream server.",
	}

	ErrConflict = &AppError{
		Code:       CodeConflict,
		StatusCode: http.StatusConflict,
		Message:    "The request conflicts with the current state of the resource.",
	}

	ErrNotImplemented = &AppError{
		Code:       CodeNotImplemented,
		StatusCode: http.StatusNotImplemented,
		Message:    "This feature is not yet implemented.",
	}

	ErrRequestCanceled = &AppError{
		Code:       CodeRequestCanceled,
		StatusCode: http.StatusRequestTimeout,
		Message:    "The request was canceled.",
	}

	ErrPayloadTooLarge = &AppError{
		Code:       CodePayloadTooLarge,
		StatusCode: http.StatusRequestEntityTooLarge,
		Message:    "The request payload is too large.",
	}

	ErrDomainNotFound = &AppError{
		Code: CodeDomainNotFound,
		StatusCode: http.StatusNotFound,
		Message: "The WHOIS server responds that the domain does not exist.",
	}
)

// DomainNotFound returns an AppError indicating the requested domain was not found.
func DomainNotFound(domain string) *AppError {
	err := &AppError{
		Code:       CodeDomainNotFound,
		StatusCode: http.StatusNotFound,
		Message:    "WHOIS data not found for the specified domain.",
	}
	err.WithDetail("domain", domain)
	return err
}

// InvalidDomain returns an AppError indicating the domain format is invalid.
func InvalidDomain(domain string) *AppError {
	err := &AppError{
		Code:       CodeInvalidDomain,
		StatusCode: http.StatusBadRequest,
		Message:    "The provided domain name is invalid.",
	}
	err.WithDetail("domain", domain)
	return err
}

// DNSResolutionFailed returns an AppError indicating a DNS resolution failure.
func DNSResolutionFailed(domain string) *AppError {
	err := &AppError{
		Code:       CodeDNSResolutionFailed,
		StatusCode: http.StatusBadGateway,
		Message:    "Failed to resolve the domain's DNS records.",
	}
	err.WithDetail("domain", domain)
	return err
}

// WhoisServerUnreachable returns an AppError indicating the WHOIS server could not be reached.
func WhoisServerUnreachable(server string) *AppError {
	err := &AppError{
		Code:       CodeWhoisServerUnreachable,
		StatusCode: http.StatusBadGateway,
		Message:    "The WHOIS server could not be reached.",
	}
	err.WithDetail("whois_server", server)
	return err
}
