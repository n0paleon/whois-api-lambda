package whois

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	whoisapi "whois-api-lambda/internal/apperrors"
)

// TestGetWhoisData_Success tests the successful retrieval of whois data
func TestGetWhoisData_Success(t *testing.T) {
	// Arrange
	client := NewClient()

	// Act - using a domain that should have whois information
	// Note: This makes an actual network call, which is not ideal for unit tests
	// but demonstrates the functionality. In a real scenario, we would mock this.
	ctx := context.Background()
	result, err := client.Whois(ctx, "google.com")

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "Domain Name:") // Basic check for whois data format
}

// TestGetWhoisData_InvalidDomain tests handling of invalid domain
func TestGetWhoisData_InvalidDomain(t *testing.T) {
	// Arrange
	client := NewClient()

	// Act
	ctx := context.Background()
	result, err := client.Whois(ctx, "invalid..domain")

	// Assert
	assert.Error(t, err)
	assert.Empty(t, result)
	// Check that it's the expected type of error
	assert.True(t, whoisapi.IsAppError(err))
}

func TestGetWhoisData_NoDot(t *testing.T) {
	// Arrange
	client := NewClient()

	// Act
	ctx := context.Background()
	result, err := client.Whois(ctx, "test")

	// Assert
	// This might succeed or fail depending on whether "test" is a valid TLD
	// but it should not crash
	if err != nil {
		// If it fails, it should be a proper AppError
		assert.True(t, whoisapi.IsAppError(err))
	} else {
		// If it succeeds, we should have some result
		assert.NotEmpty(t, result)
	}
}

// TestWhois_IPAddress_Success tests that valid IP addresses use IANA directly
func TestWhois_IPAddress_Success(t *testing.T) {
	// Arrange
	client := NewClient()

	// Act - using a valid IP address, should query IANA directly
	ctx := context.Background()
	result, err := client.Whois(ctx, "8.8.8.8")

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	// IP whois data typically contains information about the IP range
	assert.Contains(t, result, "inetnum") // Common field in IP whois responses
}
