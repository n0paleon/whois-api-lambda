package whois

import (
	"context"
	"errors"
	"testing"
	"time"
	"whois-api-lambda/internal/apperrors"
)

// BenchmarkGetWhoisData measures the performance of the GetWhoisData method
// Note: This makes actual network calls, so results may vary significantly
func BenchmarkGetWhoisData(b *testing.B) {
	client := NewClient()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.Whois(ctx, "google.com")
		if err != nil {
			var appErr *apperrors.AppError
			if errors.As(err, &appErr) {
				b.Logf("AppError occurred: %v", appErr.Unwrap())
			}
			b.Error(err)
		}
	}
}

// BenchmarkGetWhoisDataWithContextTimeout measures performance when context times out
func BenchmarkGetWhoisDataWithContextTimeout(b *testing.B) {
	client := NewClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a very short timeout to force context cancellation
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		_, err := client.Whois(ctx, "google.com")
		// Expect timeout error
		if err == nil {
			b.Error("Expected timeout error")
		}
	}
}
