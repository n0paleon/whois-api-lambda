package ports

import (
	"context"
	"whois-api-lambda/internal/domain"
)

type LLMParser interface {
	Parse(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error)
}
