package ports

import (
	"context"
	"whois-api-lambda/internal/domain"
)

type WhoisClient interface {
	Whois(ctx context.Context, query string) (string, error)
	GetAvailableTLDs() []*domain.TLD
}

type WhoisParser interface {
	Parse(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error)
}

type WhoisLLMParser interface {
	Parse(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error)
}
