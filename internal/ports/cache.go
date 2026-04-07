package ports

import (
	"context"
	"time"
	"whois-api-lambda/internal/domain"
)

type CacheService interface {
	GetRaw(ctx context.Context, domain string) (string, error)
	SetRaw(ctx context.Context, domain string, data string, ttl time.Duration) error
	GetParsed(ctx context.Context, domain string) (*domain.WhoisInfo, error)
	SetParsed(ctx context.Context, domain string, data *domain.WhoisInfo, ttl time.Duration) error
}
