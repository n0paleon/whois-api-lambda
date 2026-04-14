package services

import (
	"context"
	"net/http"
	"sync"
	"time"

	"whois-api-lambda/internal/adapters/workerpool"
	"whois-api-lambda/internal/apperrors"
	"whois-api-lambda/internal/domain"
	"whois-api-lambda/internal/ports"
	"whois-api-lambda/pkg/utils"

	"github.com/sirupsen/logrus"
)

// WhoisService orchestrates WHOIS operations with domain normalization
type WhoisService struct {
	whoisClient   ports.WhoisClient
	parserService ports.WhoisParser
	cache         ports.CacheService
}

var (
	defaultCacheTTL = 24 * time.Hour
)

// NewWhoisService creates a new WhoisService instance
func NewWhoisService(whoisClient ports.WhoisClient, parserService ports.WhoisParser, cache ports.CacheService) *WhoisService {
	return &WhoisService{
		whoisClient:   whoisClient,
		parserService: parserService,
		cache:         cache,
	}
}

// GetWhoisData retrieves raw WHOIS information for a domain with automatic normalization
func (s *WhoisService) GetRawWhoisData(ctx context.Context, domain string) (string, error) {
	_, punycodeDomain := utils.GetDomainFormats(domain)

	if punycodeDomain == "" {
		return "", apperrors.Newf(
			apperrors.CodeInvalidDomain,
			http.StatusBadRequest,
			"domain is empty after normalization",
		)
	}

	raw, err := s.cache.GetRaw(ctx, punycodeDomain)
	if err == nil {
		logrus.Debugf("Cache: successfully retrieved raw WHOIS response for %s", punycodeDomain)
		return raw, nil
	}
	if !apperrors.IsAppError(err) {
		logrus.Warnf("Cache: failed to get raw WHOIS response from cache layer: %v", err.Error())
	}

	// Fetch live
	raw, err = s.whoisClient.Whois(ctx, punycodeDomain)
	if err != nil {
		return "", err
	}

	// Cache raw asynchronously
	_ = workerpool.Submit(func() {
		if err := s.cache.SetRaw(ctx, punycodeDomain, raw, 24*time.Hour); err != nil {
			logrus.Errorf("Cache: failed to save raw WHOIS response to cache layer: %v", err.Error())
		} else {
			logrus.Debugf("Cache: successfully saved raw WHOIS response for %s", punycodeDomain)
		}
	})

	return raw, nil
}

func (s *WhoisService) GetWhoisData(ctx context.Context, domain string) (*domain.WhoisInfo, error) {
	nativeDomain, punycodeDomain := utils.GetDomainFormats(domain)

	if punycodeDomain == "" {
		return nil, apperrors.Newf(
			apperrors.CodeInvalidDomain,
			http.StatusBadRequest,
			"domain is empty after normalization",
		)
	}

	parsed, err := s.cache.GetParsed(ctx, punycodeDomain)
	if err == nil {
		logrus.Debugf("Cache: successfully retrieved parsed WHOIS response for %s", punycodeDomain)
		return parsed, nil
	}
	if !apperrors.IsAppError(err) {
		logrus.Warnf("Cache: failed to get parsed WHOIS response from cache layer: %v", err.Error())
	}

	rawWhoisData, err := s.GetRawWhoisData(ctx, punycodeDomain)
	if err != nil {
		if apperrors.IsAppError(err) {
			return nil, err
		}
		logrus.Errorf("WhoisService: failed to get raw WHOIS response: %v", err.Error())
		return nil, apperrors.ErrInternal
	}

	whoisInfo, err := s.parserService.Parse(ctx, rawWhoisData, nativeDomain)
	if err != nil || whoisInfo.Domain == nil || whoisInfo.Domain.CreatedAt == nil {
		if appErr, ok := apperrors.AsAppError(err); ok {
			return nil, appErr
		}
		return nil, apperrors.New(apperrors.CodeDomainNotFound, http.StatusNotFound, "An error occurred while attempting to parse the response from the WHOIS server. Try using a Raw WHOIS Query.")
	}

	// Cache parsed asynchronously
	_ = workerpool.Submit(func() {
		if err := s.cache.SetParsed(ctx, punycodeDomain, whoisInfo, 24*time.Hour); err != nil {
			logrus.Errorf("Cache: failed to save parsed WHOIS response to cache layer: %v", err.Error())
		} else {
			logrus.Debugf("Cache: successfully saved parsed WHOIS response for %s", punycodeDomain)
		}
	})

	return whoisInfo, nil
}

func (s *WhoisService) BulkGetWhoisData(ctx context.Context, domains []string) ([]*domain.WhoisInfoList, error) {
	if len(domains) == 0 {
		return []*domain.WhoisInfoList{}, nil
	}

	if len(domains) > 200 {
		return nil, apperrors.Newf(
			apperrors.CodeInvalidDomain,
			http.StatusBadRequest,
			"maximum 200 domains allowed per request",
		)
	}

	seen := make(map[string]bool)
	uniqueDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		_, normalized := utils.GetDomainFormats(d)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		uniqueDomains = append(uniqueDomains, normalized)
	}

	if len(uniqueDomains) == 0 {
		return nil, apperrors.Newf(
			apperrors.CodeInvalidDomain,
			http.StatusBadRequest,
			"no valid domains provided",
		)
	}

	results := make([]*domain.WhoisInfoList, 0, len(uniqueDomains))
	mu := sync.Mutex{}
	var wg sync.WaitGroup

	for _, d := range uniqueDomains {
		wg.Add(1)
		domainVal := d
		_ = workerpool.Submit(func() {
			defer wg.Done()
			entry := &domain.WhoisInfoList{}
			info, err := s.GetWhoisData(ctx, domainVal)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				var code string
				var msg string
				if appErr, ok := err.(*apperrors.AppError); ok {
					code = appErr.Code
					msg = appErr.Message
				} else {
					code = "UNKNOWN_ERROR"
					msg = err.Error()
				}
				results = append(results, &domain.WhoisInfoList{
					IsError:   true,
					ErrorCode: code,
					Message:   msg,
					Whois:     nil,
				})
				return
			}
			mu.Lock()
			defer mu.Unlock()
			entry.Whois = info
			entry.IsError = false
			results = append(results, entry)
		})
	}

	wg.Wait()
	return results, nil
}

func (s *WhoisService) GetAvailableTLDs() []*domain.TLD {
	return s.whoisClient.GetAvailableTLDs()
}
