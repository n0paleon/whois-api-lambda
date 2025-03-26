package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/zonedb/zonedb"
)

type WhoisImpl struct{}

var (
	IANA           = "whois.iana.org"
	tldCache       sync.Map
	initOnce       sync.Once
	initDone       = make(chan struct{})
	defaultTimeout = 15 * time.Second
	minDelay       = 10
	maxDelay       = 100
)

func NewWhoisService() Whois {
	return &WhoisImpl{}
}

func (s *WhoisImpl) GetAvailableTLDs() []*TLD {
	<-initDone

	var results []*TLD
	tldCache.Range(func(k, v interface{}) bool {
		results = append(results, v.(*TLD))
		return true
	})

	return results
}

func (s *WhoisImpl) GetWhoisData(ctx context.Context, query string) (*WhoisData, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query, err := ParseRootDomain(query)
	if err != nil {
		return nil, err
	}

	rawWhoisData, err := s.GetRawWhoisData(ctx, query)
	if err != nil {
		return nil, err
	}

	whoisData, err := s.parseRawWhois(rawWhoisData)
	if err != nil || whoisData.Domain.CreatedAt == nil {
		return nil, err
	}

	return whoisData, nil
}

func (s *WhoisImpl) MassWhoisLookup(ctx context.Context, queries []string) ([]*MassWhoisData, error) {
	var wg sync.WaitGroup
	var results sync.Map

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for _, q := range queries {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, err := ParseRootDomain(q)
			if err != nil {
				results.Store(q, &MassWhoisData{
					Data:       nil,
					DomainName: q,
					Error:      err,
				})
				return
			}

			rateLimit := time.Duration(RandomInRange(minDelay, maxDelay)) * time.Millisecond
			time.Sleep(rateLimit)

			result, err := s.GetWhoisData(ctx, q)
			results.Store(q, &MassWhoisData{
				Data:       result,
				DomainName: q,
				Error:      err,
			})
		}()
	}

	wg.Wait()

	finalResults := make([]*MassWhoisData, 0, len(queries))
	results.Range(func(key, value interface{}) bool {
		if val, ok := value.(*MassWhoisData); ok {
			finalResults = append(finalResults, val)
		}
		return true
	})

	return finalResults, nil
}

func (s *WhoisImpl) GetRawWhoisData(ctx context.Context, query string) ([]byte, error) {
	client := whois.NewClient()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultTimeout)
	}

	timeout := time.Until(deadline)
	client.SetTimeout(timeout)

	server, _, _ := s.GetWhoisServer(query)
	result, err := client.Whois(query, server)
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

func (s *WhoisImpl) parseRawWhois(data []byte) (*WhoisData, error) {
	parsedResult, err := whoisparser.Parse(string(data))
	if err != nil {
		return nil, err
	}

	whoisDomain := new(WhoisData)
	if parsedResult.Domain != nil {
		whoisDomain.Domain = &WhoisDomain{
			ID:          parsedResult.Domain.ID,
			Domain:      parsedResult.Domain.Domain,
			Punycode:    parsedResult.Domain.Punycode,
			Name:        parsedResult.Domain.Name,
			Extension:   parsedResult.Domain.Extension,
			WhoisServer: parsedResult.Domain.WhoisServer,
			Status:      parsedResult.Domain.Status,
			NameServers: parsedResult.Domain.NameServers,
			DNSSec:      parsedResult.Domain.DNSSec,
			CreatedAt:   parsedResult.Domain.CreatedDateInTime,
			UpdatedAt:   parsedResult.Domain.UpdatedDateInTime,
			ExpiresAt:   parsedResult.Domain.ExpirationDateInTime,
		}
	}
	if parsedResult.Registrar != nil {
		whoisDomain.Registrar = &WhoisContact{
			ID:           parsedResult.Registrar.ID,
			Name:         parsedResult.Registrar.Name,
			Organization: parsedResult.Registrar.Organization,
			Street:       parsedResult.Registrar.Street,
			City:         parsedResult.Registrar.City,
			Province:     parsedResult.Registrar.Province,
			PostalCode:   parsedResult.Registrar.PostalCode,
			Country:      parsedResult.Registrar.Country,
			Phone:        parsedResult.Registrar.Phone,
			Fax:          parsedResult.Registrar.Fax,
			Email:        parsedResult.Registrar.Email,
			ReferralURL:  parsedResult.Registrar.ReferralURL,
		}
	}
	if parsedResult.Registrant != nil {
		whoisDomain.Registrant = &WhoisContact{
			ID:           parsedResult.Registrant.ID,
			Name:         parsedResult.Registrant.Name,
			Organization: parsedResult.Registrant.Organization,
			Street:       parsedResult.Registrant.Street,
			City:         parsedResult.Registrant.City,
			Province:     parsedResult.Registrant.Province,
			PostalCode:   parsedResult.Registrant.PostalCode,
			Country:      parsedResult.Registrant.Country,
			Phone:        parsedResult.Registrant.Phone,
			Fax:          parsedResult.Registrant.Fax,
			Email:        parsedResult.Registrant.Email,
			ReferralURL:  parsedResult.Registrant.ReferralURL,
		}
	}

	return whoisDomain, nil
}

func (s *WhoisImpl) GetWhoisServer(query string) (string, string, error) {
	if strings.Index(query, ".") < 0 {
		return IANA, "", nil
	}
	z := zonedb.PublicZone(query)
	if z == nil {
		return "", "", fmt.Errorf("no public zone found for %s", query)
	}

	wu := z.WhoisURL()
	if wu != "" {
		u, err := url.Parse(wu)
		if err == nil && u.Host != "" {
			return u.Host, wu, nil
		}
	}

	h := z.WhoisServer()
	if h != "" {
		return h, "", nil
	}

	return "", "", fmt.Errorf("no whois server found for %s", query)
}

func init() {
	initOnce.Do(func() {
		list := zonedb.TLDs

		var counter atomic.Int64
		for _, tld := range list {
			if tld.WhoisServer() != "" && len(tld.NameServers) != 0 {
				data := &TLD{
					RootTLD:          tld.Domain,
					RegistryOperator: tld.RegistryOperator,
					InfoURL:          tld.InfoURL,
				}

				for _, subdomain := range tld.Subdomains {
					data.SubTLD = append(data.SubTLD, subdomain.Domain)
				}
				data.Tags = strings.Split(tld.Tags.String(), " ")

				tldCache.Store(tld.Domain, data)
				counter.Add(1)
			}
		}

		close(initDone)
		fmt.Println("Data initialized")
	})
}
