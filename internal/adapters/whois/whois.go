package whois

import (
	"context"
	"strings"
	"sync"
	"time"
	"whois-api-lambda/internal/adapters/workerpool"
	"whois-api-lambda/internal/apperrors"
	"whois-api-lambda/internal/domain"
	"whois-api-lambda/pkg/utils"

	who "github.com/likexian/whois"
	"github.com/zonedb/zonedb"
)

var (
	DefaultTimeout = 30 * time.Second
	IANA           = "whois.iana.org"
	TLDList        sync.Map
	once           sync.Once
)

func init() {
	once.Do(func() {
		for _, tld := range zonedb.TLDs {
			if tld.WhoisServer() != "" || tld.WhoisURL() != "" || len(tld.NameServers) != 0 {
				data := &domain.TLD{
					RootTLD:            tld.Domain,
					RegistryOperator:   tld.RegistryOperator,
					InfoURL:            tld.InfoURL,
					Tags:               strings.Split(tld.Tags.String(), " "),
					Languages:          tld.Languages(),
					AllowsIDN:          tld.AllowsIDN(),
					AllowsRegistration: tld.AllowsRegistration(),
				}
				for _, subdomain := range tld.Subdomains {
					data.SubTLD = append(data.SubTLD, subdomain.Domain)
				}
				TLDList.Store(tld.Domain, data)
			}
		}
	})
}

type Client struct {
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) GetAvailableTLDs() []*domain.TLD {
	var tlds []*domain.TLD
	TLDList.Range(func(key, value interface{}) bool {
		tlds = append(tlds, value.(*domain.TLD))
		return true
	})
	return tlds
}

func (c *Client) Whois(ctx context.Context, query string) (string, error) {
	childCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	resultChannel := make(chan resultChan, 1)

	_ = workerpool.Submit(func() {
		client := who.NewClient()
		client.SetDisableReferral(false)
		client.SetDisableStats(true)
		client.SetDisableReferralChain(false)

		var serverHost string
		if utils.IsValidIP(query) {
			serverHost = IANA
		} else {
			server, err := GetWhoisServer(query)
			if err != nil {
				resultChannel <- resultChan{result: "", err: err}
				return
			}
			serverHost = server.GetWhoisServerHost()
		}

		primaryCtx, cancel1 := context.WithTimeout(childCtx, 15*time.Second)
		defer cancel1()

		result, err := timedWhois(client, query, serverHost, primaryCtx)
		if err != nil || len(result) == 0 {
			if err == apperrors.ErrTimeout {
				// Primary timed out, try IANA with remaining time
				fallbackResult, fallbackErr := timedWhois(client, query, IANA, childCtx)
				if fallbackErr == nil && fallbackResult != "" {
					resultChannel <- resultChan{result: fallbackResult, err: nil}
					return
				}

				resultChannel <- resultChan{
					result: "",
					err: apperrors.WhoisServerUnreachable(serverHost).
						WithError(err).
						WithDetail("root_cause", "primary timeout, IANA fallback failed"),
				}
				return
			}

			if strings.Contains(err.Error(), "connect to whois server failed") ||
				strings.Contains(err.Error(), "connection reset") {

				fallbackResult, fallbackErr := timedWhois(client, query, IANA, childCtx)
				if fallbackErr == nil && fallbackResult != "" {
					resultChannel <- resultChan{result: fallbackResult, err: nil}
					return
				}

				resultChannel <- resultChan{
					result: "",
					err: apperrors.WhoisServerUnreachable(serverHost).
						WithError(err).
						WithDetail("root_cause", err.Error()),
				}
				return
			}

			fallbackResult, fallbackErr := timedWhois(client, query, IANA, childCtx)
			if fallbackErr == nil && fallbackResult != "" {
				resultChannel <- resultChan{result: fallbackResult, err: nil}
				return
			}

			resultChannel <- resultChan{result: "", err: err}
			return
		}

		resultChannel <- resultChan{result: result, err: nil}
	})

	select {
	case res := <-resultChannel:
		return res.result, res.err
	case <-childCtx.Done():
		return "", apperrors.ErrWhoisServerTimeout
	}
}

func timedWhois(client *who.Client, query, server string, ctx context.Context) (string, error) {
	ch := make(chan struct {
		result string
		err    error
	}, 1)

	go func() {
		result, err := client.Whois(query, server)
		ch <- struct {
			result string
			err    error
		}{result, err}
	}()

	select {
	case r := <-ch:
		return r.result, r.err
	case <-ctx.Done():
		return "", apperrors.ErrTimeout
	}
}
