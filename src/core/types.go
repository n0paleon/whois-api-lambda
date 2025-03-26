package core

import (
	"context"
	"time"
)

type APIResponse struct {
	Data    any    `json:"data"`
	Error   bool   `json:"error"`
	Message string `json:"message"`
}

type MassWhoisData struct {
	Data       *WhoisData `json:"data"`
	DomainName string     `json:"domain_name"`
	Error      error      `json:"error"`
}

type TLD struct {
	RootTLD          string   `json:"root_tld"`
	SubTLD           []string `json:"sub_tld"`
	RegistryOperator string   `json:"registry_operator"`
	InfoURL          string   `json:"info_url"`
	Tags             []string `json:"tags"`
}

type WhoisData struct {
	Domain     *WhoisDomain  `json:"domain"`
	Registrar  *WhoisContact `json:"registrar"`
	Registrant *WhoisContact `json:"registrant"`
}

type WhoisDomain struct {
	ID          string     `json:"id"`
	Domain      string     `json:"domain"`
	Punycode    string     `json:"punycode"`
	Name        string     `json:"name"`
	Extension   string     `json:"extension"`
	WhoisServer string     `json:"whois_server"`
	Status      []string   `json:"status"`
	NameServers []string   `json:"name_servers"`
	DNSSec      bool       `json:"dnssec"`
	CreatedAt   *time.Time `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type WhoisContact struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Street       string `json:"street"`
	City         string `json:"city"`
	Province     string `json:"province"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
	Phone        string `json:"phone"`
	Fax          string `json:"fax"`
	Email        string `json:"email"`
	ReferralURL  string `json:"referral_url"`
}

type Whois interface {
	GetAvailableTLDs() []*TLD
	GetWhoisData(ctx context.Context, query string) (*WhoisData, error)
	GetRawWhoisData(ctx context.Context, query string) ([]byte, error)
	MassWhoisLookup(ctx context.Context, queries []string) ([]*MassWhoisData, error)
}
