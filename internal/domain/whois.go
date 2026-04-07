package domain

import "time"

type WhoisInfoList struct {
	IsError   bool       `json:"is_error"`
	ErrorCode string     `json:"error_code,omitempty"`
	Message   string     `json:"message,omitempty"`
	Whois     *WhoisInfo `json:"whois"`
}

type WhoisInfo struct {
	Domain         *WhoisDomain  `json:"domain"`
	Registrar      *WhoisContact `json:"registrar"`
	Registrant     *WhoisContact `json:"registrant"`
	Administrative *WhoisContact `json:"administrative"`
	Technical      *WhoisContact `json:"technical"`
	Billing        *WhoisContact `json:"billing"`
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
	ID           string `json:"id,"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Street       string `json:"street,"`
	City         string `json:"city,"`
	Province     string `json:"province,"`
	PostalCode   string `json:"postal_code,"`
	Country      string `json:"country,"`
	Phone        string `json:"phone,"`
	PhoneExt     string `json:"phone_ext,"`
	Fax          string `json:"fax,"`
	FaxExt       string `json:"fax_ext,"`
	Email        string `json:"email,"`
	ReferralURL  string `json:"referral_url,"`
}
