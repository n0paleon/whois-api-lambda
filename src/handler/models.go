package handler

import "whois-api-lambda/core"

type SingleWhoisLookup struct {
	Domain string `json:"domain"`
}

type MassWhoisLookup struct {
	Domain []string `json:"domain"`
}

type MassDomainQueryResponse struct {
	Error      bool            `json:"error"`
	Message    string          `json:"message"`
	DomainName string          `json:"domain_name"`
	WhoisData  *core.WhoisData `json:"whois"`
}
