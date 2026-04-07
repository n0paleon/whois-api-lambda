package whois

import "net/url"

type WhoisServer struct {
	WhoisServer string
	WhoisURL    string
}

func (s *WhoisServer) GetWhoisServerHost() string {
	if s.WhoisServer != "" {
		return s.WhoisServer
	}

	if s.WhoisURL != "" {
		u, err := url.Parse(s.WhoisURL)
		if err != nil {
			return IANA
		}
		return u.Host
	}

	return IANA
}

type resultChan struct {
	result string
	err    error
}
