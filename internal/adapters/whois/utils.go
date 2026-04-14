package whois

import (
	"net/http"
	"strings"
	"whois-api-lambda/internal/apperrors"

	"github.com/zonedb/zonedb"
)

var defaultWhoisServer = WhoisServer{
	WhoisServer: IANA,
	WhoisURL:    "",
}

func GetWhoisServer(query string) (*WhoisServer, error) {
	if !strings.Contains(query, ".") {
		return nil, apperrors.Newf(apperrors.CodeInvalidDomain, http.StatusBadRequest, "invalid domain name: %s", query)
	}

	z := zonedb.PublicZone(query)
	if z == nil {
		return nil, apperrors.Newf(apperrors.CodeNoValidPublicZone, http.StatusBadRequest, "no valid public zone found for %s", query)
	}

	if z.WhoisServer() == "" && z.WhoisURL() == "" {
		return &defaultWhoisServer, nil
	}

	return &WhoisServer{
		WhoisServer: z.WhoisServer(),
		WhoisURL:    z.WhoisURL(),
	}, nil
}
