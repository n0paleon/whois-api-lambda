package core

import (
	"errors"
	"net/url"
	"strings"
	"unicode"

	"math/rand/v2"

	"github.com/bombsimon/tld-validator"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

func ParseRootDomain(q string) (string, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	rootDomain, err := publicsuffix.Domain(q)
	if err == nil {
		if !tld.FromDomainName(rootDomain).IsValid() {
			return "", errors.New("unsupported TLD")
		}
		return rootDomain, nil
	}

	parsedURL, err := url.Parse("https://" + q)
	if err != nil {
		return "", errors.New("invalid domain name")
	}

	hostParts := strings.Split(parsedURL.Hostname(), ".")
	if len(hostParts) < 2 {
		return "", errors.New("invalid domain name")
	}

	rootDomain = strings.Join(hostParts[len(hostParts)-2:], ".")
	if !tld.FromDomainName(rootDomain).IsValid() {
		return "", errors.New("unsupported TLD")
	}

	return rootDomain, nil
}

func IsValidDomain(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}

	for i, c := range name {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-') {
			return false // Jika ada karakter ilegal
		}
		if (i == 0 || i == len(name)-1) && c == '-' {
			return false // Tidak boleh diawali atau diakhiri dengan "-"
		}
	}
	return true
}

func RandomInRange(min, max int) int {
	if min > max {
		min, max = max, min
	}
	return min + rand.IntN(max-min+1)
}
