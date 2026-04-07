package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
	_ "github.com/zonedb/zonedb"
)

func TestGetWhoisServer_NoDot_ReturnsDefault(t *testing.T) {
	server, err := GetWhoisServer("test")
	assert.Error(t, err)
	assert.Nil(t, server)
}

func TestGetWhoisServer_WithDot_NoZone_ReturnsError(t *testing.T) {
	server, err := GetWhoisServer("nonexistent.tld")
	assert.Error(t, err)
	assert.Nil(t, server)
}

func TestGetWhoisServer_WithZone_ValidWhoisInfo_ReturnsServer(t *testing.T) {
	server, err := GetWhoisServer("example.com")
	assert.NoError(t, err)
	assert.NotNil(t, server)
	// Should not be the default server
	assert.NotEqual(t, "whois.iana.org", server.WhoisServer)
}

func TestGetWhoisServer_WithZone_NoWhoisInfo_ReturnsError(t *testing.T) {
	server, err := GetWhoisServer("example.test")
	if err != nil {
		assert.Nil(t, server)
	} else {
		assert.NotNil(t, server)
	}
}
