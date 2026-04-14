package llm

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"whois-api-lambda/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maskAPIKey masks the API key for logging
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}

// TestLoadSchema tests that the embedded schema can be loaded
func TestLoadSchema(t *testing.T) {
	schema, err := loadSchema()
	assert.NoError(t, err)
	assert.NotEmpty(t, schema)
	assert.Contains(t, schema, `"$schema"`)
	assert.Contains(t, schema, `"title": "WHOIS JSON Schema"`)
}

// TestParseWhoisData tests the JSON unmarshalling for WHOIS info structure
func TestParseWhoisData(t *testing.T) {
	// Expected JSON response from LLM based on dummy WHOIS data
	expectedJSON := `{
  "domain": {
    "id": "2336799_DOMAIN_COM-VRSN",
    "domain": "example.com",
    "punycode": "",
    "name": "example",
    "extension": "com",
    "whois_server": "whois.registrar.example",
    "status": ["clientTransferProhibited"],
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "dnssec": false,
    "created_at": "1995-08-14T04:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z",
    "expires_at": "2024-08-13T04:00:00Z"
  },
  "registrar": {
    "id": "1234",
    "name": "Example Registrar, Inc.",
    "organization": "",
    "street": "",
    "city": "",
    "province": "",
    "postal_code": "",
    "country": "",
    "phone": "+1.1234567890",
    "phone_ext": "",
    "fax": "",
    "fax_ext": "",
    "email": "abuse@example.com",
    "referral_url": "http://www.example.com"
  },
  "registrant": null,
  "administrative": null,
  "technical": null,
  "billing": null
}`

	// Test the JSON unmarshalling
	var whoisInfo domain.WhoisInfo
	err := json.Unmarshal([]byte(expectedJSON), &whoisInfo)
	assert.NoError(t, err)
	assert.NotNil(t, whoisInfo.Domain)
	assert.Equal(t, "example.com", whoisInfo.Domain.Domain)
	assert.Equal(t, []string{"ns1.example.com", "ns2.example.com"}, whoisInfo.Domain.NameServers)
	assert.Equal(t, false, whoisInfo.Domain.DNSSec)

	// Check dates
	expectedCreated, _ := time.Parse(time.RFC3339, "1995-08-14T04:00:00Z")
	assert.Equal(t, expectedCreated, whoisInfo.Domain.CreatedAt.Time)

	// Check registrar
	assert.NotNil(t, whoisInfo.Registrar)
	assert.Equal(t, "1234", whoisInfo.Registrar.ID)
	assert.Equal(t, "Example Registrar, Inc.", whoisInfo.Registrar.Name)
	assert.Equal(t, "abuse@example.com", whoisInfo.Registrar.Email)
}

// TestParseWhoisDataIntegration tests the full Parse method with dummy WHOIS data
// This test requires OPENROUTER_API_KEY to be set
func TestParseWhoisDataIntegration(t *testing.T) {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	t.Logf("API Key after loading: %s (length: %d)", maskAPIKey(apiKey), len(apiKey))
	if apiKey == "" {
		t.Skip("OPENROUTER_API_KEY not set in .env.test, skipping integration test")
	}

	parser := NewOpenRouterLLMParser(apiKey)

	// Dummy WHOIS data
	whoisData := `
Domain Name: claude.ai
Registry Domain ID: be3cad9a48374aa88e0259e019d4270d-DONUTS
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2025-01-17T19:25:43Z
Creation Date: 2018-08-04T15:48:43Z
Registry Expiry Date: 2029-08-04T15:48:44Z
Registrar: MarkMonitor Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Registry Registrant ID: 3c75800c8cc9471ea43e70fe86c91bad-DONUTS
Registrant Name: Domain Administrator
Registrant Organization: Anthropic PBC
Registrant Street: 548 Market St PMB 90375
Registrant City: San Francisco
Registrant State/Province: CA
Registrant Postal Code: 94104
Registrant Country: US
Registrant Phone: +1.4153266303
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: domains@anthropic.com
Registry Admin ID: 3c75800c8cc9471ea43e70fe86c91bad-DONUTS
Admin Name: Domain Administrator
Admin Organization: Anthropic PBC
Admin Street: 548 Market St PMB 90375
Admin City: San Francisco
Admin State/Province: CA
Admin Postal Code: 94104
Admin Country: US
Admin Phone: +1.4153266303
Admin Phone Ext: 
Admin Fax: 
Admin Fax Ext: 
Admin Email: domains@anthropic.com
Registry Tech ID: 3c75800c8cc9471ea43e70fe86c91bad-DONUTS
Tech Name: Domain Administrator
Tech Organization: Anthropic PBC
Tech Street: 548 Market St PMB 90375
Tech City: San Francisco
Tech State/Province: CA
Tech Postal Code: 94104
Tech Country: US
Tech Phone: +1.4153266303
Tech Phone Ext: 
Tech Fax: 
Tech Fax Ext: 
Tech Email: domains@anthropic.com
Name Server: isla.ns.cloudflare.com
Name Server: randy.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://icann.org/wicf/
>>> Last update of WHOIS database: 2026-04-05T19:28:29Z <<<
`

	// Call Parse
	ctx := context.Background()
	whoisInfo, err := parser.Parse(ctx, whoisData, "claude.ai")

	// Assert no error
	assert.NoError(t, err)
	assert.NotNil(t, whoisInfo)
	require.NotNil(t, whoisInfo)

	jsonResp, _ := json.MarshalIndent(whoisInfo, "", "  ")
	t.Log(string(jsonResp))

	// Basic checks - the LLM should extract key information
	// Note: Exact values depend on LLM interpretation
	if whoisInfo.Domain != nil {
		assert.Equal(t, "claude.ai", whoisInfo.Domain.Domain)
	}

	if whoisInfo.Registrar != nil {
		assert.Contains(t, whoisInfo.Registrar.Name, "MarkMonitor")
	}
}
