package llm

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"whois-api-lambda/internal/adapters/whois"
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

	targetDomain := "microsoft.com"

	parser := NewOpenRouterLLMParser(apiKey)

	// Fetch real WHOIS data using the native client
	whoisClient := whois.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	whoisData, err := whoisClient.Whois(ctx, targetDomain)
	require.NoError(t, err)
	assert.NotEmpty(t, whoisData)

	// Call Parse
	whoisInfo, err := parser.Parse(ctx, whoisData, targetDomain)

	// Assert no error
	assert.NoError(t, err)
	assert.NotNil(t, whoisInfo)
	require.NotNil(t, whoisInfo)

	jsonResp, _ := json.MarshalIndent(whoisInfo, "", "  ")
	t.Log(string(jsonResp))

	// Basic checks - the LLM should extract key information
	// Note: Exact values depend on LLM interpretation
	if whoisInfo.Domain != nil {
		assert.Equal(t, targetDomain, whoisInfo.Domain.Domain)
	}

	if whoisInfo.Registrar != nil {
		registrarNameNOrg := whoisInfo.Registrar.Name + "\n" + whoisInfo.Registrar.Organization
		assert.Contains(t, registrarNameNOrg, "MarkMonitor")
	}
}
