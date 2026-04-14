package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"whois-api-lambda/internal/apperrors"
	"whois-api-lambda/internal/domain"
	"whois-api-lambda/pkg/utils"

	"github.com/goccy/go-json"
	"github.com/revrost/go-openrouter"
	"github.com/sirupsen/logrus"
)

type OpenRouterLLMParser struct {
	apiKey string
}

func NewOpenRouterLLMParser(apiKey string) *OpenRouterLLMParser {
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}
	return &OpenRouterLLMParser{
		apiKey: apiKey,
	}
}

func (p *OpenRouterLLMParser) Parse(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error) {
	start := time.Now()

	lowerData := strings.ToLower(whoisData)
	if strings.Contains(lowerData, "no match") ||
		strings.Contains(lowerData, "not found") ||
		strings.Contains(lowerData, "domain not found") ||
		strings.Contains(lowerData, "no entries found") ||
		strings.Contains(lowerData, "no information available") ||
		strings.Contains(lowerData, "is available for registration") ||
		strings.Contains(lowerData, "no data found") {
		return nil, apperrors.ErrDomainNotFound
	}

	client := openrouter.NewClient(
		p.apiKey,
		openrouter.WithXTitle("Whois API Lambda - Parse Whois Response"),
	)

	native, punycode := utils.GetDomainFormats(targetDomain)
	whoisSchema := BuildWhoisSchema()

	request := openrouter.ChatCompletionRequest{
		Model: "google/gemini-2.5-flash-lite",
		Models: []string{
			"mistralai/devstral-small",
		},
		Provider: &openrouter.ChatProvider{
			Sort:              openrouter.ProviderSortingThroughput,
			RequireParameters: true,
			AllowFallbacks:    utils.Ptr(true),
		},
		MaxTokens:   8000,
		Temperature: 0.2,
		Messages: []openrouter.ChatCompletionMessage{
			{
				Role: openrouter.ChatMessageRoleSystem,
				Content: openrouter.Content{Text: `
You are an expert WHOIS data parser.
EXTRACT data from the user input and return ONLY a JSON object.

CRITICAL RULES FOR CONTACT EXTRACTION (READ CAREFULLY):
1. ZERO DATA LEAKAGE: You MUST NOT copy, share, or assume data between different contact roles. If the raw data only provides an "Admin" contact, you MUST NOT use that data to fill in "Registrant", "Tech", or "Billing". Treat each contact role as completely independent.
2. STRICT NULL FOR MISSING ROLES: If the raw WHOIS data does not contain explicit fields for a specific role (e.g., if there are no lines starting with "Tech " or "Billing "), you MUST set that top-level contact property exactly to "null".
3. COLLAPSE EMPTY OBJECTS: Before finalizing the JSON, verify every contact object. If a contact object exists but ALL of its extracted child properties are null or empty strings, you MUST collapse it and set the top-level property to "null" (e.g., "billing": null, NOT "billing": {"name": null, "email": null}).

GENERAL EXTRACTION RULES:
1. Schema Limits: Do not add any fields not defined in the schema. Respect 'required', 'nullable', and 'type' constraints. 
2. Mandatory Fields: Always include ALL top-level fields (domain, registrar, registrant, administrative, technical, billing) in the root JSON object, setting them to "null" if criteria from the critical rules apply.
3. Date-Time Formatting: Strictly use RFC3339 format (e.g., 2006-01-02T15:04:05Z or 2006-01-02T15:04:05+00:00). Never omit the colon in the timezone offset.
4. Contact Identification:
   - Registrar: Look for "Registrar:" or "Sponsoring Registrar:".
   - Registrant: Look for "Registrant Name:", "Registrant Organization:", etc.
   - Administrative: Look for "Admin Name:", "Administrative Contact", etc.
   - Technical: Look for "Tech Name:", "Technical Contact", etc.
   - Billing: Look for "Billing Name:", "Billing Contact", etc.
 5. Domain Parsing & IDN:
    - domain.domain: The full domain name, including the extension, in Unicode/native character format (e.g., google.com, 测试.com). YOU MUST decode Punycode (e.g., xn--...) to native.
    - domain.punycode: The full domain name in Punycode format (ASCII only, no Unicode characters allowed, e.g., xn--fsq.xn--0zwm56d, google.com, claude.ai, oxylabs.com, calculator.aws).
    - domain.name: The label part ONLY (without extension) in Unicode/Native character.
    - domain.extension: The TLD part ONLY.
 6. Domain Existence: If the WHOIS data indicates the domain does not exist, is invalid, no valid information is found, or no creation date is found, set the top-level "domain" field to "null".
7. Hierarchy Priority: Prioritize the "Registrar" or "Registrant" block of the domain over any "Registry" metadata block. DO NOT extract Registry Operator metadata as contacts.
				`},
			},
			{
				Role: openrouter.ChatMessageRoleUser,
				Content: openrouter.Content{Text: fmt.Sprintf(`
Extract this raw WHOIS response into the desired format.

Target domain (native): %s
Target domain (Punycode): %s
Raw WHOIS data:
%s`, native, punycode, whoisData)},
			},
		},
		ResponseFormat: &openrouter.ChatCompletionResponseFormat{
			Type: openrouter.ChatCompletionResponseFormatTypeJSONSchema,
			JSONSchema: &openrouter.ChatCompletionResponseFormatJSONSchema{
				Name:        "whois_response",
				Schema:      whoisSchema,
				Description: "Structured WHOIS data",
				Strict:      true,
			},
		},
	}

	apiStart := time.Now()
	resp, err := client.CreateChatCompletion(ctx, request)
	if err != nil {
		return nil, err
	}
	logrus.Infof("OpenRouter API call took: %v", time.Since(apiStart))

	if len(resp.Choices) == 0 {
		return nil, errors.New("no response from LLM")
	}

	contentStr := resp.Choices[0].Message.Content.Text

	unmarshalStart := time.Now()
	var whoisInfo domain.WhoisInfo
	if err := json.Unmarshal([]byte(contentStr), &whoisInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v\ncontent: %s", err, contentStr)
	}
	logrus.Infof("JSON unmarshal took: %v", time.Since(unmarshalStart))

	// Filter out empty contacts
	if isContactEmpty(whoisInfo.Registrar) {
		whoisInfo.Registrar = nil
	}
	if isContactEmpty(whoisInfo.Registrant) {
		whoisInfo.Registrant = nil
	}
	if isContactEmpty(whoisInfo.Administrative) {
		whoisInfo.Administrative = nil
	}
	if isContactEmpty(whoisInfo.Technical) {
		whoisInfo.Technical = nil
	}
	if isContactEmpty(whoisInfo.Billing) {
		whoisInfo.Billing = nil
	}

	if whoisInfo.Domain == nil {
		return nil, apperrors.ErrDomainNotFound
	}

	logrus.Infof("Total Parse function took: %v", time.Since(start))
	return &whoisInfo, nil
}
