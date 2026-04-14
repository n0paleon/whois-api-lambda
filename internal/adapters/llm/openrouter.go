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
        Model: "mistralai/devstral-small",
        Messages: []openrouter.ChatCompletionMessage{
            {
                Role: openrouter.ChatMessageRoleSystem,
                Content: openrouter.Content{Text: `
You are a professional WHOIS data parser.
Extract WHOIS data from the user input and return ONLY a structured JSON object.

CONTACT ROLE DEFINITIONS:
- "registrar": The accredited company/organization through which the domain was registered (e.g., GoDaddy, Namecheap, MarkMonitor, SpaceShip).
- "registrant": The person or organization that owns/registered the domain. May appear as "Registrant", "Owner", "Registrant Contact", "[Registrant]", "contact: registrant", etc.
- "administrative": The contact responsible for administrative decisions about the domain. May appear as "Admin", "Administrative Contact", "[Admin-C]", "contact: administrative", etc.
- "technical": The contact responsible for technical/DNS management. May appear as "Tech", "Technical Contact", "[Tech-C]", "contact: technical", etc.
- "billing": The contact responsible for billing. May appear as "Billing", "Billing Contact", "[Billing-C]", etc.

RULES:
1. If input is Punycode (xn--), decode it to native Unicode for domain.domain and domain.name fields.
2. TARGET FOCUS: Extract data for the SPECIFIC domain in the user message. DO NOT return Registry Operator or TLD metadata.
3. HIERARCHY: If multiple WHOIS blocks exist, prioritize the Registrar/Registrant block over the Registry metadata block.
4. WHOIS formats vary by registry — use semantic understanding to identify contact roles, not just prefix matching.
5. The “registry,” “registrant,” “administrative,” “technical,” and “billing” properties may only be null if none of the required fields in the contact schema have valid values
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

    if whoisInfo.Domain == nil {
        return nil, apperrors.ErrDomainNotFound
    }

    logrus.Infof("Total Parse function took: %v", time.Since(start))
    return &whoisInfo, nil
}