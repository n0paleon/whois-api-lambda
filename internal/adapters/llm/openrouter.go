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

	// Check for invalid domain indicators in WHOIS data
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

	schema, err := loadSchema()
	if err != nil {
		return nil, fmt.Errorf("failed to load schema: %v", err)
	}

	native, punycode := utils.GetDomainFormats(targetDomain)

	request := openrouter.ChatCompletionRequest{
		Model: "mistralai/devstral-small",
		Messages: []openrouter.ChatCompletionMessage{
			{
				Role: openrouter.ChatMessageRoleSystem,
				Content: openrouter.Content{Text: fmt.Sprintf(`You are a professional WHOIS parser.
                EXTRACT data from the user input and return ONLY a JSON object.
                STRICT ADHERENCE REQUIRED: The output must strictly follow this JSON Schema:
                %s

                RULES:
                1. Do not add any fields not defined in the schema.
                2. Respect the 'required', 'nullable', and 'type' constraints.
                3. If a value is missing but required, use a sensible default (empty string/null).
				4. Strictly use RFC3339 format for all date-time fields (e.g., 2006-01-02T15:04:05Z or 2006-01-02T15:04:05+00:00). Never omit the colon in the timezone offset.
				5. The "registrar," "registrant," "administrative," "technical," and "billing" fields should be null if there is no associated data at all.
				6. If the WHOIS data indicates the domain does not exist, is invalid, or no valid information is found, set the "domain" field to null.
				7. domain.domain: Full domain name in its original Unicode/Native character (e.g., 测试.com, google.com, wikipedia.org, etc).
				8. domain.punycode: Full domain name in Punycode format (e.g., XN--0ZWM56D.COM).
				9. domain.name: The label part ONLY (without extension) in Unicode/Native character (e.g., 测试).
				10. domain.extension: The TLD part ONLY (e.g., com).
				11. IDN Decoding: If the input is in Punycode (xn--), you MUST decode it to its native Unicode representation for the domain.domain and domain.name fields.
				12. TARGET FOCUS: Your primary task is to extract data for the SPECIFIC domain provided in the User Message. DO NOT return Registry Operator metadata.
                13. HIERARCHY: If there are multiple WHOIS blocks, prioritize the "Registrar" or "Registrant" block of the domain over the "Registry" metadata block.
                14. FORCED DECODING: You MUST decode Punycode (xn--) into native characters. Example: xn--l8yt8m.jp MUST be converted to 総務省.jp in the 'domain.domain' field.
				`, schema)},
			},
			{
				Role: openrouter.ChatMessageRoleUser,
				Content: openrouter.Content{Text: fmt.Sprintf(`
					TARGET DOMAIN (NATIVE): %s
					TARGET DOMAIN (PUNYCODE): %s
					RAW WHOIS DATA:
					%s
					`,
					native, punycode, whoisData,
				)},
			},
		},
		ResponseFormat: &openrouter.ChatCompletionResponseFormat{
			Type: openrouter.ChatCompletionResponseFormatTypeJSONObject,
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

	content := resp.Choices[0].Message.Content
	var whoisInfo domain.WhoisInfo
	contentStr := content.Text

	unmarshalStart := time.Now()
	if err := json.Unmarshal([]byte(contentStr), &whoisInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	logrus.Infof("JSON unmarshal took: %v", time.Since(unmarshalStart))

	if whoisInfo.Domain == nil {
		return nil, apperrors.ErrDomainNotFound
	}

	logrus.Infof("Total Parse function took: %v", time.Since(start))
	return &whoisInfo, nil
}
