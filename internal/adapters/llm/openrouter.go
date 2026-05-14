package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"whois-api-lambda/internal/apperrors"
	"whois-api-lambda/internal/domain"
	"whois-api-lambda/pkg/utils"

	"github.com/goccy/go-json"
	"github.com/revrost/go-openrouter"
	"github.com/sirupsen/logrus"
)

// notFoundPhrases adalah frasa yang menandakan domain tidak terdaftar.
var notFoundPhrases = []string{
	"no match",
	"not found",
	"domain not found",
	"no entries found",
	"no information available",
	"is available for registration",
	"no data found",
}

// redundantLinePatterns mendeteksi baris yang tidak mengandung data bermakna.
var redundantLinePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(>>>|#|%|;;)`),                           // komentar/delimiter umum
	regexp.MustCompile(`(?i)^(NOTICE|TERMS OF USE|URL OF THE ICANN)`), // legal boilerplate
	regexp.MustCompile(`(?i)^(For more information|Please note|IMPORTANT)`),
	regexp.MustCompile(`(?i)^(Last update|last updated).*(whois database)`), // footer registry
}

// trimWhoisData membersihkan raw WHOIS dari baris tidak relevan:
// - baris kosong berurutan
// - komentar, legal boilerplate, footer
// - baris yang hanya berisi whitespace
func trimWhoisData(raw string) string {
	lines := strings.Split(raw, "\n")
	result := make([]string, 0, len(lines))
	prevBlank := false

	for _, line := range lines {
		trimmed := strings.TrimRightFunc(line, unicode.IsSpace)

		// Hapus baris yang hanya whitespace (blank line dedup)
		if trimmed == "" {
			if !prevBlank {
				result = append(result, "")
			}
			prevBlank = true
			continue
		}
		prevBlank = false

		// Hapus baris yang cocok dengan pola redundan
		skip := false
		for _, re := range redundantLinePatterns {
			if re.MatchString(trimmed) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		result = append(result, trimmed)
	}

	// Trim blank lines di awal dan akhir
	cleaned := strings.Join(result, "\n")
	return strings.TrimSpace(cleaned)
}

type OpenRouterLLMParser struct {
	apiKey string
}

func NewOpenRouterLLMParser(apiKey string) *OpenRouterLLMParser {
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}
	return &OpenRouterLLMParser{apiKey: apiKey}
}

func (p *OpenRouterLLMParser) Parse(ctx context.Context, whoisData string, targetDomain string) (*domain.WhoisInfo, error) {
	start := time.Now()

	// 1. Cek domain tidak ditemukan sebelum trimming
	lowerData := strings.ToLower(whoisData)
	for _, phrase := range notFoundPhrases {
		if strings.Contains(lowerData, phrase) {
			return nil, apperrors.ErrDomainNotFound
		}
	}

	// 2. Trim WHOIS data dari noise
	cleanedWhois := trimWhoisData(whoisData)
	if cleanedWhois == "" {
		return nil, apperrors.ErrDomainNotFound
	}

	// 3. Setup client & schema
	client := openrouter.NewClient(
		p.apiKey,
		openrouter.WithXTitle("Whois API Lambda - Parse Whois Response"),
	)

	native, punycode := utils.GetDomainFormats(targetDomain)
	whoisSchema := BuildWhoisSchema()

	request := openrouter.ChatCompletionRequest{
		Model: "mistralai/devstral-small",
		Models: []string{
			"deepseek/deepseek-v4-flash",
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
				Content: openrouter.Content{Text: systemPrompt},
			},
			{
				Role: openrouter.ChatMessageRoleUser,
				Content: openrouter.Content{Text: buildUserPrompt(native, punycode, cleanedWhois)},
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

	// 4. Panggil API
	apiStart := time.Now()
	resp, err := client.CreateChatCompletion(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("openrouter API error: %w", err)
	}
	logrus.Infof("OpenRouter API call took: %v", time.Since(apiStart))

	if len(resp.Choices) == 0 {
		return nil, errors.New("no response from LLM")
	}

	contentStr := resp.Choices[0].Message.Content.Text

	// 5. Unmarshal
	unmarshalStart := time.Now()
	var whoisInfo domain.WhoisInfo
	if err := json.Unmarshal([]byte(contentStr), &whoisInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w\ncontent: %s", err, contentStr)
	}
	logrus.Infof("JSON unmarshal took: %v", time.Since(unmarshalStart))

	// 6. Collapse empty contacts
	whoisInfo.Registrar = nilIfEmpty(whoisInfo.Registrar)
	whoisInfo.Registrant = nilIfEmpty(whoisInfo.Registrant)
	whoisInfo.Administrative = nilIfEmpty(whoisInfo.Administrative)
	whoisInfo.Technical = nilIfEmpty(whoisInfo.Technical)
	whoisInfo.Billing = nilIfEmpty(whoisInfo.Billing)

	if whoisInfo.Domain == nil {
		return nil, apperrors.ErrDomainNotFound
	}

	logrus.Infof("Total Parse function took: %v", time.Since(start))
	return &whoisInfo, nil
}

// nilIfEmpty adalah wrapper generik untuk menggantikan isContactEmpty per-tipe.
// Karena Go generics butuh constraint interface, pakai helper per-tipe atau
// gunakan fungsi isContactEmpty yang sudah ada dan rename jadi nilIfEmpty.
func nilIfEmpty(c *domain.WhoisContact) *domain.WhoisContact {
	if c.IsEmpty() {
		return nil
	}
	return c
}

// buildUserPrompt membangun user message secara terpisah agar mudah di-test/modifikasi.
func buildUserPrompt(native, punycode, whoisData string) string {
	return fmt.Sprintf(
		"Target domain: %s (Punycode: %s)\n\nRaw WHOIS:\n%s",
		native, punycode, whoisData,
	)
}

// systemPrompt dipisahkan sebagai konstanta agar tidak polusi di dalam fungsi Parse.
const systemPrompt = `You are a WHOIS data parser. Extract data from the input and return ONLY a valid JSON object matching the schema below. No explanation. No markdown. No extra text outside the JSON.

---

## CONTACT ROLE ISOLATION (CRITICAL)

Each contact role is COMPLETELY INDEPENDENT. Never copy or infer data between roles.

Role detection — only extract a role if these EXACT prefixes exist in the raw input:
- ` + "`registrant`" + `     → lines starting with: ` + "`Registrant Name:`" + `, ` + "`Registrant Org:`" + `, ` + "`Registrant Email:`" + `, etc.
- ` + "`administrative`" + ` → lines starting with: ` + "`Admin Name:`" + `, ` + "`Admin Email:`" + `, etc.
- ` + "`technical`" + `      → lines starting with: ` + "`Tech Name:`" + `, ` + "`Tech Email:`" + `, etc.
- ` + "`billing`" + `        → lines starting with: ` + "`Billing Name:`" + `, ` + "`Billing Email:`" + `, etc.
- ` + "`registrar`" + `      → lines starting with: ` + "`Registrar:`" + `, ` + "`Sponsoring Registrar:`" + `, ` + "`Registrar IANA ID:`" + `, etc.

If a role has NO matching lines in the raw input → set it to null.
If a role exists but ALL fields are null or empty string → collapse to null.

---

## FIELD MAPPING PER ROLE

| JSON Field   | WHOIS Source Field Example                                      |
|--------------|-----------------------------------------------------------------|
| id           | Registrant IANA ID / Admin ID / Tech ID                        |
| name         | Registrant Name / Admin Name / Tech Name                       |
| organization | Registrant Organization / Admin Organization                    |
| street       | Registrant Street / Admin Street (join multi-line with ", ")   |
| city         | Registrant City / Admin City                                   |
| province     | Registrant State/Province / Admin State/Province               |
| postal_code  | Registrant Postal Code                                         |
| country      | Registrant Country                                             |
| phone        | Registrant Phone (digits and + only, no ext)                   |
| phone_ext    | Registrant Phone Ext                                           |
| fax          | Registrant Fax (digits and + only, no ext)                     |
| fax_ext      | Registrant Fax Ext                                             |
| email        | Registrant Email                                               |
| referral_url | Registrar URL / Registrant URL                                 |

For registrar specifically:
- id → Registrar IANA ID
- referral_url → Registrar URL

---

## DOMAIN RULES

- domain → Full domain in Unicode (decode Punycode). e.g. google.com, 测试.com
- punycode → Full domain in ASCII. e.g. google.com, xn--0zwm56d.com
- name → Label only, no TLD, in Unicode. e.g. google
- extension → TLD only. e.g. com, ai, id
- dnssec → boolean: true if signedDelegation or yes; false if unsigned or no
- whois_server → Registrar WHOIS Server
- id → Registry Domain ID
- status → array of all Domain Status values
- name_servers → array of all Name Server values, lowercased

If domain does not exist, is invalid, has no created_at, or no valid info found → set "domain": null.

---

## DATE FORMAT

All date-time fields MUST use RFC3339: 2006-01-02T15:04:05Z or 2006-01-02T15:04:05+00:00.
Never omit the colon in timezone offset. Never use other formats.

---

## REQUIRED FIELDS BEHAVIOR

All required fields must be present. If no value found in raw WHOIS → output as null.
Do NOT omit required fields. Do NOT add fields not in the schema.

---

## HIERARCHY RULE

Prioritize Registrar or Registrant block over Registry metadata.
Do NOT extract Registry Operator info as registrar/registrant/admin/tech/billing.

---

## SELF-CHECK BEFORE OUTPUT

1. Did I set any role to null that had no matching lines? ✓
2. Did I copy any field from one role to another? ✗ (not allowed)
3. Are all dates RFC3339 with colon in offset? ✓
4. Are all required fields present (even if null)? ✓
5. Is output pure JSON with no extra text? ✓`