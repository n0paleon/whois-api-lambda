package llm

import "github.com/revrost/go-openrouter/jsonschema"

var contactProperties = map[string]jsonschema.Definition{
	"id":           {Type: jsonschema.String, Nullable: true},
	"name":         {Type: jsonschema.String, Nullable: true},
	"organization": {Type: jsonschema.String, Nullable: true},
	"street":       {Type: jsonschema.String, Nullable: true},
	"city":         {Type: jsonschema.String, Nullable: true},
	"province":     {Type: jsonschema.String, Nullable: true},
	"postal_code":  {Type: jsonschema.String, Nullable: true},
	"country":      {Type: jsonschema.String, Nullable: true},
	"phone":        {Type: jsonschema.String, Nullable: true},
	"phone_ext":    {Type: jsonschema.String, Nullable: true},
	"fax":          {Type: jsonschema.String, Nullable: true},
	"fax_ext":      {Type: jsonschema.String, Nullable: true},
	"email":        {Type: jsonschema.String, Nullable: true},
	"referral_url": {Type: jsonschema.String, Nullable: true},
}
var contactRequired = []string{"id", "name", "organization", "street", "city", "province", "postal_code", "country", "phone", "phone_ext", "fax", "fax_ext", "email", "referral_url"}

func BuildWhoisSchema() *jsonschema.Definition {
	return &jsonschema.Definition{
		Type: jsonschema.Object,
		Properties: map[string]jsonschema.Definition{
			"domain": {
				Type:        jsonschema.Object,
				Nullable:    true,
				Description: "Set to null if domain does not exist or no valid information found",
				Properties: map[string]jsonschema.Definition{
					"id":           {Type: jsonschema.String, Nullable: true},
					"domain":       {Type: jsonschema.String, Nullable: true, Description: "Full domain name in Unicode/Native character (decode Punycode if present)"},
					"punycode":     {Type: jsonschema.String, Nullable: true, Description: "Full domain name in Punycode format"},
					"name":         {Type: jsonschema.String, Nullable: true, Description: "The label part only (without extension) in Unicode/Native character"},
					"extension":    {Type: jsonschema.String, Nullable: true, Description: "The TLD part only"},
					"whois_server": {Type: jsonschema.String, Nullable: true},
					"status": {
						Type:     jsonschema.Array,
						Nullable: true,
						Items:    &jsonschema.Definition{Type: jsonschema.String},
					},
					"name_servers": {
						Type:     jsonschema.Array,
						Nullable: true,
						Items:    &jsonschema.Definition{Type: jsonschema.String},
					},
					"dnssec":     {Type: jsonschema.Boolean, Nullable: true},
					"created_at": {Type: jsonschema.String, Nullable: true, Description: "RFC3339 format (e.g., 2006-01-02T15:04:05Z), never omit colon in timezone offset"},
					"updated_at": {Type: jsonschema.String, Nullable: true, Description: "RFC3339 format (e.g., 2006-01-02T15:04:05Z), never omit colon in timezone offset"},
					"expires_at": {Type: jsonschema.String, Nullable: true, Description: "RFC3339 format (e.g., 2006-01-02T15:04:05Z), never omit colon in timezone offset"},
				},
				Required: []string{
					"id", "domain", "punycode", "name", "extension",
					"whois_server", "status", "name_servers", "dnssec",
					"created_at", "updated_at", "expires_at",
				},
				AdditionalProperties: false,
			},
			"registrar": {
				Type:                 jsonschema.Object,
				Nullable:             true,
				Description:          `"registrar": The accredited company/organization through which the domain was registered (e.g., GoDaddy, Namecheap, MarkMonitor, SpaceShip).`,
				Properties:           contactProperties,
				Required:             contactRequired,
				AdditionalProperties: false,
			},
			"registrant": {
				Type:                 jsonschema.Object,
				Nullable:             true,
				Description:          `"registrant": The person or organization that owns/registered the domain. May appear as "Registrant", "Owner", "Registrant Contact", "Registrant Organization", "[Registrant]", "contact: registrant", etc.`,
				Properties:           contactProperties,
				Required:             contactRequired,
				AdditionalProperties: false,
			},
			"administrative": {
				Type:                 jsonschema.Object,
				Nullable:             true,
				Description:          `"administrative": The contact responsible for administrative decisions about the domain. May appear as "Admin", "Administrative Contact", "[Admin-C]", "contact: administrative", etc.`,
				Properties:           contactProperties,
				Required:             contactRequired,
				AdditionalProperties: false,
			},
			"technical": {
				Type:                 jsonschema.Object,
				Nullable:             true,
				Description:          `"technical": The contact responsible for technical/DNS management. May appear as "Tech", "Technical Contact", "[Tech-C]", "contact: technical", etc.`,
				Properties:           contactProperties,
				Required:             contactRequired,
				AdditionalProperties: false,
			},
			"billing": {
				Type:                 jsonschema.Object,
				Nullable:             true,
				Description:          `"billing": The contact responsible for billing. May appear as "Billing", "Billing Contact", "[Billing-C]", etc.`,
				Properties:           contactProperties,
				Required:             contactRequired,
				AdditionalProperties: false,
			},
		},
		Required: []string{
			"domain",
		},
		AdditionalProperties: false,
	}
}
