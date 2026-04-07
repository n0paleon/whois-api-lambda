package llm

import (
	_ "embed"
)

//go:embed whois_json_schema.json
var whoisSchema string

func loadSchema() (string, error) {
	// Return the embedded schema instead of reading from file
	return whoisSchema, nil
}
