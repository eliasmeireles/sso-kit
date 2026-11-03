package ssohttp

import "encoding/json"

// quoteJSON encodes s as a JSON string literal.
func quoteJSON(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}
