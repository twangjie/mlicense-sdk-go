package mlicense

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/twangjie/mlicense-sdk-go/crypto"
)

type TokenPayload struct {
	Issuer      string                 `json:"issuer"`
	ProductID   string                 `json:"product_id"`
	LicenseID   string                 `json:"license_id"`
	Subject     string                 `json:"subject"`
	Type        string                 `json:"type"`
	Fingerprint string                 `json:"fingerprint,omitempty"`
	ServerURL   string                 `json:"server_url,omitempty"`
	Features    []string               `json:"features"`
	Limits      map[string]int         `json:"limits"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
	IssuedAt    string                 `json:"issued_at"`
	ExpireAt    string                 `json:"expire_at"`
	NotBefore   string                 `json:"not_before"`
}

func EncodeToken(kid string, payload *TokenPayload) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(payloadJSON); err != nil {
		return "", fmt.Errorf("failed to compress payload: %w", err)
	}
	if err := gw.Close(); err != nil {
		return "", fmt.Errorf("failed to close gzip writer: %w", err)
	}

	payloadEncoded := crypto.Base64URLEncode(compressed.Bytes())

	return kid + "." + payloadEncoded, nil
}

func DecodeToken(token string) (*TokenPayload, string, error) {
	// Accept both "kid.payload" (2 parts) and "kid.payload.signature" (3 parts).
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, "", fmt.Errorf("invalid token format")
	}

	kid := parts[0]
	payloadEncoded := parts[1]

	payloadBytes, err := crypto.Base64URLDecode(payloadEncoded)
	if err != nil {
		return nil, kid, fmt.Errorf("failed to decode payload: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, kid, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	var payload TokenPayload
	if err := json.NewDecoder(gr).Decode(&payload); err != nil {
		return nil, kid, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &payload, kid, nil
}

func EncodePEM(token string) string {
	var buf strings.Builder
	buf.WriteString("-----BEGIN LICENSE-----\n")

	for i := 0; i < len(token); i += 64 {
		end := i + 64
		if end > len(token) {
			end = len(token)
		}
		buf.WriteString(token[i:end])
		buf.WriteString("\n")
	}

	buf.WriteString("-----END LICENSE-----\n")
	return buf.String()
}

func DecodePEM(pemStr string) (string, error) {
	lines := strings.Split(pemStr, "\n")
	var tokenParts []string

	inBlock := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "-----BEGIN LICENSE-----" {
			inBlock = true
			continue
		}
		if line == "-----END LICENSE-----" {
			inBlock = false
			continue
		}
		if inBlock && line != "" {
			tokenParts = append(tokenParts, line)
		}
	}

	if len(tokenParts) == 0 {
		return "", fmt.Errorf("no license token found in PEM")
	}

	return strings.Join(tokenParts, ""), nil
}
