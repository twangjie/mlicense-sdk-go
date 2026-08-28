//go:build !nolicense

package mlicense

import (
	"fmt"
	"os"
	"strings"

	"github.com/twangjie/mlicense-sdk-go/crypto"
)

func (c *Client) loadToken() (string, error) {
	data, err := os.ReadFile(c.config.LicensePath)
	if err != nil {
		return "", fmt.Errorf("failed to read license file: %w", err)
	}

	content := strings.TrimSpace(string(data))

	if strings.HasPrefix(content, "-----BEGIN LICENSE-----") {
		return DecodePEM(content)
	}

	return content, nil
}

func (c *Client) saveToken(token string) error {
	encoded := EncodePEM(token)
	return os.WriteFile(c.config.LicensePath, []byte(encoded), 0644)
}

func (c *Client) ImportLicense(token string) error {
	payload, kid, err := DecodeToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	if payload.ProductID != c.config.ProductID {
		return fmt.Errorf("product_id mismatch: expected %s, got %s", c.config.ProductID, payload.ProductID)
	}

	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format: expected 3 parts")
	}

	sigBytes, err := crypto.Base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey := c.resolvePublicKey(kid)

	claims := buildCanonicalClaims(payload, payload.Fingerprint, "")
	if !crypto.Verify(pubKey, claims, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return c.saveToken(token)
}
