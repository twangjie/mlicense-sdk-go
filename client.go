//go:build !nolicense

package mlicense

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/twangjie/mlicense-sdk-go/crypto"
	"github.com/twangjie/mlicense-sdk-go/hardware"
)

type Client struct {
	config   Config
	keys     map[string]*ecdsa.PublicKey
	primary  *ecdsa.PublicKey
	license  *TokenPayload
	rawToken string
	hwInfo   *hardware.HardwareInfo
	challengeCode string
	activated     bool
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.LicensePath == "" {
		cfg.LicensePath = "./lic.dat"
	}

	if err := cfg.applyKeyBundle(); err != nil {
		return nil, err
	}

	if cfg.ProductID == "" {
		return nil, fmt.Errorf("product_id is required (or provide a key bundle containing it)")
	}

	if cfg.PublicKeyPEM == "" {
		return nil, fmt.Errorf("public_key is required (or provide a key bundle)")
	}

	keys, err := loadPublicKeys(cfg)
	if err != nil {
		return nil, err
	}

	primary, err := crypto.LoadPublicKey(cfg.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load primary public key: %w", err)
	}

	return &Client{
		config:  cfg,
		keys:    keys,
		primary: primary,
	}, nil
}

// resolvePublicKey returns the public key for the given kid. It falls back to
// the primary key when the kid is unknown or empty.
func (c *Client) resolvePublicKey(kid string) *ecdsa.PublicKey {
	if kid != "" {
		if pk, ok := c.keys[kid]; ok {
			return pk
		}
	}
	return c.primary
}

func (c *Client) Verify() error {
	token, err := c.loadToken()
	if err != nil {
		return err
	}

	payload, kid, err := DecodeToken(token)
	if err != nil {
		return fmt.Errorf("failed to decode token: %w", err)
	}

	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format: expected 3 parts")
	}

	sigBytes, err := crypto.Base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	salt, err := c.getSalt()
	if err != nil {
		return fmt.Errorf("failed to get salt: %w", err)
	}

	hwInfo, err := hardware.Collect(salt)
	if err != nil {
		return fmt.Errorf("failed to collect hardware info: %w", err)
	}
	c.hwInfo = hwInfo

	if payload.Fingerprint != "" && payload.Fingerprint != hwInfo.Fingerprint {
		return fmt.Errorf("hardware fingerprint mismatch")
	}

	claims := buildCanonicalClaims(payload, payload.Fingerprint, "")
	pubKey := c.resolvePublicKey(kid)
	if !crypto.Verify(pubKey, claims, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	now := time.Now().UTC()
	expireAt, err := time.Parse(time.RFC3339, payload.ExpireAt)
	if err != nil {
		return fmt.Errorf("failed to parse expire_at: %w", err)
	}
	if now.After(expireAt) {
		return fmt.Errorf("license expired at %s", payload.ExpireAt)
	}

	notBefore, err := time.Parse(time.RFC3339, payload.NotBefore)
	if err != nil {
		return fmt.Errorf("failed to parse not_before: %w", err)
	}
	if now.Before(notBefore) {
		return fmt.Errorf("license not yet valid until %s", payload.NotBefore)
	}

	c.license = payload
	c.rawToken = token
	return nil
}

func (c *Client) GetLicense() *TokenPayload {
	return c.license
}

func (c *Client) GetStatus() string {
	if c.activated {
		return "active"
	}
	if c.license == nil {
		return "no_license"
	}

	now := time.Now().UTC()
	expireAt, err := time.Parse(time.RFC3339, c.license.ExpireAt)
	if err != nil {
		return "invalid"
	}
	if now.After(expireAt) {
		return "expired"
	}
	return "active"
}

// IsActivated reports whether the client has been authorized, either via the
// simple challenge code flow or via a license file.
func (c *Client) IsActivated() bool {
	return c.activated || c.GetStatus() == "active"
}

func (c *Client) GetFingerprint() string {
	if c.hwInfo == nil {
		salt, _ := c.getSalt()
		hwInfo, _ := hardware.Collect(salt)
		if hwInfo != nil {
			c.hwInfo = hwInfo
		}
	}
	if c.hwInfo != nil {
		return c.hwInfo.Fingerprint
	}
	return ""
}

func (c *Client) GetHardwareInfo() *hardware.HardwareInfo {
	if c.hwInfo == nil {
		salt, _ := c.getSalt()
		hwInfo, _ := hardware.Collect(salt)
		if hwInfo != nil {
			c.hwInfo = hwInfo
		}
	}
	return c.hwInfo
}

func (c *Client) Close() {
}

func (c *Client) getSalt() (string, error) {
	// The salt must be stable across process restarts so the device fingerprint
	// is reproducible. Persist it next to the license file.
	return c.persistentSalt()
}

func (c *Client) persistentSalt() (string, error) {
	path := c.config.LicensePath + ".salt"
	data, err := os.ReadFile(path)
	if err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			return s, nil
		}
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(salt), 0600); err != nil {
		return "", err
	}
	return salt, nil
}

func buildCanonicalClaims(payload *TokenPayload, fingerprint string, serverURL string) string {
	claims := make(map[string]string)
	claims["issuer"] = payload.Issuer
	claims["product_id"] = payload.ProductID
	claims["type"] = payload.Type

	if fingerprint != "" {
		claims["fingerprint"] = fingerprint
	}
	if serverURL != "" {
		claims["server_url"] = serverURL
	}

	claims["expire_at"] = payload.ExpireAt

	features := make([]string, len(payload.Features))
	copy(features, payload.Features)
	claims["features"] = joinSorted(features)

	limitParts := make([]string, 0, len(payload.Limits))
	for k, v := range payload.Limits {
		limitParts = append(limitParts, fmt.Sprintf("%s:%d", k, v))
	}
	claims["limits"] = joinSorted(limitParts)

	for k, v := range payload.Extra {
		claims["extra."+k] = fmt.Sprintf("%v", v)
	}

	return crypto.CanonicalClaims(claims)
}

func joinSorted(items []string) string {
	sorted := make([]string, len(items))
	copy(sorted, items)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return strings.Join(sorted, ",")
}

// loadPublicKeys builds a kid -> public key map from the configuration's
// primary key and ExtraKeys.
func loadPublicKeys(cfg Config) (map[string]*ecdsa.PublicKey, error) {
	keys := make(map[string]*ecdsa.PublicKey)

	if cfg.PublicKeyPEM != "" {
		pk, err := crypto.LoadPublicKey(cfg.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load primary public key: %w", err)
		}
		keys["__primary__"] = pk
	}

	for kid, pem := range cfg.ExtraKeys {
		if strings.TrimSpace(pem) == "" {
			continue
		}
		pk, err := crypto.LoadPublicKey(pem)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key for kid %q: %w", kid, err)
		}
		keys[kid] = pk
	}

	return keys, nil
}
