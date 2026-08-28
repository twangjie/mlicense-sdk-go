package mlicense

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	ProductID    string
	PublicKeyPEM string
	LicensePath  string
	ExtraKeys    map[string]string

	// KeyBundle (optional) replaces manual PublicKeyPEM/ExtraKeys configuration.
	// If both PublicKeyPEM and KeyBundle are given, PublicKeyPEM takes
	// precedence as the primary key and the bundle's key is merged as extra.
	KeyBundle     string
	KeyBundlePath string
}

type KeyBundle struct {
	ProductID   string `json:"product_id"`
	ProductName string `json:"product_name"`
	PublicKey   string `json:"public_key"`
	Kid         string `json:"kid"`
	ExportedAt  string `json:"exported_at"`
	Note        string `json:"note"`
}

// applyKeyBundle loads and merges the key bundle (from KeyBundlePath or
// KeyBundle) into the configuration. The product_id inside the bundle is only
// used as a fallback when Config.ProductID is empty.
func (c *Config) applyKeyBundle() error {
	var raw string
	if c.KeyBundlePath != "" {
		data, err := os.ReadFile(c.KeyBundlePath)
		if err != nil {
			return fmt.Errorf("failed to read key bundle: %w", err)
		}
		raw = string(data)
	} else if c.KeyBundle != "" {
		raw = c.KeyBundle
	}

	if raw == "" {
		return nil
	}

	var bundle KeyBundle
	if err := json.Unmarshal([]byte(raw), &bundle); err != nil {
		return fmt.Errorf("failed to parse key bundle: %w", err)
	}

	if c.ProductID == "" && bundle.ProductID != "" {
		c.ProductID = bundle.ProductID
	}
	if c.PublicKeyPEM == "" && bundle.PublicKey != "" {
		c.PublicKeyPEM = bundle.PublicKey
	}
	if bundle.PublicKey != "" && bundle.Kid != "" {
		if c.ExtraKeys == nil {
			c.ExtraKeys = make(map[string]string)
		}
		if _, ok := c.ExtraKeys[bundle.Kid]; !ok {
			c.ExtraKeys[bundle.Kid] = bundle.PublicKey
		}
	}

	return nil
}
