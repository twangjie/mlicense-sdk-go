//go:build !nolicense

package mlicense

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/twangjie/mlicense-sdk-go/crypto"
)

func newTestToken(t *testing.T, productID, kid string, privPEM string, fingerprint string) string {
	t.Helper()
	priv, err := crypto.LoadPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("load private key: %v", err)
	}
	now := time.Now().UTC()
	payload := &TokenPayload{
		Issuer:      "mlicense-server",
		ProductID:   productID,
		LicenseID:   "test-license",
		Subject:     "test",
		Type:        "offline",
		Fingerprint: fingerprint,
		Features:    []string{"gb28181_access"},
		Limits:      map[string]int{"max_streams": 10},
		IssuedAt:    now.Format(time.RFC3339),
		ExpireAt:    now.AddDate(0, 0, 365).Format(time.RFC3339),
		NotBefore:   now.Format(time.RFC3339),
	}
	claims := buildCanonicalClaims(payload, fingerprint, "")
	sig, err := crypto.Sign(priv, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, err := EncodeToken(kid, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return body + "." + crypto.Base64URLEncode(sig)
}

func TestKeyBundleLoadAndProductIDResolve(t *testing.T) {
	_, pubPEM, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen key pair: %v", err)
	}

	bundle := KeyBundle{
		ProductID: "mcvr",
		PublicKey: pubPEM,
		Kid:       "mcvr-v1",
	}
	raw, _ := json.Marshal(bundle)

	cfg := Config{
		KeyBundle:   string(raw),
		LicensePath: t.TempDir() + "/lic.dat",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient with key bundle: %v", err)
	}
	if client.config.ProductID != "mcvr" {
		t.Fatalf("expected product_id resolved from bundle, got %q", client.config.ProductID)
	}
	if client.config.PublicKeyPEM == "" {
		t.Fatalf("expected public key resolved from bundle")
	}
	if _, ok := client.keys["mcvr-v1"]; !ok {
		t.Fatalf("expected kid mcvr-v1 in key map")
	}
}

func TestExtraKeysVerifyOldKeyToken(t *testing.T) {
	oldPriv, oldPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen old key: %v", err)
	}
	_, newPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen new key: %v", err)
	}

	// Token signed with the OLD (rotated) key, kid references the old key.
	// client is configured with the NEW key as primary + old key via ExtraKeys.
	token := newTestToken(t, "mcvr", "mcvr-v1", oldPriv, "fp-test")

	client, err := NewClient(Config{
		ProductID:    "mcvr",
		PublicKeyPEM: newPub,
		ExtraKeys:    map[string]string{"mcvr-v1": oldPub},
		LicensePath:  t.TempDir() + "/lic.dat",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ImportLicense(token); err != nil {
		t.Fatalf("ImportLicense with old-key token should verify via ExtraKeys: %v", err)
	}
}

func TestUnknownKidFallsBackToPrimary(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	// kid unknown, signed with primary key -> should verify via fallback.
	token := newTestToken(t, "mcvr", "mcvr-v999", priv, "fp-test")

	client, err := NewClient(Config{
		ProductID:    "mcvr",
		PublicKeyPEM: pub,
		LicensePath:  t.TempDir() + "/lic.dat",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ImportLicense(token); err != nil {
		t.Fatalf("ImportLicense should fall back to primary key: %v", err)
	}
}

func TestKeyBundleFileLoad(t *testing.T) {
	_, pubPEM, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	bundle := KeyBundle{ProductID: "mcvr", PublicKey: pubPEM, Kid: "mcvr-v1"}
	raw, _ := json.Marshal(bundle)
	path := t.TempDir() + "/keys.json"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}

	client, err := NewClient(Config{
		KeyBundlePath: path,
		LicensePath:   t.TempDir() + "/lic.dat",
	})
	if err != nil {
		t.Fatalf("NewClient with key bundle file: %v", err)
	}
	if client.config.ProductID != "mcvr" {
		t.Fatalf("expected product_id from bundle file, got %q", client.config.ProductID)
	}
}
