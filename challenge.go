//go:build !nolicense

package mlicense

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/twangjie/mlicense-sdk-go/crypto"
	"github.com/twangjie/mlicense-sdk-go/hardware"
)

var ErrInvalidResponseCode = errors.New("invalid response code")
var ErrNoChallengeCode = errors.New("no challenge code generated")

// GenerateChallengeCode generates a challenge code based on current hardware
// fingerprint. The generated code is remembered internally so it can later be
// verified via ActivateByResponse / ActivateByResponseWithToken.
func (c *Client) GenerateChallengeCode() (string, error) {
	if c.hwInfo == nil {
		salt, _ := c.getSalt()
		hwInfo, err := hardware.Collect(salt)
		if err != nil {
			return "", fmt.Errorf("failed to collect hardware info: %w", err)
		}
		c.hwInfo = hwInfo
	}

	nonce, err := crypto.GenerateNonce()
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Unix()
	key := c.hmacKey()
	code := crypto.GenerateChallengeCode(key, c.hwInfo.Fingerprint, timestamp, nonce)

	c.challengeCode = code
	return code, nil
}

// ActivateByResponse performs simple challenge-based authorization for clients
// that do not need dedicated feature/limit management.
//
// It verifies the response code against the device fingerprint; on success the
// client is marked as activated in memory and a minimal activation token is
// written to the license file for persistence across restarts.
func (c *Client) ActivateByResponse(responseCode string, fingerprint string) error {
	if c.challengeCode == "" {
		return ErrNoChallengeCode
	}
	if fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}

	key := c.hmacKey()
	if !crypto.VerifyResponseCode(key, c.challengeCode, fingerprint, responseCode) {
		return ErrInvalidResponseCode
	}

	// Create a minimal activation token for persistence
	token := c.createActivationToken(responseCode, fingerprint)
	if err := c.saveToken(token); err != nil {
		return fmt.Errorf("failed to save activation: %w", err)
	}

	c.challengeCode = ""
	c.activated = true
	return nil
}

// createActivationToken creates a minimal activation token for simple challenge-response flow.
// This token represents successful response-code activation and is saved to lic.dat for persistence.
// It does not carry features/limits/expiry - it only proves the device was activated via response code.
func (c *Client) createActivationToken(responseCode string, fingerprint string) string {
	payload := TokenPayload{
		Issuer:      "mlicense-server",
		ProductID:   c.config.ProductID,
		LicenseID:   "challenge-response",
		Subject:     "device",
		Type:        "challenge-response",
		Fingerprint: fingerprint,
		Features:    []string{},
		Limits:      map[string]int{},
		IssuedAt:    time.Now().UTC().Format(time.RFC3339),
		ExpireAt:    time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339), // long expiry
		NotBefore:   time.Now().UTC().Format(time.RFC3339),
	}

	// Create unsigned token (kid.payload without signature) - the HMAC verification already proved authenticity
	kid := "challenge-response"
	payloadJSON, _ := json.Marshal(payload)
	compressed := new(bytes.Buffer)
	gw := gzip.NewWriter(compressed)
	gw.Write(payloadJSON)
	gw.Close()
	payloadEncoded := crypto.Base64URLEncode(compressed.Bytes())
	return kid + "." + payloadEncoded
}

// ActivateByResponseWithToken verifies the response code against a license token
// and, on success, writes the license token to the license file.
//
// The license token (issued by the mlicense server for the device) carries the
// full authorization: fingerprint, features, limits and expiry. Features and
// limits are derived from the token, not from the response code; the response
// code only authorizes the device (challenge + fingerprint).
func (c *Client) ActivateByResponseWithToken(responseCode string, licenseToken string, fingerprint string) error {
	if c.challengeCode == "" {
		return ErrNoChallengeCode
	}
	if fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}

	payload, _, err := DecodeToken(licenseToken)
	if err != nil {
		return fmt.Errorf("invalid license token: %w", err)
	}

	if payload.Fingerprint != "" && payload.Fingerprint != fingerprint {
		return fmt.Errorf("license token fingerprint mismatch")
	}

	key := c.hmacKey()
	if !crypto.VerifyResponseCode(key, c.challengeCode, fingerprint, responseCode) {
		return ErrInvalidResponseCode
	}

	if err := c.ImportLicense(licenseToken); err != nil {
		return fmt.Errorf("failed to save license: %w", err)
	}

	c.challengeCode = ""
	return c.Verify()
}

func (c *Client) hmacKey() []byte {
	return crypto.HMACKey(c.config.ProductID, c.config.PublicKeyPEM)
}
