//go:build !nolicense

package mlicense

import (
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
// It verifies the response code (with empty features/limits) against the device
// fingerprint; on success the client is marked as activated in memory.
func (c *Client) ActivateByResponse(responseCode string, fingerprint string) error {
	if c.challengeCode == "" {
		return ErrNoChallengeCode
	}
	if fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}

	key := c.hmacKey()
	if !crypto.VerifyResponseCode(
		key, c.challengeCode, fingerprint,
		crypto.HashFeatures(nil), crypto.HashLimits(nil), responseCode,
	) {
		return ErrInvalidResponseCode
	}

	c.challengeCode = ""
	c.activated = true
	return nil
}

// ActivateByResponseWithToken verifies the response code against a license token
// and, on success, writes the license token to the license file.
//
// The license token (issued by the mlicense server for the device) carries the
// full authorization: fingerprint, features, limits and expiry. Features and
// limits are derived from the token, not passed in.
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
	if !crypto.VerifyResponseCode(
		key, c.challengeCode, fingerprint,
		crypto.HashFeatures(payload.Features), crypto.HashLimits(payload.Limits), responseCode,
	) {
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
