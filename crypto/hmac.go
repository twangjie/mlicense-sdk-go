package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func HMACKey(productID string, privateKeyPEM string) []byte {
	h := sha256.New()
	h.Write([]byte("mlicense-hmac:" + productID + ":" + privateKeyPEM))
	return h.Sum(nil)
}

func GenerateChallengeCode(key []byte, fingerprint string, timestamp int64, nonce string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fmt.Sprintf("%s|%d|%s", fingerprint, timestamp, nonce)))
	sum := mac.Sum(nil)

	val := uint64(sum[0])<<24 | uint64(sum[1])<<16 | uint64(sum[2])<<8 | uint64(sum[3])
	code := val % 1000000
	return fmt.Sprintf("%06d", code)
}

// GenerateResponseCode generates a 6-8 digit numeric response code.
// The response code authenticates the DEVICE (challenge + fingerprint) and is
// deliberately not bound to features/limits, which are carried and verified
// independently by the license file when present.
func GenerateResponseCode(key []byte, challengeCode string, fingerprint string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fmt.Sprintf("%s|%s", challengeCode, fingerprint)))
	sum := mac.Sum(nil)

	val := uint64(sum[0])<<24 | uint64(sum[1])<<16 | uint64(sum[2])<<8 | uint64(sum[3])
	code := val % 100000000
	return fmt.Sprintf("%08d", code)
}

func VerifyResponseCode(key []byte, challengeCode string, fingerprint string, providedCode string) bool {
	expected := GenerateResponseCode(key, challengeCode, fingerprint)
	return hmac.Equal([]byte(expected), []byte(providedCode))
}

func HashFeatures(features []string) string {
	sorted := make([]string, len(features))
	copy(sorted, features)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	h := sha256.New()
	h.Write([]byte(strings.Join(sorted, ",")))
	return hex.EncodeToString(h.Sum(nil))
}

func HashLimits(limits map[string]int) string {
	parts := make([]string, 0, len(limits))
	for k, v := range limits {
		parts = append(parts, fmt.Sprintf("%s:%d", k, v))
	}
	for i := 0; i < len(parts); i++ {
		for j := i + 1; j < len(parts); j++ {
			if parts[i] > parts[j] {
				parts[i], parts[j] = parts[j], parts[i]
			}
		}
	}
	h := sha256.New()
	h.Write([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}


