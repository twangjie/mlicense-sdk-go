package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

func GenerateKeyPair() (privateKeyPEM, publicKeyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	privBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	privateKeyPEM = string(pem.EncodeToMemory(privBlock))

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	publicKeyPEM = string(pem.EncodeToMemory(pubBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

func LoadPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return key, nil
}

func LoadPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return key, nil
}

func Sign(privateKey *ecdsa.PrivateKey, message string) ([]byte, error) {
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	sig, err := encodeSignature(r, s)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}
	return sig, nil
}

func Verify(publicKey *ecdsa.PublicKey, message string, signature []byte) bool {
	hash := sha256.Sum256([]byte(message))
	r, s, err := decodeSignature(signature)
	if err != nil {
		return false
	}
	return ecdsa.Verify(publicKey, hash[:], r, s)
}

func encodeSignature(r, s *big.Int) ([]byte, error) {
	return asn1Encode(r.Bytes(), s.Bytes())
}

func decodeSignature(sig []byte) (*big.Int, *big.Int, error) {
	rBytes, sBytes, err := asn1Decode(sig)
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes), nil
}

func asn1Encode(r, s []byte) ([]byte, error) {
	rLen := len(r)
	sLen := len(s)
	totalLen := 2 + rLen + 2 + sLen

	result := make([]byte, 0, 4+totalLen)
	result = append(result, 0x30)
	result = append(result, byte(totalLen))

	result = append(result, 0x02)
	result = append(result, byte(rLen))
	result = append(result, r...)

	result = append(result, 0x02)
	result = append(result, byte(sLen))
	result = append(result, s...)

	return result, nil
}

func asn1Decode(sig []byte) ([]byte, []byte, error) {
	if len(sig) < 8 || sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid ASN.1 signature")
	}

	rOffset := 4
	rLen := int(sig[3])
	if rOffset+rLen > len(sig) {
		return nil, nil, fmt.Errorf("invalid R length")
	}
	rBytes := sig[rOffset : rOffset+rLen]

	sOffset := rOffset + rLen + 2
	if sOffset >= len(sig) {
		return nil, nil, fmt.Errorf("invalid S offset")
	}
	sLen := int(sig[sOffset-1])
	if sOffset+sLen > len(sig) {
		return nil, nil, fmt.Errorf("invalid S length")
	}
	sBytes := sig[sOffset : sOffset+sLen]

	return rBytes, sBytes, nil
}

func CanonicalClaims(claims map[string]string) string {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		v := claims[k]
		if strings.Contains(v, ",") {
			sorted := strings.Split(v, ",")
			sort.Strings(sorted)
			v = strings.Join(sorted, ",")
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, "\n")
}

func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
