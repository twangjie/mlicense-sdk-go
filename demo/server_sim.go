package main

import (
	"crypto/ecdsa"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/twangjie/mlicense-sdk-go"
	"github.com/twangjie/mlicense-sdk-go/crypto"
)

// simulateServerResponseCode 模拟 mlicense 管理后台生成应答码。
// 应答码仅绑定 挑战码+指纹（设备授权），不绑定功能/限制；功能/限制由授权文件独立携带与校验。
// 为与 SDK 一致，此处用公钥派生 HMAC key（SDK 只持有公钥）。
func simulateServerResponseCode(challengeCode string, fingerprint string) string {
	key := crypto.HMACKey(productID, publicKeyPEM)
	return crypto.GenerateResponseCode(key, challengeCode, fingerprint)
}

// simulateServerLicenseToken 模拟 mlicense 后台为设备签发的完整授权文件 token。
func simulateServerLicenseToken(features []string, limits map[string]int, fingerprint string) string {
	now := time.Now().UTC()
	payload := &mlicense.TokenPayload{
		Issuer:      "mlicense-server",
		ProductID:   productID,
		LicenseID:   "demo-license-001",
		Subject:     "demo customer",
		Type:        "offline",
		Fingerprint: fingerprint,
		Features:    features,
		Limits:      limits,
		IssuedAt:    now.Format(time.RFC3339),
		ExpireAt:    now.AddDate(0, 0, 365).Format(time.RFC3339),
		NotBefore:   now.Format(time.RFC3339),
	}

	claims := demoClaims(payload)
	signature, err := crypto.Sign(loadPrivateKey(), claims)
	if err != nil {
		panic(err)
	}

	kid := productID + "-v1"
	body, err := mlicense.EncodeToken(kid, payload)
	if err != nil {
		panic(err)
	}
	return body + "." + crypto.Base64URLEncode(signature)
}

// demoClaims 构建与 SDK 内部完全一致的 canonical claims（保证验签通过）。
func demoClaims(p *mlicense.TokenPayload) string {
	claims := map[string]string{
		"issuer":      p.Issuer,
		"product_id":  p.ProductID,
		"type":        p.Type,
		"fingerprint": p.Fingerprint,
		"expire_at":   p.ExpireAt,
		"features":    sortedJoin(p.Features),
		"limits":      limitsString(p.Limits),
	}
	for k, v := range p.Extra {
		claims["extra."+k] = fmt.Sprintf("%v", v)
	}
	return crypto.CanonicalClaims(claims)
}

func sortedJoin(items []string) string {
	s := append([]string{}, items...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

func limitsString(limits map[string]int) string {
	keys := make([]string, 0, len(limits))
	for k := range limits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+strconv.Itoa(limits[k]))
	}
	return strings.Join(parts, ",")
}

func loadPrivateKey() *ecdsa.PrivateKey {
	key, err := crypto.LoadPrivateKey(privateKeyPEM)
	if err != nil {
		panic(err)
	}
	return key
}
