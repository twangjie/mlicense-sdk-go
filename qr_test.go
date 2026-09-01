package mlicense

import (
	"strings"
	"testing"

	"github.com/twangjie/mlicense-sdk-go/crypto"
)

func TestEncodeDecodeQRPayload(t *testing.T) {
	_, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	c, err := NewClient(Config{ProductID: "mcvr", PublicKeyPEM: pub})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	qr, err := c.GenerateQR()
	if err != nil {
		t.Fatalf("GenerateQR: %v", err)
	}
	if !strings.HasPrefix(qr, QRDataURIPrefix) {
		t.Fatalf("qr should have prefix %q, got %q", QRDataURIPrefix, qr)
	}

	payload, err := DecodeQRPayload(qr)
	if err != nil {
		t.Fatalf("DecodeQRPayload: %v", err)
	}
	if payload.ProductID != "mcvr" {
		t.Errorf("product_id = %q, want mcvr", payload.ProductID)
	}
	fp := c.GetFingerprint()
	if payload.Fingerprint == "" {
		t.Error("fingerprint empty in QR")
	}
	if fp != "" && payload.Fingerprint != fp {
		t.Errorf("qr fingerprint %q != device fingerprint %q", payload.Fingerprint, fp)
	}
	if payload.ExpiresAt == 0 {
		t.Error("expires_at missing in QR")
	}
	if payload.Timestamp != 0 {
		t.Errorf("timestamp should not be transmitted, got %d", payload.Timestamp)
	}
	if payload.Nonce == "" {
		t.Error("nonce empty in QR")
	}
	if payload.ChallengeCode == "" || len(payload.ChallengeCode) != 6 {
		t.Errorf("challenge_code should be 6 digits, got %q", payload.ChallengeCode)
	}

	if _, err := DecodeQRPayload("not-a-qr"); err == nil {
		t.Error("expected error for invalid QR")
	}
}

// TestQRDecodedSizeBound asserts the decoded QR payload stays well under 128
// bytes even with 3 MACs and a long non-UUID machine id.
func TestQRDecodedSizeBound(t *testing.T) {
	p := &QRRequestPayload{
		Type:          qrRequestType,
		Version:       qrVersion,
		ProductID:     "mcvr-aj",
		Fingerprint:   strings.Repeat("ab", 32),
		MachineID:     "12345678-1234-1234-1234-123456789abc", // 36-char UUID
		MACs:          []string{"aabbccddeeff", "112233445566", "fedcba987654"},
		ChallengeCode: "123456",
		Nonce:         strings.Repeat("00", 16),
		ExpiresAt:     1704070800,
	}
	qr, err := EncodeQRPayload(p)
	if err != nil {
		t.Fatalf("EncodeQRPayload: %v", err)
	}
	decoded, err := DecodeQRPayload(qr)
	if err != nil {
		t.Fatalf("DecodeQRPayload: %v", err)
	}
	if decoded.MachineID != p.MachineID {
		t.Errorf("machine_id roundtrip = %q, want %q", decoded.MachineID, p.MachineID)
	}
	if len(decoded.MACs) != 3 || decoded.MACs[2] != "fedcba987654" {
		t.Errorf("macs roundtrip = %v", decoded.MACs)
	}
	if decoded.ChallengeCode != "123456" {
		t.Errorf("challenge roundtrip = %q", decoded.ChallengeCode)
	}
	if decoded.Fingerprint != p.Fingerprint || decoded.Nonce != p.Nonce || decoded.ExpiresAt != p.ExpiresAt {
		t.Errorf("fields differ after roundtrip: %+v", decoded)
	}

	raw, err := crypto.Base64URLDecode(qr[len(QRDataURIPrefix):])
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if len(raw) > 128 {
		t.Errorf("decoded QR size = %d bytes, want <= 128", len(raw))
	}

	// Worst realistic case: 3 MACs + UUID machine id.
	if len(raw) > 128 {
		t.Fatal("typical QR exceeds 128 bytes")
	}
	t.Logf("decoded QR size with 3 MACs + UUID machine id: %d bytes (URI %d chars)", len(raw), len(qr))
}

// TestQRMacTruncation asserts encode caps the transmitted MAC list at 3.
func TestQRMacTruncation(t *testing.T) {
	macs := []string{"aabbccddeeff", "112233445566", "fedcba987654", "010203040506"}
	p := &QRRequestPayload{
		ProductID:     "mcvr-aj",
		Fingerprint:   strings.Repeat("ab", 32),
		MachineID:     "plain-machine-1",
		MACs:          macs,
		ChallengeCode: "123456",
		Nonce:         strings.Repeat("00", 16),
		ExpiresAt:     1704070800,
	}
	qr, err := EncodeQRPayload(p)
	if err != nil {
		t.Fatalf("EncodeQRPayload: %v", err)
	}
	decoded, err := DecodeQRPayload(qr)
	if err != nil {
		t.Fatalf("DecodeQRPayload: %v", err)
	}
	if len(decoded.MACs) != 3 {
		t.Errorf("macs truncated to %d, want 3", len(decoded.MACs))
	}
}

// TestQRUUDORoundTrip verifies a canonical UUID machine id is byte-compressed
// and restored exactly.
func TestQRUUIDRoundTrip(t *testing.T) {
	uuidStr := "12345678-1234-1234-1234-123456789abc"
	p := &QRRequestPayload{
		ProductID:     "mcvr-aj",
		Fingerprint:   strings.Repeat("ab", 32),
		MachineID:     uuidStr,
		MACs:          []string{"aabbccddeeff"},
		ChallengeCode: "123456",
		Nonce:         strings.Repeat("00", 16),
		ExpiresAt:     1704070800,
	}
	qr, err := EncodeQRPayload(p)
	if err != nil {
		t.Fatalf("EncodeQRPayload: %v", err)
	}
	raw, err := crypto.Base64URLDecode(qr[len(QRDataURIPrefix):])
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	// UUID machine id must be stored as 16 raw bytes, not 36-char text.
	if len(raw) != 4+7+16+1+6+3+16+32+4 {
		t.Fatalf("unexpected decoded size %d", len(raw))
	}
	decoded, err := DecodeQRPayload(qr)
	if err != nil {
		t.Fatalf("DecodeQRPayload: %v", err)
	}
	if decoded.MachineID != uuidStr {
		t.Errorf("machine_id roundtrip = %q, want %q", decoded.MachineID, uuidStr)
	}
}

func TestGenerateQRRequiresProductID(t *testing.T) {
	_, pub, _ := crypto.GenerateKeyPair()
	c, err := NewClient(Config{ProductID: "mcvr", PublicKeyPEM: pub})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.config.ProductID = ""
	if _, err := c.GenerateQR(); err == nil {
		t.Error("expected error when ProductID empty")
	}
}
