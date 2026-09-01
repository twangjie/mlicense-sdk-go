//go:build !nolicense

package mlicense

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/twangjie/mlicense-sdk-go/crypto"
)

// QRRequestPayload is the device-side offline-activation QR request. It is
// generated locally by the SDK, deliberately unsigned and minimal (the device
// only self-describes). Business/customer data is intentionally NOT embedded;
// the admin fills it in on the web console after scanning.
//
// The payload is NOT serialized as JSON on the wire; it uses a compact binary
// layout (see EncodeQRPayload) so the decoded QR stays well under 128 bytes.
type QRRequestPayload struct {
	Type          string   `json:"type"`          // mlicense-offline-request
	Version       string   `json:"version"`       // payload schema version ("1")
	ProductID     string   `json:"product_id"`    // product slug, max 32 chars
	Fingerprint   string   `json:"fingerprint"`   // 64-char hex (SHA-256)
	MachineID     string   `json:"machine_id"`    // machine id (GUID or free text, max 63 chars)
	MACs          []string `json:"macs"`          // normalized 12-char hex MACs (max 3 in QR)
	ChallengeCode string   `json:"challenge_code"` // 6-digit zero-padded
	Nonce         string   `json:"nonce"`         // 32-char hex (16 bytes)
	Timestamp     int64    `json:"timestamp"`     // not transmitted (kept for compatibility)
	ExpiresAt     int64    `json:"expires_at"`
}

// QRDataURIPrefix is the scheme prefix of the offline-activation QR.
const QRDataURIPrefix = "mlicense://offline?qr="

const qrRequestType = "mlicense-offline-request"
const qrVersion = "1"

// Wire format constraints.
const (
	qrBinaryVersion = 2
	qrMagic         = 0x4C // 'L'

	qrMaxProductIDLen = 32
	qrMaxMacCount     = 3   // QR carries the first 3 MACs (display only)
	qrMaxMachineLen   = 63  // plain (non-UUID) machine id length cap
	qrMaxChallengeLen = 6
)

// flag bits in byte 2.
const (
	qrFlagHasChallenge    = 1 << 0
	qrFlagMachineUUID     = 1 << 1 // machine_id is a 16-byte compressed UUID
)

// qrTTL is how long the device-side QR stays valid (for backend expiry check).
//
// A generous TTL is used so an offline QR can be sent via email / IM and be
// processed by an admin in batch, which routinely exceeds a few minutes. The
// expiry only serves as a soft, administrative notice on the backend scan side;
// the real authorization is the challenge+response HMAC computed against the
// device fingerprint at activation time.
const qrTTL = 7 * 24 * time.Hour

// GenerateQR builds an offline-activation request QR payload from the local
// hardware fingerprint and returns it as a data URI that can be rendered as a
// QR image. The QR is unsigned and minimal; an admin scans it in the mlicense
// web console and issues a response code or an authorization file.
func (c *Client) GenerateQR() (string, error) {
	if c.config.ProductID == "" {
		return "", fmt.Errorf("product_id is required to generate a QR")
	}

	// Generate and store a challenge code locally; it is embedded in the QR so
	// the admin can compute the matching response code (simple mode).
	challenge, err := c.GenerateChallengeCode()
	if err != nil {
		return "", err
	}

	hw := c.GetHardwareInfo()
	if hw == nil {
		return "", fmt.Errorf("failed to collect hardware info")
	}

	nonce, err := crypto.GenerateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	now := time.Now().UTC().Unix()
	payload := QRRequestPayload{
		Type:          qrRequestType,
		Version:       qrVersion,
		ProductID:     c.config.ProductID,
		Fingerprint:   hw.Fingerprint,
		MachineID:     hw.MachineID,
		MACs:          hw.MACs,
		ChallengeCode: challenge,
		Nonce:         nonce,
		Timestamp:     now,
		ExpiresAt:     now + int64(qrTTL.Seconds()),
	}

	return EncodeQRPayload(&payload)
}

// EncodeQRPayload serializes a QR request payload into an unsigned offline QR
// data URI (mlicense://offline?qr=<base64url(binary)>).
//
// Binary layout (big-endian):
//
//	[0]  magic byte 0x4C
//	[1]  binary version (2)
//	[2]  flags: bit0 has_challenge, bit1 machine_id is a 16-byte UUID
//	[3]  product_id_len (1..32)
//	[..] product_id bytes
//	machine_id: if UUID flag -> 16 raw bytes; else 1 len byte (0..63) + bytes
//	macs: 1 count byte (0..3) + count*6 raw bytes
//	challenge_code: (if has_challenge) 3 bytes BCD of 6 digits
//	nonce: 16 raw bytes
//	fingerprint: 32 raw bytes (SHA-256)
//	expires_at: uint32 unix seconds (4 bytes)
func EncodeQRPayload(payload *QRRequestPayload) (string, error) {
	if payload == nil || payload.ProductID == "" {
		return "", fmt.Errorf("product_id is required")
	}
	if len(payload.ProductID) > qrMaxProductIDLen {
		return "", fmt.Errorf("product_id too long (%d > %d)", len(payload.ProductID), qrMaxProductIDLen)
	}

	fpRaw, err := decodeHex(payload.Fingerprint, 32)
	if err != nil {
		return "", fmt.Errorf("fingerprint must be 64-char hex (SHA-256): %w", err)
	}
	nonceRaw, err := decodeHex(payload.Nonce, 16)
	if err != nil {
		return "", fmt.Errorf("nonce must be 32-char hex: %w", err)
	}
	if payload.ExpiresAt <= 0 || payload.ExpiresAt > math.MaxUint32 {
		return "", fmt.Errorf("invalid expires_at: %d", payload.ExpiresAt)
	}

	var machine []byte
	var flags byte
	if raw, ok := parseUUID(payload.MachineID); ok {
		machine = raw
		flags |= qrFlagMachineUUID
	} else {
		if len(payload.MachineID) > qrMaxMachineLen {
			return "", fmt.Errorf("machine_id too long (%d > %d)", len(payload.MachineID), qrMaxMachineLen)
		}
		machine = []byte(payload.MachineID)
	}

	if payload.ChallengeCode != "" {
		if len(payload.ChallengeCode) != qrMaxChallengeLen {
			return "", fmt.Errorf("challenge_code must be %d digits", qrMaxChallengeLen)
		}
		if _, err := bcdEncode(payload.ChallengeCode); err != nil {
			return "", fmt.Errorf("challenge_code: %w", err)
		}
		flags |= qrFlagHasChallenge
	}

	macs := payload.MACs
	if len(macs) > qrMaxMacCount {
		macs = macs[:qrMaxMacCount]
	}
	macRaw := make([]byte, 0, len(macs)*6)
	for _, m := range macs {
		raw, err := decodeHex(m, 6)
		if err != nil {
			return "", fmt.Errorf("mac %q must be 12-char hex: %w", m, err)
		}
		macRaw = append(macRaw, raw...)
	}

	bodyLen := 4 + len(payload.ProductID) + len(machine) + 1 + len(macRaw) +
		16 + 32 + 4
	if flags&qrFlagHasChallenge != 0 {
		bodyLen += 3
	}
	body := make([]byte, 0, bodyLen)
	body = append(body, qrMagic, qrBinaryVersion, flags, byte(len(payload.ProductID)))
	body = append(body, payload.ProductID...)
	if flags&qrFlagMachineUUID != 0 {
		body = append(body, machine...)
	} else {
		body = append(body, byte(len(machine)))
		body = append(body, machine...)
	}
	body = append(body, byte(len(macs)))
	body = append(body, macRaw...)
	if flags&qrFlagHasChallenge != 0 {
		ch, _ := bcdEncode(payload.ChallengeCode)
		body = append(body, ch...)
	}
	body = append(body, nonceRaw...)
	body = append(body, fpRaw...)
	body = append(body, uint32BE(payload.ExpiresAt)...)

	return QRDataURIPrefix + crypto.Base64URLEncode(body), nil
}

// DecodeQRPayload extracts the QRRequestPayload from an offline QR data URI.
// It returns an error if the QR is not a recognized offline-request QR.
func DecodeQRPayload(qr string) (*QRRequestPayload, error) {
	const prefix = QRDataURIPrefix
	if len(qr) <= len(prefix) || qr[:len(prefix)] != prefix {
		return nil, fmt.Errorf("not a valid mlicense offline QR")
	}
	raw, err := crypto.Base64URLDecode(qr[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("failed to decode QR payload: %w", err)
	}

	b := raw
	if len(b) < 4 || b[0] != qrMagic || b[1] != qrBinaryVersion {
		return nil, fmt.Errorf("invalid or unsupported QR payload")
	}
	flags := b[2]

	pidLen := int(b[3])
	if pidLen < 1 || pidLen > qrMaxProductIDLen {
		return nil, fmt.Errorf("invalid product_id length")
	}
	if len(b) < 4+pidLen {
		return nil, fmt.Errorf("truncated QR payload")
	}
	pos := 4
	productID := string(b[pos : pos+pidLen])
	pos += pidLen

	machineID := ""
	if flags&qrFlagMachineUUID != 0 {
		if len(b) < pos+16 {
			return nil, fmt.Errorf("truncated QR payload (machine uuid)")
		}
		machineID = formatUUID(b[pos : pos+16])
		pos += 16
	} else {
		if len(b) < pos+1 {
			return nil, fmt.Errorf("truncated QR payload (machine id)")
		}
		mLen := int(b[pos])
		pos++
		if mLen > qrMaxMachineLen || len(b) < pos+mLen {
			return nil, fmt.Errorf("invalid machine id")
		}
		machineID = string(b[pos : pos+mLen])
		pos += mLen
	}

	if len(b) < pos+1 {
		return nil, fmt.Errorf("truncated QR payload (macs)")
	}
	macCount := int(b[pos])
	pos++
	if macCount > qrMaxMacCount {
		return nil, fmt.Errorf("invalid mac count")
	}
	if len(b) < pos+macCount*6 {
		return nil, fmt.Errorf("truncated QR payload (macs)")
	}
	macs := make([]string, 0, macCount)
	for i := 0; i < macCount; i++ {
		macs = append(macs, hex.EncodeToString(b[pos:pos+6]))
		pos += 6
	}

	challengeCode := ""
	if flags&qrFlagHasChallenge != 0 {
		if len(b) < pos+3 {
			return nil, fmt.Errorf("truncated QR payload (challenge)")
		}
		challengeCode, err = bcdDecode(b[pos : pos+3])
		if err != nil {
			return nil, fmt.Errorf("challenge_code: %w", err)
		}
		pos += 3
	}

	if len(b) < pos+16+32+4 {
		return nil, fmt.Errorf("truncated QR payload (nonce/fingerprint/expiry)")
	}
	nonce := hex.EncodeToString(b[pos : pos+16])
	pos += 16
	fingerprint := hex.EncodeToString(b[pos : pos+32])
	pos += 32
	expiresAt := int64(uint32(b[pos])<<24 | uint32(b[pos+1])<<16 | uint32(b[pos+2])<<8 | uint32(b[pos+3]))
	pos += 4

	if pos != len(b) {
		return nil, fmt.Errorf("trailing bytes in QR payload")
	}

	return &QRRequestPayload{
		Type:          qrRequestType,
		Version:       qrVersion,
		ProductID:     productID,
		Fingerprint:   fingerprint,
		MachineID:     machineID,
		MACs:          macs,
		ChallengeCode: challengeCode,
		Nonce:         nonce,
		ExpiresAt:     expiresAt,
	}, nil
}

func uint32BE(v int64) []byte {
	n := uint32(v)
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func decodeHex(s string, want int) ([]byte, error) {
	if len(s) != want*2 {
		return nil, fmt.Errorf("expected %d hex chars, got %d", want*2, len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// parseUUID returns the 16 raw bytes when s is a canonical UUID
// (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), else ok=false.
func parseUUID(s string) ([]byte, bool) {
	if len(s) != 36 {
		return nil, false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, false
	}
	compact := strings.ReplaceAll(s, "-", "")
	raw, err := hex.DecodeString(compact)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// bcdEncode packs a 6-digit zero-padded decimal string into 3 bytes.
func bcdEncode(s string) ([]byte, error) {
	if len(s) != qrMaxChallengeLen {
		return nil, fmt.Errorf("must be exactly %d digits", qrMaxChallengeLen)
	}
	out := []byte{0, 0, 0}
	for i, ch := range []byte(s) {
		if ch < '0' || ch > '9' {
			return nil, fmt.Errorf("non-digit character %q", ch)
		}
		d := ch - '0'
		if i%2 == 0 {
			out[i/2] = d << 4
		} else {
			out[i/2] |= d
		}
	}
	return out, nil
}

func bcdDecode(b []byte) (string, error) {
	if len(b) != 3 {
		return "", fmt.Errorf("challenge_code must be 3 bytes")
	}
	digits := make([]byte, 0, 6)
	for _, v := range b {
		hi, lo := v>>4, v&0x0f
		if hi > 9 || lo > 9 {
			return "", fmt.Errorf("invalid BCD byte 0x%02x", v)
		}
		digits = append(digits, '0'+hi, '0'+lo)
	}
	return string(digits), nil
}
