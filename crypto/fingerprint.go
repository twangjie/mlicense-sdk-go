package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func ComputeFingerprint(salt string, machineID string, macs []string) string {
	sortedMACs := make([]string, len(macs))
	copy(sortedMACs, macs)
	sort.Strings(sortedMACs)

	macPart := strings.Join(sortedMACs, ":")
	raw := fmt.Sprintf("%s:%s:%s", salt, machineID, macPart)

	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func GenerateSalt() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func NormalizeMAC(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	return mac
}
