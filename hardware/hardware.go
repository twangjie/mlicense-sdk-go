package hardware

import (
	"github.com/twangjie/mlicense-sdk-go/crypto"
)

type HardwareInfo struct {
	MachineID   string   `json:"machine_id"`
	MACs        []string `json:"macs"`
	Fingerprint string   `json:"fingerprint"`
}

func Collect(salt string) (*HardwareInfo, error) {
	machineID, err := getMachineID()
	if err != nil {
		return nil, err
	}

	macs, err := getPhysicalMACs()
	if err != nil {
		return nil, err
	}

	normalizedMACs := make([]string, len(macs))
	for i, mac := range macs {
		normalizedMACs[i] = crypto.NormalizeMAC(mac)
	}

	fingerprint := crypto.ComputeFingerprint(salt, machineID, normalizedMACs)

	return &HardwareInfo{
		MachineID:   machineID,
		MACs:        normalizedMACs,
		Fingerprint: fingerprint,
	}, nil
}
