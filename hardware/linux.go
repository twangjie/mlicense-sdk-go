//go:build linux

package hardware

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func getMachineID() (string, error) {
	paths := []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("cannot read machine-id")
}

var virtualNICRe = regexp.MustCompile(`^(lo|docker|vmnet|veth|virbr|br-|tap|tun|vEthernet|vboxnet)`)

func getPhysicalMACs() ([]string, error) {
	var macs []string
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		name := entry.Name()
		if virtualNICRe.MatchString(name) {
			continue
		}

		addrFile := filepath.Join("/sys/class/net", name, "address")
		data, err := os.ReadFile(addrFile)
		if err != nil {
			continue
		}
		addr := strings.TrimSpace(string(data))
		if addr == "00:00:00:00:00:00" || addr == "" {
			continue
		}

		operstateFile := filepath.Join("/sys/class/net", name, "operstate")
		opData, err := os.ReadFile(operstateFile)
		if err == nil && strings.TrimSpace(string(opData)) != "up" {
			continue
		}

		macs = append(macs, addr)
	}

	if len(macs) == 0 {
		return nil, fmt.Errorf("no physical MAC addresses found")
	}
	return macs, nil
}
