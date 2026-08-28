//go:build darwin

package hardware

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func getMachineID() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("failed to read IOPlatformUUID: %w", err)
	}

	re := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
	matches := re.FindSubmatch(out)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to parse IOPlatformUUID")
	}
	return string(matches[1]), nil
}

func getPhysicalMACs() ([]string, error) {
	out, err := exec.Command("ifconfig").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ifconfig: %w", err)
	}

	虚拟接口 := regexp.MustCompile(`(?i)(lo[0-9]*|bridge[0-9]*|utun[0-9]*|vEthernet|vmnet|docker|vboxnet)`)

	var macs []string
	lines := strings.Split(string(out), "\n")
	var currentIface string
	for _, line := range lines {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) >= 1 {
				currentIface = strings.TrimSpace(parts[0])
			}
		}

		if 虚拟接口.MatchString(currentIface) {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ether ") {
			mac := strings.TrimPrefix(trimmed, "ether ")
			mac = strings.TrimSpace(mac)
			if mac != "" && mac != "00:00:00:00:00:00" {
				macs = append(macs, mac)
			}
		}
	}

	if len(macs) == 0 {
		return nil, fmt.Errorf("no physical MAC addresses found")
	}
	return macs, nil
}
