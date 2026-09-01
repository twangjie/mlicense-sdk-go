//go:build windows

package hardware

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// findCmd resolves an external Windows command to an absolute path, so the
// hardware collector does not depend on the process PATH containing the system
// directory (which some service hosts strip or set to a literal "%PATH%").
// It prefers exec.LookPath and falls back to %SystemRoot%\System32 (and
// Sysnative for WOW64) where reg.exe/netsh.exe/getmac.exe live.
func findCmd(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}

	// The external commands (reg/netsh/getmac) are Windows executables; append
	// the .exe extension when resolving against the system directory.
	exe := name
	if !strings.HasSuffix(strings.ToLower(exe), ".exe") {
		exe += ".exe"
	}

	candidates := []string{
		filepath.Join(systemRoot, "System32", exe),
		filepath.Join(systemRoot, "Sysnative", exe),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return name
}

func getMachineID() (string, error) {
	out, err := exec.Command(findCmd("reg"), "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`,
		"/v", "MachineGuid").Output()
	if err != nil {
		return "", fmt.Errorf("failed to read MachineGuid: %w", err)
	}

	re := regexp.MustCompile(`MachineGuid\s+REG_SZ\s+(\S+)`)
	matches := re.FindSubmatch(out)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to parse MachineGuid")
	}
	return string(matches[1]), nil
}

func getPhysicalMACs() ([]string, error) {
	netsh := findCmd("netsh")
	getmac := findCmd("getmac")

	out, err := exec.Command(netsh, "interface", "show", "interface").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	var ifaces []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Connected") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				ifaces = append(ifaces, parts[len(parts)-1])
			}
		}
	}

	虚拟接口 := regexp.MustCompile(`(?i)(isatap|teredo|loopback|pseudo|virtual|docker|vmware|virtualbox|hamachi)`)

	var macs []string
	for _, iface := range ifaces {
		if 虚拟接口.MatchString(iface) {
			continue
		}

		out, err := exec.Command(getmac, "/fo", "csv", "/nh").Output()
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) >= 1 {
				mac := strings.Trim(parts[0], `"`)
				ifaceName := ""
				if len(parts) >= 3 {
					ifaceName = strings.Trim(parts[2], `"`)
				}
				if strings.EqualFold(ifaceName, iface) && mac != "" && mac != "N/A" {
					macs = append(macs, mac)
					break
				}
			}
		}
	}

	if len(macs) == 0 {
		out, err := exec.Command(getmac, "/fo", "csv", "/nh").Output()
		if err == nil {
			seen := make(map[string]bool)
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ",")
				if len(parts) >= 1 {
					mac := strings.Trim(parts[0], `"`)
					if mac != "" && mac != "N/A" && !seen[strings.ToLower(mac)] {
						seen[strings.ToLower(mac)] = true
						macs = append(macs, mac)
					}
				}
			}
		}
	}

	if len(macs) == 0 {
		return nil, fmt.Errorf("no physical MAC addresses found")
	}
	return macs, nil
}
