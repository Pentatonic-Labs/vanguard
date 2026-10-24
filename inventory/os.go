package inventory

import (
	"os"
	"strings"
)

// DetectOSID reads /etc/os-release and returns the OS ID (e.g. "ubuntu",
// "debian", "alpine"), or "" if it cannot be determined.
func DetectOSID() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "ID="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// DetectOSVersion reads /etc/os-release and returns the OS release
// (VERSION_ID, e.g. "24.04"), or "" if it cannot be determined.
func DetectOSVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "VERSION_ID="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// OSVEcosystem maps an OS ID to the OSV.dev ecosystem export name used to
// fetch that distro's vulnerability data. Matching the distro matters: Debian
// and Ubuntu version numbers live in different namespaces, so fetching the
// wrong ecosystem yields "fixed" versions that are meaningless (or even look
// like downgrades) for the installed packages.
func OSVEcosystem(osID string) string {
	switch strings.ToLower(strings.TrimSpace(osID)) {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	case "alpine":
		return "Alpine"
	default:
		// Conservative default: Debian is the most broadly applicable
		// deb-based ecosystem.
		return "Debian"
	}
}
