// Package drivers enumerates the NVIDIA driver, CUDA, and cuDNN versions on a
// DGX/NVIDIA host and flags driver/runtime disagreements.
package drivers

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ProcDriverVersionPath is where the loaded NVIDIA kernel driver reports its
// version.
const ProcDriverVersionPath = "/proc/driver/nvidia/version"

// DriverInfo describes the NVIDIA kernel driver installed on a host.
type DriverInfo struct {
	// Version is the NVIDIA driver version, e.g. "560.35.03".
	Version string
	// Arch is the userland architecture the driver reports, e.g. "x86_64".
	Arch string
	// Source records where Version was read from, e.g. ProcDriverVersionPath.
	Source string
}

var (
	// nvrmVersionRE extracts the dotted NVIDIA driver version from an NVRM
	// line. It matches the classic ("... x86_64 Kernel Module  560.35.03"),
	// the open-kernel ("... Open Kernel Module for x86_64  610.57.04"), and
	// bare ("Kernel Module  550.54.14") forms.
	nvrmVersionRE = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
	// nvrmArchRE extracts the architecture token when the line reports one.
	nvrmArchRE = regexp.MustCompile(`(x86_64|aarch64)`)
)

// ParseProcDriverVersion parses the contents of /proc/driver/nvidia/version and
// returns the driver version (and architecture, when the line reports one). It
// is pure so it can be exercised with fixtures and without a GPU.
func ParseProcDriverVersion(contents string) (DriverInfo, error) {
	sc := bufio.NewScanner(strings.NewReader(contents))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "NVRM version:") {
			continue
		}
		m := nvrmVersionRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		info := DriverInfo{Version: m[1]}
		if a := nvrmArchRE.FindStringSubmatch(line); a != nil {
			info.Arch = a[1]
		}
		return info, nil
	}
	if err := sc.Err(); err != nil {
		return DriverInfo{}, fmt.Errorf("drivers: read driver version: %w", err)
	}
	return DriverInfo{}, fmt.Errorf("drivers: no NVRM version line in %s", ProcDriverVersionPath)
}

// DetectDriver reads and parses the live driver version from the kernel.
func DetectDriver() (DriverInfo, error) {
	b, err := os.ReadFile(ProcDriverVersionPath)
	if err != nil {
		return DriverInfo{}, fmt.Errorf("drivers: read %s: %w", ProcDriverVersionPath, err)
	}
	info, err := ParseProcDriverVersion(string(b))
	if err != nil {
		return DriverInfo{}, err
	}
	info.Source = ProcDriverVersionPath
	return info, nil
}
