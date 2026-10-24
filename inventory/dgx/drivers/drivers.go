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
	nvrmLineRE     = regexp.MustCompile(`NVRM version:\s*NVIDIA UNIX\s+(\S+)\s+Kernel Module\s+(\S+)`)
	nvrmLineBareRE = regexp.MustCompile(`NVRM version:.*Kernel Module\s+(\S+)`)
)

// ParseProcDriverVersion parses the contents of /proc/driver/nvidia/version and
// returns the driver version (and architecture, when the line reports one). It
// is pure so it can be exercised with fixtures and without a GPU.
func ParseProcDriverVersion(contents string) (DriverInfo, error) {
	sc := bufio.NewScanner(strings.NewReader(contents))
	for sc.Scan() {
		line := sc.Text()
		if m := nvrmLineRE.FindStringSubmatch(line); m != nil {
			return DriverInfo{Arch: m[1], Version: m[2]}, nil
		}
		if m := nvrmLineBareRE.FindStringSubmatch(line); m != nil {
			return DriverInfo{Version: m[1]}, nil
		}
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
