// Package platform identifies the host SoC/CPU and the DGX-specific platform
// features that sit above the GPU: the NVIDIA Grace CPU (GB10 / DGX Spark),
// MIG mode, and DPU/ConnectX (Mellanox) NIC presence.
package platform

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Info is the platform-level inventory for one DGX/GB10 host.
type Info struct {
	SoCModel string   // e.g. "NVIDIA DGX Spark" (device-tree) or /proc/cpuinfo model
	IsGrace  bool     // true when the CPU is NVIDIA Grace (GB10)
	MIGMode  string   // nvidia-smi MIG mode ("Enabled"/"Disabled"), "" when unknown
	HasDPU   bool     // true when a Mellanox ConnectX (vendor 0x15b3) NIC is present
	NICs     []string // interface names backed by Mellanox
}

// Collect gathers platform info from the running host. Missing hardware is
// reported as zero values, never an error, so it is safe on non-DGX hosts.
func Collect() Info {
	info := Info{}
	info.SoCModel = detectSoCModel()
	info.IsGrace = IsGrace(info.SoCModel)
	info.MIGMode = detectMIGMode()
	info.NICs = detectDPUNICs("/sys/class/net")
	info.HasDPU = len(info.NICs) > 0
	return info
}

func detectSoCModel() string {
	if b, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		if m := ParseDeviceTreeModel(string(b)); m != "" {
			return m
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if m := ParseCPUInfoModel(string(b)); m != "" {
			return m
		}
	}
	return ""
}

func detectMIGMode() string {
	out, err := exec.Command(
		"nvidia-smi", "--query-gpu=mig.mode.current", "--format=csv,noheader",
	).Output()
	if err != nil {
		return ""
	}
	return ParseMIGMode(string(out))
}

func detectDPUNICs(netClassDir string) []string {
	entries, err := os.ReadDir(netClassDir)
	if err != nil {
		return nil
	}
	var nics []string
	for _, e := range entries {
		vendor, err := os.ReadFile(filepath.Join(netClassDir, e.Name(), "device", "vendor"))
		if err != nil {
			continue
		}
		if MellanoxVendorID(strings.TrimSpace(string(vendor))) {
			nics = append(nics, e.Name())
		}
	}
	return nics
}

// ParseDeviceTreeModel trims a /proc/device-tree/model read (NUL-terminated on
// ARM device trees).
func ParseDeviceTreeModel(contents string) string {
	return strings.TrimRight(strings.TrimSpace(contents), "\x00")
}

// ParseCPUInfoModel extracts the first "model name" (x86) or "Hardware" (ARM)
// line from /proc/cpuinfo output.
func ParseCPUInfoModel(contents string) string {
	sc := bufio.NewScanner(strings.NewReader(contents))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for _, key := range []string{"model name", "Hardware"} {
			if v, ok := splitKeyValue(line, key); ok {
				return v
			}
		}
	}
	return ""
}

// ParseMIGMode extracts the MIG mode token from nvidia-smi CSV output.
func ParseMIGMode(out string) string {
	first := strings.TrimSpace(strings.Split(out, "\n")[0])
	return strings.TrimSpace(first)
}

// IsGrace reports whether a SoC model string identifies NVIDIA Grace / GB10.
func IsGrace(model string) bool {
	m := strings.ToLower(model)
	for _, k := range []string{"grace", "gb10", "dgx spark", "dgx b200", "dgx b300"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}

// MellanoxVendorID reports whether a PCI vendor id string is Mellanox (0x15b3).
func MellanoxVendorID(vendor string) bool {
	v := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(vendor), "0x"))
	return v == "15b3"
}

func splitKeyValue(line, key string) (string, bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", false
	}
	if strings.TrimSpace(line[:i]) != key {
		return "", false
	}
	return strings.TrimSpace(line[i+1:]), true
}
