// Package firmware collects GPU firmware and VBIOS versions from an NVIDIA
// host and compares them against a known-good baseline.
package firmware

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// queryFields is the nvidia-smi query used to collect firmware inventory.
const queryFields = "name,vbios_version,driver_version"

// FirmwareInfo describes the firmware-facing versions reported by nvidia-smi
// for a single GPU.
type FirmwareInfo struct {
	GPUName       string
	VBIOSVersion  string
	DriverVersion string
}

// Baseline is a known-good VBIOS/driver pair for one GPU model. An empty field
// is not checked, so a partial baseline is valid.
type Baseline struct {
	VBIOSVersion  string
	DriverVersion string
}

// Deviation records a firmware value that differs from its baseline.
type Deviation struct {
	GPUName string
	Field   string // "vbios_version" or "driver_version"
	Have    string
	Want    string
}

// seedBaseline is the embedded known-good set. These are seed values for the
// DGX fleet; replace them with the fleet's pinned baseline as it is established.
var seedBaseline = map[string]Baseline{
	"NVIDIA RTX PRO 6000 Blackwell": {
		VBIOSVersion:  "98.02.55.00.0B",
		DriverVersion: "610.57.04",
	},
	"NVIDIA GB10": {
		// DGX Spark (GB10): VBIOS is not pinned yet, so it is not checked.
		DriverVersion: "580.65.06",
	},
}

// ParseSMIOutput parses the CSV emitted by:
//
//	nvidia-smi --query-gpu=name,vbios_version,driver_version --format=csv,noheader
//
// Each non-empty line is "name, vbios_version, driver_version". Blank lines are
// skipped; a line with any other field count is an error.
func ParseSMIOutput(out string) ([]FirmwareInfo, error) {
	var infos []FirmwareInfo
	for i, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 3 {
			return nil, fmt.Errorf("firmware: line %d: expected 3 CSV fields, got %d: %q", i+1, len(fields), line)
		}
		infos = append(infos, FirmwareInfo{
			GPUName:       strings.TrimSpace(fields[0]),
			VBIOSVersion:  strings.TrimSpace(fields[1]),
			DriverVersion: strings.TrimSpace(fields[2]),
		})
	}
	return infos, nil
}

// Collect runs nvidia-smi on the host and returns firmware inventory for every
// GPU it reports.
func Collect(ctx context.Context) ([]FirmwareInfo, error) {
	out, err := exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu="+queryFields, "--format=csv,noheader").Output()
	if err != nil {
		return nil, fmt.Errorf("firmware: run nvidia-smi: %w", err)
	}
	return ParseSMIOutput(string(out))
}

// CheckBaseline compares collected firmware against the embedded baseline and
// returns one deviation per mismatched, checked field. GPU models that are not
// in the baseline are ignored.
func CheckBaseline(infos []FirmwareInfo) []Deviation {
	var devs []Deviation
	for _, fi := range infos {
		base, ok := seedBaseline[fi.GPUName]
		if !ok {
			continue
		}
		if base.VBIOSVersion != "" && fi.VBIOSVersion != base.VBIOSVersion {
			devs = append(devs, Deviation{
				GPUName: fi.GPUName,
				Field:   "vbios_version",
				Have:    fi.VBIOSVersion,
				Want:    base.VBIOSVersion,
			})
		}
		if base.DriverVersion != "" && fi.DriverVersion != base.DriverVersion {
			devs = append(devs, Deviation{
				GPUName: fi.GPUName,
				Field:   "driver_version",
				Have:    fi.DriverVersion,
				Want:    base.DriverVersion,
			})
		}
	}
	return devs
}
