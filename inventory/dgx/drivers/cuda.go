package drivers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// CUDAInfo describes the CUDA toolkit and runtime versions on a host.
type CUDAInfo struct {
	// Toolkit is the CUDA toolkit version reported by nvcc, e.g. "12.6".
	Toolkit string
	// Runtime is the CUDA version supported by the loaded driver, from
	// nvidia-smi, e.g. "12.6".
	Runtime string
	// ToolkitSource and RuntimeSource record where each value came from.
	ToolkitSource string
	RuntimeSource string
}

// CuDNNInfo describes the cuDNN library version on a host.
type CuDNNInfo struct {
	// Version is the cuDNN version, e.g. "9.1.0".
	Version string
	// Source records where Version was read from.
	Source string
}

// Report aggregates a DGX driver and CUDA/cuDNN enumeration.
type Report struct {
	Driver DriverInfo
	CUDA   CUDAInfo
	CuDNN  CuDNNInfo

	// Mismatch reports a CUDA driver/runtime disagreement: the CUDA version
	// supported by the loaded driver (nvidia-smi) differs in major.minor from
	// the CUDA toolkit reported by nvcc.
	Mismatch bool
	// MismatchDetail explains Mismatch when it is true.
	MismatchDetail string

	// Errors collects non-fatal collection failures.
	Errors []string
}

var (
	nvccReleaseRE = regexp.MustCompile(`release\s+(\d+\.\d+)`)
	smiCUDARE     = regexp.MustCompile(`CUDA Version:\s*(\d+\.\d+)`)

	cudnnMajorRE  = regexp.MustCompile(`#define\s+CUDNN_MAJOR\s+(\d+)`)
	cudnnMinorRE  = regexp.MustCompile(`#define\s+CUDNN_MINOR\s+(\d+)`)
	cudnnPatchRE  = regexp.MustCompile(`#define\s+CUDNN_PATCH(?:LEVEL)?\s+(\d+)`)
	cudnnSonameRE = regexp.MustCompile(`libcudnn\.so\.(\d+(?:\.\d+)*)`)
)

// ParseNvccVersion extracts the CUDA toolkit version from `nvcc --version`
// output, e.g. "Cuda compilation tools, release 12.6, V12.6.77" -> "12.6".
func ParseNvccVersion(out string) (string, error) {
	if m := nvccReleaseRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("drivers: no CUDA release in nvcc output")
}

// ParseNvidiaSmiVersion extracts the CUDA version from the nvidia-smi header,
// e.g. "CUDA Version: 12.6" -> "12.6".
func ParseNvidiaSmiVersion(out string) (string, error) {
	if m := smiCUDARE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("drivers: no CUDA Version in nvidia-smi output")
}

// ParseCudnnHeader extracts the cuDNN version from a cudnn_version.h header.
// The patch level defaults to 0 when the header omits it.
func ParseCudnnHeader(contents string) (string, error) {
	major, minor, patch := -1, -1, 0
	if m := cudnnMajorRE.FindStringSubmatch(contents); m != nil {
		major = mustAtoi(m[1])
	}
	if m := cudnnMinorRE.FindStringSubmatch(contents); m != nil {
		minor = mustAtoi(m[1])
	}
	if m := cudnnPatchRE.FindStringSubmatch(contents); m != nil {
		patch = mustAtoi(m[1])
	}
	if major < 0 || minor < 0 {
		return "", fmt.Errorf("drivers: cudnn_version.h missing CUDNN_MAJOR/MINOR")
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
}

// ParseCudnnSoname extracts the cuDNN version from a library soname such as
// "libcudnn.so.9.1.0" -> "9.1.0".
func ParseCudnnSoname(name string) (string, error) {
	if m := cudnnSonameRE.FindStringSubmatch(name); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("drivers: %q is not a libcudnn soname", name)
}

// majorMinor returns the leading "major.minor" of a dotted version string.
func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// cudaMismatch reports whether the toolkit and driver runtime CUDA versions
// disagree in major.minor. Empty inputs are never treated as a mismatch.
func cudaMismatch(toolkit, runtime string) bool {
	if toolkit == "" || runtime == "" {
		return false
	}
	return majorMinor(toolkit) != majorMinor(runtime)
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// detectNvcc returns the CUDA toolkit version reported by nvcc.
func detectNvcc() (string, error) {
	out, err := exec.Command("nvcc", "--version").Output()
	if err != nil {
		return "", fmt.Errorf("drivers: nvcc --version: %w", err)
	}
	return ParseNvccVersion(string(out))
}

// detectNvidiaSmi returns the CUDA version supported by the loaded driver.
func detectNvidiaSmi() (string, error) {
	out, err := exec.Command("nvidia-smi").Output()
	if err != nil {
		return "", fmt.Errorf("drivers: nvidia-smi: %w", err)
	}
	return ParseNvidiaSmiVersion(string(out))
}

// cudnnHeaderPath is where cuDNN's version macros usually live.
const cudnnHeaderPath = "/usr/include/cudnn_version.h"

var cudnnLibGlobs = []string{
	"/usr/lib/x86_64-linux-gnu/libcudnn.so.*",
	"/usr/lib64/libcudnn.so.*",
	"/usr/lib/libcudnn.so.*",
	"/usr/local/cuda/lib64/libcudnn.so.*",
}

// detectCudnn returns the cuDNN version and the source it was read from.
func detectCudnn() (string, string, error) {
	if b, err := os.ReadFile(cudnnHeaderPath); err == nil {
		if v, err := ParseCudnnHeader(string(b)); err == nil {
			return v, cudnnHeaderPath, nil
		}
	}
	for _, pattern := range cudnnLibGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if v, err := ParseCudnnSoname(filepath.Base(m)); err == nil {
				return v, m, nil
			}
		}
	}
	return "", "", fmt.Errorf("drivers: cuDNN version not found")
}

// Detect enumerates the driver, CUDA, and cuDNN versions on the host. Driver
// detection is fatal; CUDA and cuDNN are best-effort and any failure is
// recorded in Report.Errors.
func Detect() (Report, error) {
	var r Report

	drv, err := DetectDriver()
	if err != nil {
		return r, err
	}
	r.Driver = drv

	if v, err := detectNvcc(); err != nil {
		r.Errors = append(r.Errors, err.Error())
	} else {
		r.CUDA.Toolkit = v
		r.CUDA.ToolkitSource = "nvcc --version"
	}

	if v, err := detectNvidiaSmi(); err != nil {
		r.Errors = append(r.Errors, err.Error())
	} else {
		r.CUDA.Runtime = v
		r.CUDA.RuntimeSource = "nvidia-smi"
	}

	if v, src, err := detectCudnn(); err != nil {
		r.Errors = append(r.Errors, err.Error())
	} else {
		r.CuDNN.Version = v
		r.CuDNN.Source = src
	}

	if cudaMismatch(r.CUDA.Toolkit, r.CUDA.Runtime) {
		r.Mismatch = true
		r.MismatchDetail = fmt.Sprintf(
			"nvcc reports CUDA %s but the loaded driver supports CUDA %s",
			r.CUDA.Toolkit, r.CUDA.Runtime)
	}

	return r, nil
}
