package drivers

import "testing"

// Fixtures mirror real host output so the parsers can be exercised without a
// GPU or the NVIDIA toolchain installed.
const procDriverVersionFixture = `NVRM version: NVIDIA UNIX x86_64 Kernel Module  560.35.03  Thu Aug 22 18:38:38 UTC 2024
GCC version:  gcc version 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04)
`

const nvccFixture = `nvcc: NVIDIA (R) Cuda compiler driver
Copyright (c) 2005-2024 NVIDIA Corporation
Built on Tue_Aug_15_19:34:23_PDT_2023
Cuda compilation tools, release 12.6, V12.6.77
Build cuda_12.6.r12.6/compiler.35111979_0
`

const nvidiaSmiFixture = `+-----------------------------------------------------------------------------------------+
| NVIDIA-SMI 560.35.03              Driver Version: 560.35.03      CUDA Version: 12.6     |
|-----------------------------------------+------------------------+----------------------+
`

const cudnnHeaderFixture = `#define CUDNN_MAJOR 9
#define CUDNN_MINOR 1
#define CUDNN_PATCHLEVEL 0
`

func TestParseProcDriverVersion(t *testing.T) {
	info, err := ParseProcDriverVersion(procDriverVersionFixture)
	if err != nil {
		t.Fatalf("ParseProcDriverVersion: %v", err)
	}
	if info.Version != "560.35.03" {
		t.Errorf("Version = %q, want 560.35.03", info.Version)
	}
	if info.Arch != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", info.Arch)
	}
}

func TestParseProcDriverVersionNoArch(t *testing.T) {
	info, err := ParseProcDriverVersion("NVRM version: Kernel Module  550.54.14\n")
	if err != nil {
		t.Fatalf("ParseProcDriverVersion: %v", err)
	}
	if info.Version != "550.54.14" {
		t.Errorf("Version = %q, want 550.54.14", info.Version)
	}
}

func TestParseProcDriverVersionInvalid(t *testing.T) {
	if _, err := ParseProcDriverVersion("nothing useful here\n"); err == nil {
		t.Fatal("expected error for input without an NVRM version line")
	}
}

func TestParseNvccVersion(t *testing.T) {
	v, err := ParseNvccVersion(nvccFixture)
	if err != nil {
		t.Fatalf("ParseNvccVersion: %v", err)
	}
	if v != "12.6" {
		t.Errorf("version = %q, want 12.6", v)
	}
}

func TestParseNvidiaSmiVersion(t *testing.T) {
	v, err := ParseNvidiaSmiVersion(nvidiaSmiFixture)
	if err != nil {
		t.Fatalf("ParseNvidiaSmiVersion: %v", err)
	}
	if v != "12.6" {
		t.Errorf("version = %q, want 12.6", v)
	}
}

func TestParseCudnnHeader(t *testing.T) {
	v, err := ParseCudnnHeader(cudnnHeaderFixture)
	if err != nil {
		t.Fatalf("ParseCudnnHeader: %v", err)
	}
	if v != "9.1.0" {
		t.Errorf("version = %q, want 9.1.0", v)
	}
}

func TestParseCudnnHeaderMissing(t *testing.T) {
	if _, err := ParseCudnnHeader("no defines here\n"); err == nil {
		t.Fatal("expected error for header without CUDNN_MAJOR/MINOR")
	}
}

func TestParseCudnnSoname(t *testing.T) {
	cases := map[string]string{
		"libcudnn.so.9.1.0": "9.1.0",
		"libcudnn.so.9":     "9",
	}
	for name, want := range cases {
		got, err := ParseCudnnSoname(name)
		if err != nil {
			t.Fatalf("ParseCudnnSoname(%q): %v", name, err)
		}
		if got != want {
			t.Errorf("ParseCudnnSoname(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCudaMismatch(t *testing.T) {
	cases := []struct {
		toolkit string
		runtime string
		want    bool
	}{
		{"12.6", "12.6", false},
		{"12.6.77", "12.6", false},
		{"12.6", "12.4", true},
		{"", "12.6", false},
		{"12.6", "", false},
	}
	for _, c := range cases {
		if got := cudaMismatch(c.toolkit, c.runtime); got != c.want {
			t.Errorf("cudaMismatch(%q, %q) = %v, want %v", c.toolkit, c.runtime, got, c.want)
		}
	}
}

func TestMajorMinor(t *testing.T) {
	cases := map[string]string{
		"12.6.77": "12.6",
		"12.6":    "12.6",
		"9":       "9",
	}
	for in, want := range cases {
		if got := majorMinor(in); got != want {
			t.Errorf("majorMinor(%q) = %q, want %q", in, got, want)
		}
	}
}
