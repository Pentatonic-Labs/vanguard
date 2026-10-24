package platform

import "testing"

func TestParseDeviceTreeModel(t *testing.T) {
	got := ParseDeviceTreeModel("NVIDIA DGX Spark\x00\x00")
	if got != "NVIDIA DGX Spark" {
		t.Fatalf("ParseDeviceTreeModel = %q, want %q", got, "NVIDIA DGX Spark")
	}
}

func TestParseCPUInfoModel(t *testing.T) {
	x86 := "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R)\n"
	if got := ParseCPUInfoModel(x86); got != "Intel(R) Xeon(R)" {
		t.Fatalf("x86 model = %q", got)
	}
	arm := "processor\t: 0\nBogoMIPS\t: 200.00\nHardware\t: NVIDIA Grace\n"
	if got := ParseCPUInfoModel(arm); got != "NVIDIA Grace" {
		t.Fatalf("arm model = %q", got)
	}
	if got := ParseCPUInfoModel("nothing here\n"); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

func TestIsGrace(t *testing.T) {
	for _, m := range []string{"NVIDIA DGX Spark", "NVIDIA GB10", "NVIDIA Grace Hopper"} {
		if !IsGrace(m) {
			t.Errorf("IsGrace(%q) = false, want true", m)
		}
	}
	if IsGrace("Intel(R) Xeon(R)") {
		t.Error("IsGrace(Xeon) = true, want false")
	}
}

func TestMellanoxVendorID(t *testing.T) {
	if !MellanoxVendorID("0x15b3") || !MellanoxVendorID("15b3") {
		t.Error("MellanoxVendorID should accept 0x15b3 and 15b3")
	}
	if MellanoxVendorID("0x10de") {
		t.Error("MellanoxVendorID(0x10de) = true, want false")
	}
}

func TestParseMIGMode(t *testing.T) {
	if got := ParseMIGMode("Enabled\nDisabled\n"); got != "Enabled" {
		t.Fatalf("ParseMIGMode = %q", got)
	}
	if got := ParseMIGMode(""); got != "" {
		t.Fatalf("ParseMIGMode empty = %q", got)
	}
}
