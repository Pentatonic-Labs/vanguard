package firmware

import "testing"

// sampleSMI is representative output of:
//
//	nvidia-smi --query-gpu=name,vbios_version,driver_version --format=csv,noheader
const sampleSMI = "NVIDIA RTX PRO 6000 Blackwell, 98.02.55.00.0B, 610.57.04\n" +
	"NVIDIA GB10, 96.00.00.00.01, 580.65.06\n"

func TestParseSMIOutput(t *testing.T) {
	infos, err := ParseSMIOutput(sampleSMI)
	if err != nil {
		t.Fatalf("ParseSMIOutput: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("want 2 GPUs, got %d", len(infos))
	}
	want := FirmwareInfo{
		GPUName:       "NVIDIA RTX PRO 6000 Blackwell",
		VBIOSVersion:  "98.02.55.00.0B",
		DriverVersion: "610.57.04",
	}
	if infos[0] != want {
		t.Fatalf("first entry = %+v, want %+v", infos[0], want)
	}
}

func TestParseSMIOutputSkipsBlankLines(t *testing.T) {
	infos, err := ParseSMIOutput("\n   \nNVIDIA GB10, 96.00.00.00.01, 580.65.06\n\n")
	if err != nil {
		t.Fatalf("ParseSMIOutput: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("want 1 GPU, got %d", len(infos))
	}
}

func TestParseSMIOutputRejectsMalformedLine(t *testing.T) {
	if _, err := ParseSMIOutput("NVIDIA GB10, 580.65.06\n"); err == nil {
		t.Fatal("expected an error for a 2-field line")
	}
}

func TestParseSMIOutputEmpty(t *testing.T) {
	infos, err := ParseSMIOutput("")
	if err != nil {
		t.Fatalf("ParseSMIOutput: %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("want 0 GPUs, got %d", len(infos))
	}
}

func TestCheckBaselineNoDeviations(t *testing.T) {
	infos := []FirmwareInfo{
		{GPUName: "NVIDIA RTX PRO 6000 Blackwell", VBIOSVersion: "98.02.55.00.0B", DriverVersion: "610.57.04"},
	}
	if devs := CheckBaseline(infos); len(devs) != 0 {
		t.Fatalf("want no deviations, got %+v", devs)
	}
}

func TestCheckBaselineVBIOSDeviation(t *testing.T) {
	infos := []FirmwareInfo{
		{GPUName: "NVIDIA RTX PRO 6000 Blackwell", VBIOSVersion: "98.02.55.00.0C", DriverVersion: "610.57.04"},
	}
	devs := CheckBaseline(infos)
	if len(devs) != 1 {
		t.Fatalf("want 1 deviation, got %d: %+v", len(devs), devs)
	}
	if devs[0].Field != "vbios_version" || devs[0].Have != "98.02.55.00.0C" || devs[0].Want != "98.02.55.00.0B" {
		t.Fatalf("unexpected deviation: %+v", devs[0])
	}
}

func TestCheckBaselineDriverDeviation(t *testing.T) {
	infos := []FirmwareInfo{
		{GPUName: "NVIDIA GB10", VBIOSVersion: "96.00.00.00.01", DriverVersion: "580.65.99"},
	}
	devs := CheckBaseline(infos)
	if len(devs) != 1 {
		t.Fatalf("want 1 deviation, got %d: %+v", len(devs), devs)
	}
	if devs[0].Field != "driver_version" || devs[0].Want != "580.65.06" {
		t.Fatalf("unexpected deviation: %+v", devs[0])
	}
}

// A GPU model absent from the baseline is ignored, and an empty baseline field
// is not checked (NVIDIA GB10 has no pinned VBIOS).
func TestCheckBaselineIgnoresUnknownAndUnpinned(t *testing.T) {
	infos := []FirmwareInfo{
		{GPUName: "Some Other GPU", VBIOSVersion: "x", DriverVersion: "y"},
		{GPUName: "NVIDIA GB10", VBIOSVersion: "anything", DriverVersion: "580.65.06"},
	}
	if devs := CheckBaseline(infos); len(devs) != 0 {
		t.Fatalf("want no deviations, got %+v", devs)
	}
}
