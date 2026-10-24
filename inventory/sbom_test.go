package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSBOMToCycloneDX(t *testing.T) {
	sbom := NewSBOM([]Package{
		{Name: "libc6", Version: "2.36-9", Purl: "pkg:deb/libc6@2.36-9", Ecosystem: "deb"},
		{Name: "bash", Version: "5.2.15-2", Purl: "pkg:deb/bash@5.2.15-2", Ecosystem: "deb"},
	})

	data, err := sbom.ToCycloneDXJSON()
	if err != nil {
		t.Fatalf("ToCycloneDXJSON: %v", err)
	}

	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Components  []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", doc.BOMFormat, "CycloneDX")
	}
	if doc.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want %q", doc.SpecVersion, "1.5")
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d, want 2", len(doc.Components))
	}
	// NewSBOM sorts by name, so bash precedes libc6.
	if doc.Components[0].Name != "bash" {
		t.Errorf("components[0].name = %q, want %q", doc.Components[0].Name, "bash")
	}
	for _, c := range doc.Components {
		if c.Type == "" || c.Name == "" || c.Purl == "" {
			t.Errorf("component missing required field: %+v", c)
		}
	}
}

func TestSBOMToSPDX(t *testing.T) {
	sbom := NewSBOM([]Package{
		{Name: "openssl-libs", Version: "3.0.7-27.el9", Purl: "pkg:rpm/openssl-libs@3.0.7-27.el9?arch=x86_64", Ecosystem: "rpm"},
	})

	data, err := sbom.ToSPDXJSON()
	if err != nil {
		t.Fatalf("ToSPDXJSON: %v", err)
	}

	var doc struct {
		SPDXVersion       string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo      struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			SPDXID           string `json:"SPDXID"`
			Name             string `json:"name"`
			VersionInfo      string `json:"versionInfo"`
			DownloadLocation string `json:"downloadLocation"`
			ExternalRefs     []struct {
				ReferenceCategory string `json:"referenceCategory"`
				ReferenceType     string `json:"referenceType"`
				ReferenceLocator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal SPDX: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want %q", doc.SPDXVersion, "SPDX-2.3")
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want %q", doc.DataLicense, "CC0-1.0")
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want %q", doc.SPDXID, "SPDXRef-DOCUMENT")
	}
	if doc.Name == "" || doc.DocumentNamespace == "" {
		t.Errorf("name/namespace must be set: name=%q namespace=%q", doc.Name, doc.DocumentNamespace)
	}
	if doc.CreationInfo.Created == "" || len(doc.CreationInfo.Creators) == 0 {
		t.Errorf("creationInfo incomplete: %+v", doc.CreationInfo)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(doc.Packages))
	}
	pkg := doc.Packages[0]
	if !strings.HasPrefix(pkg.SPDXID, "SPDXRef-Package-") {
		t.Errorf("SPDXID = %q, want prefix SPDXRef-Package-", pkg.SPDXID)
	}
	if pkg.DownloadLocation != "NOASSERTION" {
		t.Errorf("downloadLocation = %q, want NOASSERTION", pkg.DownloadLocation)
	}
	if len(pkg.ExternalRefs) != 1 || pkg.ExternalRefs[0].ReferenceType != "purl" ||
		pkg.ExternalRefs[0].ReferenceLocator == "" {
		t.Errorf("missing purl external reference: %+v", pkg.ExternalRefs)
	}
}

func TestEmptySBOMEmitsEmptyArrays(t *testing.T) {
	sbom := NewSBOM(nil)

	cdx, err := sbom.ToCycloneDXJSON()
	if err != nil {
		t.Fatalf("ToCycloneDXJSON: %v", err)
	}
	if !strings.Contains(string(cdx), `"components": []`) {
		t.Errorf("CycloneDX empty SBOM should emit an empty components array:\n%s", cdx)
	}

	spdx, err := sbom.ToSPDXJSON()
	if err != nil {
		t.Fatalf("ToSPDXJSON: %v", err)
	}
	if !strings.Contains(string(spdx), `"packages": []`) {
		t.Errorf("SPDX empty SBOM should emit an empty packages array:\n%s", spdx)
	}
}

func TestParseDpkgOutput(t *testing.T) {
	fixture := "bash\t5.2.15-2+b2\nlibc6\t2.36-9+deb12u4\n\n"

	pkgs, err := parseDpkgOutput(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseDpkgOutput: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("packages = %d, want 2", len(pkgs))
	}

	want := []Package{
		{Name: "bash", Version: "5.2.15-2+b2", Purl: "pkg:deb/bash@5.2.15-2+b2", Ecosystem: "deb"},
		{Name: "libc6", Version: "2.36-9+deb12u4", Purl: "pkg:deb/libc6@2.36-9+deb12u4", Ecosystem: "deb"},
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("package[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}

func TestParseRPMOutput(t *testing.T) {
	fixture := "bash-5.2.15-2.el9.x86_64\nkernel-core-5.14.0-362.el9.x86_64\nopenssl-libs-3.0.7-27.el9.x86_64\n"

	pkgs, err := parseRPMOutput(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseRPMOutput: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("packages = %d, want 3", len(pkgs))
	}

	want := []Package{
		{Name: "bash", Version: "5.2.15-2.el9", Purl: "pkg:rpm/bash@5.2.15-2.el9?arch=x86_64", Ecosystem: "rpm"},
		{Name: "kernel-core", Version: "5.14.0-362.el9", Purl: "pkg:rpm/kernel-core@5.14.0-362.el9?arch=x86_64", Ecosystem: "rpm"},
		{Name: "openssl-libs", Version: "3.0.7-27.el9", Purl: "pkg:rpm/openssl-libs@3.0.7-27.el9?arch=x86_64", Ecosystem: "rpm"},
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("package[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}

func TestParseRPMOutputSkipsMalformed(t *testing.T) {
	// Neither a bare name nor a gpg-pubkey entry carries a NEVRA arch suffix,
	// so both must be dropped; the well-formed bash line must survive.
	fixture := "not-a-valid-nevra\ngpg-pubkey-3135ce90-5e3a9a3d\nbash-5.2.15-2.el9.x86_64\n"

	pkgs, err := parseRPMOutput(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseRPMOutput: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1 (%+v)", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "bash" {
		t.Errorf("package[0].name = %q, want %q", pkgs[0].Name, "bash")
	}
}

func TestNewSBOMSorts(t *testing.T) {
	sbom := NewSBOM([]Package{
		{Name: "zlib", Version: "1.3"},
		{Name: "acl", Version: "2.3"},
		{Name: "acl", Version: "2.2"},
	})
	got := []string{}
	for _, p := range sbom.Packages {
		got = append(got, p.Name+"@"+p.Version)
	}
	want := []string{"acl@2.2", "acl@2.3", "zlib@1.3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sorted packages = %v, want %v", got, want)
	}
}
