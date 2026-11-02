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

// A kernel ships as three sources for one build: the image comes from
// linux-signed-nvidia-6.17, the modules and headers from linux-nvidia-6.17.
// dpkg knows that; a parser that keeps only the binary name throws it away and
// nothing in the kernel can ever match a distro CVE.
func TestParseDpkgOutputSourceFields(t *testing.T) {
	const out = "linux-image-6.17.0-1031-nvidia\t6.17.0-1031.31\tlinux-signed-nvidia-6.17\t6.17.0-1031.31\n" +
		"linux-modules-6.17.0-1031-nvidia\t6.17.0-1031.31\tlinux-nvidia-6.17\t6.17.0-1031.31\n" +
		"openssl\t3.0.13-0ubuntu3.7\topenssl\t3.0.13-0ubuntu3.7\n"
	pkgs, err := parseDpkgOutput(strings.NewReader(out))
	if err != nil {
		t.Fatalf("parseDpkgOutput: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}
	if pkgs[0].SourceName != "linux-signed-nvidia-6.17" || pkgs[0].SourceVersion != "6.17.0-1031.31" {
		t.Errorf("image source = %q/%q", pkgs[0].SourceName, pkgs[0].SourceVersion)
	}
	if pkgs[1].SourceName != "linux-nvidia-6.17" {
		t.Errorf("modules source = %q", pkgs[1].SourceName)
	}
	// Same name: no second identity, so nothing downstream gets a duplicate.
	if pkgs[2].SourceName != "" || pkgs[2].SourceVersion != "" {
		t.Errorf("openssl should carry no separate source, got %q/%q", pkgs[2].SourceName, pkgs[2].SourceVersion)
	}
}

// Two-field output is what the old query produced, and fixtures elsewhere still
// use it: it must parse, just without source identities.
func TestParseDpkgOutputLegacyTwoFields(t *testing.T) {
	pkgs, err := parseDpkgOutput(strings.NewReader("bash\t5.2.15-2\n"))
	if err != nil {
		t.Fatalf("parseDpkgOutput: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "bash" || pkgs[0].Purl != "pkg:deb/bash@5.2.15-2" {
		t.Fatalf("got %+v", pkgs)
	}
	if pkgs[0].SourceName != "" {
		t.Errorf("legacy line should carry no source, got %q", pkgs[0].SourceName)
	}
}

// Identities must lead with the binary itself (so the emitted purl is something
// apt can install) and must reach the unsigned kernel source, because that is
// the only name OSV files the CVE under.
func TestPackageIdentities(t *testing.T) {
	p := Package{
		Name:          "linux-image-6.17.0-1031-nvidia",
		Version:       "6.17.0-1031.31",
		Purl:          "pkg:deb/linux-image-6.17.0-1031-nvidia@6.17.0-1031.31",
		Ecosystem:     "deb",
		SourceName:    "linux-signed-nvidia-6.17",
		SourceVersion: "6.17.0-1031.31",
	}
	ids := p.Identities()
	want := []string{
		"pkg:deb/linux-image-6.17.0-1031-nvidia@6.17.0-1031.31",
		"pkg:deb/linux-signed-nvidia-6.17@6.17.0-1031.31",
		"pkg:deb/linux-nvidia-6.17@6.17.0-1031.31",
	}
	if len(ids) != len(want) {
		t.Fatalf("got %d identities, want %d: %+v", len(ids), len(want), ids)
	}
	for i, w := range want {
		if ids[i].Purl != w {
			t.Errorf("identity %d = %q, want %q", i, ids[i].Purl, w)
		}
	}
	// A non-kernel signed source must not be rewritten into a "linux-" name.
	q := Package{Name: "foo", Version: "1", Purl: "pkg:deb/foo@1", Ecosystem: "deb",
		SourceName: "bar-signed-1", SourceVersion: "1"}
	if got := len(q.Identities()); got != 2 {
		t.Errorf("non-linux signed source produced %d identities, want 2", got)
	}
}
