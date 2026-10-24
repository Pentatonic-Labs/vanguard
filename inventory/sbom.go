package inventory

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Package is a single software component, identified by its purl.
type Package struct {
	Name      string
	Version   string
	Purl      string
	Ecosystem string
}

// SBOM is a software bill of materials.
type SBOM struct {
	Packages []Package
}

// NewSBOM returns an SBOM whose packages are sorted for deterministic output.
func NewSBOM(pkgs []Package) *SBOM {
	cp := make([]Package, len(pkgs))
	copy(cp, pkgs)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Name != cp[j].Name {
			return cp[i].Name < cp[j].Name
		}
		return cp[i].Version < cp[j].Version
	})
	return &SBOM{Packages: cp}
}

// cdxComponent is a CycloneDX 1.5 component.
type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

// cdxBOM is the minimal CycloneDX 1.5 document this package emits.
type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []cdxComponent `json:"components"`
}

// ToCycloneDXJSON renders the SBOM as CycloneDX 1.5 JSON.
func (s *SBOM) ToCycloneDXJSON() ([]byte, error) {
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  make([]cdxComponent, 0, len(s.Packages)),
	}
	for _, p := range s.Packages {
		bom.Components = append(bom.Components, cdxComponent{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
			Purl:    p.Purl,
		})
	}
	return json.MarshalIndent(bom, "", "  ")
}

// spdxExternalRef is an SPDX 2.3 external reference.
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// spdxPackage is an SPDX 2.3 package entry.
type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

// spdxCreationInfo is the SPDX 2.3 creationInfo block.
type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// spdxDocument is the minimal SPDX 2.3 document this package emits.
type spdxDocument struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	Packages          []spdxPackage    `json:"packages"`
}

// ToSPDXJSON renders the SBOM as SPDX 2.3 JSON.
func (s *SBOM) ToSPDXJSON() ([]byte, error) {
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "vanguard-sbom",
		DocumentNamespace: "https://pentatonic.com/vanguard/spdx/" + s.namespaceHash(),
		CreationInfo: spdxCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: vanguard"},
		},
		Packages: make([]spdxPackage, 0, len(s.Packages)),
	}
	for i, p := range s.Packages {
		pkg := spdxPackage{
			SPDXID:           spdxID(p.Name, i),
			Name:             p.Name,
			VersionInfo:      p.Version,
			DownloadLocation: "NOASSERTION",
		}
		if p.Purl != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  p.Purl,
			}}
		}
		doc.Packages = append(doc.Packages, pkg)
	}
	return json.MarshalIndent(doc, "", "  ")
}

// namespaceHash derives a stable document namespace from the package set.
func (s *SBOM) namespaceHash() string {
	h := sha256.New()
	for _, p := range s.Packages {
		fmt.Fprintf(h, "%s@%s\n", p.Name, p.Version)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// spdxID builds a valid, unique SPDX identifier for a package.
func spdxID(name string, idx int) string {
	var b strings.Builder
	b.WriteString("SPDXRef-Package-")
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	fmt.Fprintf(&b, "-%d", idx)
	return b.String()
}

// CollectOSPackages detects the host package manager and returns the installed
// OS packages as Package values with deb or rpm purls.
func CollectOSPackages() ([]Package, error) {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
		if err != nil {
			return nil, fmt.Errorf("dpkg-query: %w", err)
		}
		return parseDpkgOutput(bytes.NewReader(out))
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.Command("rpm", "-qa").Output()
		if err != nil {
			return nil, fmt.Errorf("rpm -qa: %w", err)
		}
		return parseRPMOutput(bytes.NewReader(out))
	}
	return nil, fmt.Errorf("no supported package manager found (dpkg-query or rpm)")
}

// parseDpkgOutput parses `dpkg-query -W` output ("name<TAB>version" per line).
func parseDpkgOutput(r io.Reader) ([]Package, error) {
	var pkgs []Package
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, version := fields[0], fields[1]
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Purl:      "pkg:deb/" + name + "@" + version,
			Ecosystem: "deb",
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// parseRPMOutput parses `rpm -qa` output ("name-version-release.arch" per line).
func parseRPMOutput(r io.Reader) ([]Package, error) {
	var pkgs []Package
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, version, release, arch, ok := parseNEVRA(line)
		if !ok {
			continue
		}
		purl := "pkg:rpm/" + name + "@" + version + "-" + release
		if arch != "" {
			purl += "?arch=" + arch
		}
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version + "-" + release,
			Purl:      purl,
			Ecosystem: "rpm",
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// parseNEVRA splits an RPM name-version-release.arch string. The arch is the
// segment after the final dot; version and release are the two rightmost
// hyphen-delimited segments, so names containing hyphens are preserved.
func parseNEVRA(s string) (name, version, release, arch string, ok bool) {
	dot := strings.LastIndex(s, ".")
	if dot <= 0 || dot == len(s)-1 {
		return "", "", "", "", false
	}
	arch = s[dot+1:]
	rest := s[:dot]

	last := strings.LastIndex(rest, "-")
	if last <= 0 {
		return "", "", "", "", false
	}
	release = rest[last+1:]
	rest = rest[:last]

	prev := strings.LastIndex(rest, "-")
	if prev <= 0 {
		return "", "", "", "", false
	}
	version = rest[prev+1:]
	name = rest[:prev]

	if name == "" || version == "" || release == "" {
		return "", "", "", "", false
	}
	return name, version, release, arch, true
}
