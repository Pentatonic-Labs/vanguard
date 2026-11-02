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
	// SourceName and SourceVersion identify the SOURCE package the binary was
	// built from, when it differs from Name (empty otherwise).
	//
	// Vulnerability databases index distro packages by source name: OSV's
	// Ubuntu records are filed under "linux-nvidia-6.17", not under the
	// binary "linux-image-6.17.0-1031-nvidia". Matching on the binary name
	// alone therefore misses every package whose binary and source names
	// differ, and the kernel is the worst case — a box could run a remotely
	// exploitable kernel CVE and report zero kernel findings.
	SourceName    string
	SourceVersion string
}

// Identities returns every way a vulnerability record might name this
// package: the binary itself, then its source package, then the source
// package with Canonical's "linux-signed-" prefix dropped.
//
// The kernel ships as three sources for one kernel: `linux-image-*
// -nvidia` comes from "linux-signed-nvidia-6.17", the modules from
// "linux-nvidia-6.17", and OSV files the CVE only under the latter. The
// signed/unsigned pairing is not a guess — it is Canonical's naming for the
// signed copy of the same build — but it is applied only to the source name
// so an unrelated binary name can never be widened.
//
// The first element is always the package itself, so a caller that emits the
// matched purl keeps naming something a package manager can install.
func (p Package) Identities() []Package {
	ids := []Package{p}
	if p.SourceName == "" || p.SourceName == p.Name {
		return ids
	}
	src := p
	src.Name = p.SourceName
	src.Version = p.SourceVersion
	src.Purl = purlFor(p.SourceName, p.SourceVersion)
	ids = append(ids, src)
	if trimmed, ok := strings.CutPrefix(p.SourceName, "linux-signed-"); ok {
		unsigned := src
		unsigned.Name = "linux-" + trimmed
		unsigned.Purl = purlFor(unsigned.Name, src.Version)
		ids = append(ids, unsigned)
	}
	return ids
}

// purlFor builds a deb purl from a name and version.
func purlFor(name, version string) string {
	if version == "" {
		return "pkg:deb/" + name
	}
	return "pkg:deb/" + name + "@" + version
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
		// Source fields are asked for explicitly: dpkg's default output is
		// binary name + version only, and that is not what the vulnerability
		// databases are keyed on.
		out, err := exec.Command("dpkg-query", "-W",
			"-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\n").Output()
		if err != nil {
			return nil, fmt.Errorf("dpkg-query: %w", err)
		}
		return parseDpkgOutput(bytes.NewReader(out))
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		// Ask for SOURCERPM: rpm, like dpkg, gives the binary name by default,
		// and the vulnerability databases index distro packages by SOURCE
		// (kernel-core is filed under "kernel"). RPM has no per-package source
		// VERSION, so the source version is parsed out of the source RPM name.
		out, err := exec.Command("rpm", "-qa",
			"--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n").Output()
		if err != nil {
			return nil, fmt.Errorf("rpm -qa: %w", err)
		}
		return parseRPMQueryOutput(bytes.NewReader(out))
	}
	return nil, fmt.Errorf("no supported package manager found (dpkg-query or rpm)")
}

// parseDpkgOutput parses `dpkg-query -W` output. Full output is
// "name<TAB>version<TAB>source<TAB>source-version" per line; the source fields
// are optional, so a two-field line (older callers and fixtures) still parses.
func parseDpkgOutput(r io.Reader) ([]Package, error) {
	var pkgs []Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			fields = strings.Fields(line)
		}
		if len(fields) < 2 {
			continue
		}
		p := Package{
			Name:      fields[0],
			Version:   fields[1],
			Purl:      purlFor(fields[0], fields[1]),
			Ecosystem: "deb",
		}
		// dpkg reports the source as "name (version)" when the version
		// differs from the binary's; the format string above gives them
		// separately, but be tolerant of the parenthesised shape anyway.
		if len(fields) >= 4 && fields[2] != "" {
			srcName := strings.TrimSpace(fields[2])
			srcVer := strings.TrimSpace(fields[3])
			if i := strings.IndexByte(srcName, ' '); i >= 0 {
				if srcVer == "" {
					srcVer = strings.Trim(srcName[i:], " ()")
				}
				srcName = srcName[:i]
			}
			if srcName != p.Name {
				p.SourceName = srcName
				if srcVer == "" {
					srcVer = p.Version
				}
				p.SourceVersion = srcVer
			}
		}
		pkgs = append(pkgs, p)
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

// parseRPMQueryOutput parses the source-aware rpm query:
// "name<TAB>version-release<TAB>sourcerpm<TAB>arch" per line. A line without
// the source columns still parses (the source is simply unknown), and lines
// where rpm reports "(none)" for SOURCERPM carry no source identity.
func parseRPMQueryOutput(r io.Reader) ([]Package, error) {
	var pkgs []Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		p := Package{Name: fields[0], Version: fields[1], Ecosystem: "rpm"}
		arch := ""
		if len(fields) >= 4 {
			arch = strings.TrimSpace(fields[3])
		}
		p.Purl = "pkg:rpm/" + p.Name + "@" + p.Version
		if arch != "" {
			p.Purl += "?arch=" + arch
		}
		if len(fields) >= 3 {
			if srcName, srcVer, ok := parseSourceRPM(fields[2]); ok && srcName != p.Name {
				p.SourceName, p.SourceVersion = srcName, srcVer
			}
		}
		pkgs = append(pkgs, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// parseSourceRPM splits an SOURCERPM value ("kernel-devel-5.14.0-362.el9.src.rpm")
// into source name and version. The name may contain dashes, the version and
// release may not, so the split is from the right: name-version-release.src.rpm.
func parseSourceRPM(s string) (name, version string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "(none)" {
		return "", "", false
	}
	s = strings.TrimSuffix(s, ".rpm")
	s = strings.TrimSuffix(s, ".src")
	// name-version-release: split off release, then version, from the right.
	i := strings.LastIndex(s, "-")
	if i <= 0 {
		return "", "", false
	}
	release := s[i+1:]
	rest := s[:i]
	j := strings.LastIndex(rest, "-")
	if j <= 0 {
		return "", "", false
	}
	ver := rest[j+1:]
	name = rest[:j]
	if name == "" || ver == "" || release == "" {
		return "", "", false
	}
	return name, ver + "-" + release, true
}
