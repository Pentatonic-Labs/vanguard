package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PackagesInUse returns the set of SOURCE package names that own at least one
// shared library currently mapped by a running process. Binary packages are
// mapped back to their source package (e.g. "libssl3t64" -> "openssl") so the
// result aligns with OSV's source-package identifiers. Linux only.
func PackagesInUse() map[string]bool {
	mapped, err := mappedLibraries()
	if err != nil {
		return map[string]bool{}
	}
	src := sourcePackages()
	inUse := make(map[string]bool)
	for path := range mapped {
		if pkg := owningPackage(path); pkg != "" {
			name := pkg
			if s, ok := src[pkg]; ok {
				name = s
			}
			inUse[name] = true
		}
	}
	return inUse
}

// sourcePackages returns a map from binary package name to source package name,
// from dpkg-query.
func sourcePackages() map[string]string {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Source}\n").Output()
	if err != nil {
		return nil
	}
	m := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if pkg, src, ok := parseSourceField(line); ok {
			m[pkg] = src
		}
	}
	return m
}

// parseSourceField parses a dpkg-query line "pkg\tSource" into (binary, source)
// package names, stripping any version suffix and treating an empty source as
// equal to the binary package name.
func parseSourceField(line string) (pkg, src string, ok bool) {
	fields := strings.SplitN(line, "\t", 2)
	if len(fields) != 2 {
		return "", "", false
	}
	pkg = strings.TrimSpace(fields[0])
	src = strings.TrimSpace(fields[1])
	if pkg == "" {
		return "", "", false
	}
	if src == "" {
		src = pkg
	}
	if i := strings.IndexAny(src, " ("); i >= 0 {
		src = src[:i]
	}
	return pkg, src, true
}

// mappedLibraries returns the set of shared-library paths (".so") mapped by any
// running process, read from /proc/*/maps.
func mappedLibraries() (map[string]bool, error) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	mapped := make(map[string]bool)
	for _, p := range procs {
		if !p.IsDir() || !isNumeric(p.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", p.Name(), "maps"))
		if err != nil {
			continue // the process may have exited
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			path := fields[len(fields)-1]
			if strings.Contains(path, ".so") {
				mapped[path] = true
			}
		}
	}
	return mapped, nil
}

// owningPackage returns the package that owns path, via dpkg -S, or "" when it
// cannot be determined.
func owningPackage(path string) string {
	out, err := exec.Command("dpkg", "-S", path).Output()
	if err != nil {
		return ""
	}
	return parseDpkgSOwner(string(out))
}

// parseDpkgSOwner extracts the package name from `dpkg -S` output, e.g.
// "libssl3t64:amd64: /usr/lib/x86_64-linux-gnu/libssl.so.3" -> "libssl3t64".
func parseDpkgSOwner(output string) string {
	line := strings.SplitN(output, "\n", 2)[0]
	if i := strings.IndexByte(line, ':'); i > 0 {
		return strings.TrimSpace(line[:i])
	}
	return ""
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
