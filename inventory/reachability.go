package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PackagesInUse returns the set of package names that own at least one shared
// library currently mapped by a running process. It is a Linux-only runtime
// reachability heuristic: a package whose libraries are not loaded by any live
// process is treated as not currently reachable. It returns an empty map when
// the data is unavailable (non-Linux, no dpkg, or permission errors).
func PackagesInUse() map[string]bool {
	mapped, err := mappedLibraries()
	if err != nil {
		return map[string]bool{}
	}
	inUse := make(map[string]bool)
	for path := range mapped {
		if pkg := owningPackage(path); pkg != "" {
			inUse[pkg] = true
		}
	}
	return inUse
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
