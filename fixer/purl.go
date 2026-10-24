package fixer

import "strings"

// purlEcosystemAndName splits a purl like "pkg:golang/github.com/foo/bar@1.2.3"
// into its ecosystem ("golang") and package name ("github.com/foo/bar").
func purlEcosystemAndName(p string) (eco, name string) {
	if !strings.HasPrefix(p, "pkg:") {
		return "", ""
	}
	rest := strings.TrimPrefix(p, "pkg:")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return rest, ""
	}
	eco = rest[:i]
	nv := rest[i+1:]
	if j := strings.IndexAny(nv, "@?"); j >= 0 {
		name = nv[:j]
	} else {
		name = nv
	}
	return eco, name
}
