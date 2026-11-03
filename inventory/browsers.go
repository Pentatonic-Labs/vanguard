package inventory

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ChromiumEcosystem names browser builds in the inventory. A browser that a
// test tool downloaded is not a dpkg or rpm package, so it is reported under
// its own ecosystem rather than pretending to be "deb".
const ChromiumEcosystem = "chromium"

// versionTimeout bounds `<bin> --version` so a wedged browser cannot stall a
// scan.
const versionTimeout = 5 * time.Second

// maxBrowserScanDepth bounds the directory walk inside a browser cache.
const maxBrowserScanDepth = 6

var (
	// browserVersionRe matches the release number in a --version banner:
	// "Chromium 141.0.7390.122 built on Ubuntu 22.04", "Google Chrome for
	// Testing 141.0.7390.122", "Google Chrome 141.0.7390.122".
	browserVersionRe = regexp.MustCompile(`\b(\d+\.\d+\.\d+(?:\.\d+)?)\b`)
	// cacheBuildDirRe matches the directory a downloader unpacks a build into,
	// so the operator can be pointed at the whole stale build.
	cacheBuildDirRe = regexp.MustCompile(`^(chromium-\d+|chromium_headless_shell-\d+|linux-\d+\.\d+\.\d+\.\d+)$`)
)

// browserBinaryNames are the executable names a Chromium build ships under.
var browserBinaryNames = map[string]bool{
	"chrome":                true,
	"chromium":              true,
	"chromium-browser":      true,
	"chrome-headless-shell": true,
	"headless_shell":        true,
}

// CollectBrowsers returns the Chromium-family builds installed on this host,
// including the ones a test tool downloaded into its own cache (Playwright's
// ~/.cache/ms-playwright, Puppeteer's ~/.cache/puppeteer).
//
// This closes a blind spot: dpkg and rpm only know about browsers the distro
// installed. A host whose tests run against Playwright's bundled Chromium has a
// browser on disk that no package manager will ever upgrade, and one that can
// sit several releases behind without anything reporting it.
//
// Every build is emitted under the ChromiumEcosystem so browser advisories can
// match it, and builds that no package manager maintains are marked unmanaged.
// Builds that cannot be versioned are skipped rather than guessed at.
func CollectBrowsers() ([]Package, error) {
	return collectBrowsers(defaultBrowserRoots())
}

// browserRoots is the file-system surface the collector looks at. It is a
// struct so tests can point the collector at a fake tree.
type browserRoots struct {
	// Homes are user home directories; browser caches live under them.
	Homes []string
	// Binaries are absolute paths or globs of system browser executables or
	// the directories holding them.
	Binaries []string
}

// defaultBrowserRoots returns the locations a browser may be installed in.
func defaultBrowserRoots() browserRoots {
	return browserRoots{
		Homes: HomeDirs(),
		Binaries: []string{
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/usr/bin/google-chrome*",
			"/opt/google/chrome",
		},
	}
}

// HomeDirs lists the home directories to inspect: /root plus every directory
// directly under /home. Unreadable locations are skipped, not fatal.
func HomeDirs() []string {
	var homes []string
	if st, err := os.Stat("/root"); err == nil && st.IsDir() {
		homes = append(homes, "/root")
	}
	entries, err := os.ReadDir("/home")
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if e.IsDir() {
			homes = append(homes, filepath.Join("/home", e.Name()))
		}
	}
	return homes
}

// collectBrowsers finds and versions every browser build under roots.
func collectBrowsers(roots browserRoots) ([]Package, error) {
	type build struct {
		bin       string
		unmanaged bool
	}
	var builds []build

	for _, home := range roots.Homes {
		for _, dir := range toolCacheDirs(filepath.Join(home, ".cache")) {
			for _, bin := range findBrowserBinaries(dir) {
				builds = append(builds, build{bin: bin, unmanaged: true})
			}
		}
	}
	for _, pattern := range roots.Binaries {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, m := range matches {
			st, err := os.Stat(m)
			if err != nil {
				continue
			}
			if st.IsDir() {
				for _, bin := range findBrowserBinaries(m) {
					builds = append(builds, build{bin: bin})
				}
				continue
			}
			if isBrowserBinary(st) {
				builds = append(builds, build{bin: m})
			}
		}
	}

	seen := make(map[string]bool, len(builds))
	pkgs := make([]Package, 0, len(builds))
	for _, b := range builds {
		if seen[b.bin] {
			continue
		}
		seen[b.bin] = true
		version, err := browserVersion(b.bin)
		if err != nil || version == "" {
			continue
		}
		dir := filepath.Dir(b.bin)
		if b.unmanaged {
			dir = cacheBuildDir(b.bin)
		}
		pkgs = append(pkgs, Package{
			Name:      "chromium",
			Version:   version,
			Ecosystem: ChromiumEcosystem,
			Purl:      chromiumPurl(version, dir, b.unmanaged),
		})
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Purl != pkgs[j].Purl {
			return pkgs[i].Purl < pkgs[j].Purl
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	return pkgs, nil
}

// chromiumPurl builds the purl for a browser build. The install directory is
// a qualifier because the same version can sit in several places on one host,
// and "path" is what a fix has to name.
func chromiumPurl(version, dir string, unmanaged bool) string {
	purl := "pkg:generic/chromium@" + version + "?path=" + dir
	if unmanaged {
		purl += "&unmanaged=true"
	}
	return purl
}

// toolCacheDirs returns the directories under a home's .cache that a
// browser-downloading test tool writes to.
func toolCacheDirs(cache string) []string {
	patterns := []string{
		filepath.Join(cache, "ms-playwright", "chromium-*"),
		filepath.Join(cache, "ms-playwright", "chromium_headless_shell-*"),
		filepath.Join(cache, "puppeteer"),
	}
	var dirs []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && st.IsDir() {
				dirs = append(dirs, m)
			}
		}
	}
	return dirs
}

// findBrowserBinaries returns the browser executables at or under root, to a
// bounded depth. An unreadable subtree is skipped: a cache owned by another
// user is not an error worth failing a scan over.
func findBrowserBinaries(root string) []string {
	if _, err := os.Stat(root); err != nil {
		return nil
	}
	base := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if strings.Count(path, string(os.PathSeparator))-base > maxBrowserScanDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !browserBinaryNames[d.Name()] {
			return nil
		}
		info, err := d.Info()
		if err != nil || !isBrowserBinary(info) {
			return nil
		}
		out = append(out, path)
		return nil
	})
	sort.Strings(out)
	return out
}

// isBrowserBinary reports whether a file is an executable regular file.
func isBrowserBinary(info fs.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// cacheBuildDir returns the directory a downloaded build occupies, so a fix can
// say "delete builds under .../chromium-1187" rather than the chrome-linux
// directory inside it.
func cacheBuildDir(bin string) string {
	dir := filepath.Dir(bin)
	for d := dir; d != "" && filepath.Dir(d) != d; d = filepath.Dir(d) {
		if cacheBuildDirRe.MatchString(filepath.Base(d)) {
			return d
		}
	}
	return dir
}

// browserVersion runs `<bin> --version` and extracts the release number.
func browserVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", bin, err)
	}
	return parseBrowserVersion(string(out)), nil
}

// parseBrowserVersion extracts the release number from a --version banner.
// Every Chromium-family banner puts it in the same place, so one pattern
// covers "Chromium 141.0.7390.122 built on Ubuntu 22.04",
// "Google Chrome for Testing 141.0.7390.122" and "Google Chrome 141.0.7390.122".
func parseBrowserVersion(banner string) string {
	m := browserVersionRe.FindStringSubmatch(banner)
	if m == nil {
		return ""
	}
	return m[1]
}

// FixAdvice returns the operator action for a browser build purl produced by
// CollectBrowsers, or "" for any other package.
//
// The two cases need different words. A build a test tool downloaded is not
// upgraded by apt: the operator has to update the tool and remove the stale
// copies. A build the distro installed is an ordinary package upgrade.
func FixAdvice(purl string) string {
	dir, ok := purlQualifier(purl, "path")
	if !ok {
		return ""
	}
	if unmanaged, _ := purlQualifier(purl, "unmanaged"); unmanaged == "true" {
		return "update the tool that bundles it (e.g. Playwright) and delete old builds under " + dir
	}
	return "upgrade the package"
}

// purlQualifier returns the value of a purl qualifier such as "path".
func purlQualifier(purl, key string) (string, bool) {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return "", false
	}
	for _, kv := range strings.Split(purl[i+1:], "&") {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v, true
		}
	}
	return "", false
}
