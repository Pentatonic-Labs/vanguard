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
	"syscall"
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

// maxVersionOutput caps the `--version` banner read into memory.
const maxVersionOutput = 4 << 10

// nobodyUID and nobodyGID are the unprivileged identity a version probe runs
// under when the binary is owned by root. The scanner runs as root on a
// monitored host, so executing a browser binary as root would hand every local
// user code execution as root: they only have to place a file where the
// collector looks.
const (
	nobodyUID = 65534
	nobodyGID = 65534
)

// Test seams. Whether the probe drops privileges depends on the effective uid
// and on the file's owner, neither of which a test can arrange without being
// root, so both are indirected here.
var (
	execEUID     = os.Geteuid
	statPath     = os.Stat
	evalSymlinks = filepath.EvalSymlinks
)

var (
	// browserVersionRe matches the release number in a --version banner:
	// "Chromium 141.0.7390.122 built on Ubuntu 22.04", "Google Chrome for
	// Testing 141.0.7390.122", "Google Chrome 141.0.7390.122".
	browserVersionRe = regexp.MustCompile(`\b(\d+\.\d+\.\d+(?:\.\d+)?)\b`)
	// cacheBuildDirRe matches the directory a downloader unpacks a build into,
	// so the operator can be pointed at the whole stale build.
	cacheBuildDirRe = regexp.MustCompile(`^(chromium-\d+|chromium_headless_shell-\d+|linux-\d+\.\d+\.\d+\.\d+)$`)
	// fourPartVersionRe matches a browser release version such as 141.0.7390.122.
	fourPartVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
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
	return collectBrowsers(defaultBrowserRoots(), nil)
}

// CollectBrowsersWithNotes is CollectBrowsers reporting each build it refused
// to probe, and why, through note. A build that cannot be probed safely is
// skipped rather than guessed at, but the operator still needs to know it is
// there — an attacker-planted executable in a browser cache is exactly the kind
// of thing a silent skip would hide.
func CollectBrowsersWithNotes(note func(string)) ([]Package, error) {
	return collectBrowsers(defaultBrowserRoots(), note)
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

// browserCandidate is a path that looked like a browser binary, plus the
// directory it was found under (empty for system locations).
type browserCandidate struct {
	bin       string
	root      string
	unmanaged bool
}

// collectBrowsers finds and versions every browser build under roots. A
// candidate that cannot be probed safely is reported through note (when
// non-nil) and left out.
func collectBrowsers(roots browserRoots, note func(string)) ([]Package, error) {
	var cands []browserCandidate

	for _, home := range roots.Homes {
		for _, dir := range toolCacheDirs(filepath.Join(home, ".cache")) {
			for _, bin := range findBrowserBinaries(dir) {
				cands = append(cands, browserCandidate{bin: bin, root: dir, unmanaged: true})
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
					cands = append(cands, browserCandidate{bin: bin})
				}
				continue
			}
			cands = append(cands, browserCandidate{bin: m})
		}
	}

	seen := make(map[string]bool, len(cands))
	pkgs := make([]Package, 0, len(cands))
	for _, c := range cands {
		if seen[c.bin] {
			continue
		}
		seen[c.bin] = true

		bin, reason := probeablePath(c)
		if bin == "" {
			noteOnce(note, c.bin, reason)
			continue
		}

		// A version the downloader encoded in the build path needs no exec at
		// all, which is the safest probe there is.
		version := ""
		if c.unmanaged {
			version = buildDirVersion(bin)
		}
		if version == "" {
			probed, err := browserVersion(bin)
			if err == nil {
				version = probed
			}
		}
		if version == "" {
			noteOnce(note, c.bin, "no version could be read")
			continue
		}

		dir := filepath.Dir(bin)
		if c.unmanaged {
			dir = cacheBuildDir(bin)
		}
		pkgs = append(pkgs, Package{
			Name:      "chromium",
			Version:   version,
			Ecosystem: ChromiumEcosystem,
			Purl:      chromiumPurl(version, dir, c.unmanaged),
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

// noteOnce reports a skipped build, when someone is listening.
func noteOnce(note func(string), path, reason string) {
	if note != nil {
		note("skipped browser build " + path + ": " + reason)
	}
}

// probeablePath validates a candidate and returns the path that may be
// versioned, or "" and the reason it may not.
//
// The collector runs as root on a monitored host, so a file a local user can
// write must never be executed as root. Only a regular executable file is
// accepted, and inside a downloaded build (the part of the tree a user can
// write to) a symlink has to stay within that build.
func probeablePath(c browserCandidate) (string, string) {
	info, err := os.Lstat(c.bin)
	if err != nil {
		return "", "cannot stat: " + err.Error()
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := evalSymlinks(c.bin)
		if err != nil {
			return "", "unresolvable symlink: " + err.Error()
		}
		if c.unmanaged && c.root != "" && !withinDir(target, c.root) {
			return "", "symlink points outside " + c.root
		}
		targetInfo, err := statPath(target)
		if err != nil {
			return "", "symlink target cannot be stat'd: " + err.Error()
		}
		if !isBrowserBinary(targetInfo) {
			return "", "symlink target is not an executable regular file"
		}
		return target, ""
	}
	if !info.Mode().IsRegular() {
		return "", "not a regular file"
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", "not executable"
	}
	return c.bin, ""
}

// withinDir reports whether path is root or below it.
func withinDir(path, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
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

// findBrowserBinaries returns every file named like a browser binary at or
// under root, to a bounded depth. An unreadable subtree is skipped: a cache owned by another
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
		// Every match is returned, executable or not: probeablePath decides
		// what may run, and the ones it refuses are reported to the operator.
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
//
// The probe runs with a fixed working directory and a minimal environment (no
// inherited PATH, no HOME of a real user) and drops to the file's owner when
// this process is root, so a binary planted in a writable cache cannot become
// root code execution. See probeSysProcAttr.
func browserVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()

	attr, err := probeSysProcAttr(bin)
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp"}
	cmd.SysProcAttr = attr
	out := &limitedWriter{limit: maxVersionOutput}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s --version: %w", bin, err)
	}
	return parseBrowserVersion(string(out.buf)), nil
}

// probeSysProcAttr returns the attributes the version probe must run under.
//
// When this process is root, the probe is executed as the file's owner: a file
// a local user can write must never run as root, and that is the whole point of
// a browser build sitting in someone's cache. A root-owned binary (a distro
// package, /opt) runs as nobody instead, since running it as root would give the
// same escalation to anyone who can replace it.
func probeSysProcAttr(bin string) (*syscall.SysProcAttr, error) {
	if execEUID() != 0 {
		return nil, nil
	}
	uid, gid, err := fileOwner(bin)
	if err != nil {
		return nil, err
	}
	if uid == 0 {
		uid, gid = nobodyUID, nobodyGID
	}
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}, nil
}

// fileOwner returns the uid and gid owning path.
func fileOwner(path string) (uint32, uint32, error) {
	info, err := statPath(path)
	if err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("stat %s: no owner information", path)
	}
	return st.Uid, st.Gid, nil
}

// limitedWriter keeps at most limit bytes of what a child process writes and
// discards the rest, so a hostile binary cannot exhaust memory.
type limitedWriter struct {
	buf   []byte
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if room := w.limit - len(w.buf); room > 0 {
		if len(p) > room {
			w.buf = append(w.buf, p[:room]...)
		} else {
			w.buf = append(w.buf, p...)
		}
	}
	return len(p), nil
}

// buildDirVersion returns the version a downloader encoded in the build path,
// which avoids executing the binary at all. Puppeteer unpacks a browser into
// .../chrome/linux-<version>/; nothing else is known to carry the version in a
// directory name, so this returns "" for the other layouts and the caller falls
// back to the version probe.
func buildDirVersion(bin string) string {
	for d := filepath.Dir(bin); d != "" && filepath.Dir(d) != d; d = filepath.Dir(d) {
		base := filepath.Base(d)
		if v, ok := strings.CutPrefix(base, "linux-"); ok && isFourPartVersion(v) {
			return v
		}
	}
	return ""
}

// isFourPartVersion reports whether v is a browser version (141.0.7390.122).
func isFourPartVersion(v string) bool {
	return fourPartVersionRe.MatchString(v)
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
