package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// writeStubBuild creates an executable that answers `--version` with banner,
// mirroring the chromium-<rev>/chrome-linux/chrome layout a test tool unpacks.
func writeStubBuild(t *testing.T, root string, parts []string, banner string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(append([]string{root}, parts[:len(parts)-1]...)...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	bin := filepath.Join(dir, parts[len(parts)-1])
	script := "#!/bin/sh\necho '" + banner + "'\n"
	if err := os.WriteFile(bin, []byte(script), mode); err != nil {
		t.Fatalf("write stub %s: %v", bin, err)
	}
	return bin
}

func TestCollectBrowsers(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "builder")
	cache := filepath.Join(home, ".cache")

	writeStubBuild(t,
		filepath.Join(cache, "ms-playwright"),
		[]string{"chromium-1187", "chrome-linux", "chrome"},
		"Chromium 141.0.7390.122 built on Ubuntu 22.04", 0o755)
	writeStubBuild(t,
		filepath.Join(cache, "ms-playwright"),
		[]string{"chromium_headless_shell-1187", "chrome-linux", "headless_shell"},
		"Chromium 141.0.7390.122 built on Ubuntu 22.04", 0o755)
	writeStubBuild(t,
		filepath.Join(cache, "puppeteer"),
		[]string{"chrome", "linux-131.0.6778.87", "chrome-linux64", "chrome"},
		"Google Chrome for Testing 131.0.6778.87", 0o755)
	distro := writeStubBuild(t,
		filepath.Join(root, "usr", "bin"),
		[]string{"chromium"},
		"Chromium 140.0.7339.80 built on Debian 12.6, running on Debian 12.6", 0o755)
	// A non-executable file with a browser's name is not a browser.
	if err := os.WriteFile(filepath.Join(filepath.Dir(distro), "ruby3.2"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}
	notExecutable := writeStubBuild(t,
		filepath.Join(root, "opt", "google", "chrome"),
		[]string{"chrome"},
		"Google Chrome 139.0.7258.154", 0o644)

	roots := browserRoots{
		Homes: []string{home},
		Binaries: []string{
			distro,
			filepath.Join(root, "opt", "google", "chrome"),
		},
	}
	pkgs, err := collectBrowsers(roots)
	if err != nil {
		t.Fatalf("collectBrowsers: %v", err)
	}

	byPurl := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		byPurl[p.Purl] = p
	}

	wantPlaywright := "pkg:generic/chromium@141.0.7390.122?path=" +
		filepath.Join(cache, "ms-playwright", "chromium-1187") + "&unmanaged=true"
	if _, ok := byPurl[wantPlaywright]; !ok {
		t.Errorf("missing playwright build %s; got %v", wantPlaywright, purls(pkgs))
	}
	wantHeadless := "pkg:generic/chromium@141.0.7390.122?path=" +
		filepath.Join(cache, "ms-playwright", "chromium_headless_shell-1187") + "&unmanaged=true"
	if _, ok := byPurl[wantHeadless]; !ok {
		t.Errorf("missing headless shell build %s; got %v", wantHeadless, purls(pkgs))
	}
	wantPuppeteer := "pkg:generic/chromium@131.0.6778.87?path=" +
		filepath.Join(cache, "puppeteer", "chrome", "linux-131.0.6778.87") + "&unmanaged=true"
	if _, ok := byPurl[wantPuppeteer]; !ok {
		t.Errorf("missing puppeteer build %s; got %v", wantPuppeteer, purls(pkgs))
	}
	wantDistro := "pkg:generic/chromium@140.0.7339.80?path=" + filepath.Dir(distro)
	if _, ok := byPurl[wantDistro]; !ok {
		t.Errorf("missing distro build %s; got %v", wantDistro, purls(pkgs))
	}

	for _, p := range pkgs {
		if p.Ecosystem != ChromiumEcosystem {
			t.Errorf("%s: ecosystem = %q, want %q", p.Purl, p.Ecosystem, ChromiumEcosystem)
		}
		if p.Name != "chromium" {
			t.Errorf("%s: name = %q, want chromium", p.Purl, p.Name)
		}
	}

	// The non-executable copy must not be reported.
	for purl := range byPurl {
		if purl == "pkg:generic/chromium@139.0.7258.154?path="+filepath.Dir(notExecutable) {
			t.Errorf("non-executable file reported as a browser: %s", purl)
		}
	}

	if got := len(pkgs); got != 4 {
		t.Fatalf("got %d packages, want 4: %v", got, purls(pkgs))
	}
}

func purls(pkgs []Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Purl)
	}
	return out
}

func TestCollectBrowsersMissingRoots(t *testing.T) {
	pkgs, err := collectBrowsers(browserRoots{
		Homes:    []string{filepath.Join(t.TempDir(), "absent")},
		Binaries: []string{filepath.Join(t.TempDir(), "absent", "chromium")},
	})
	if err != nil {
		t.Fatalf("collectBrowsers: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("got %v, want no packages", purls(pkgs))
	}
}

func TestParseBrowserVersion(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"Chromium 141.0.7390.122 built on Ubuntu 22.04", "141.0.7390.122"},
		{"Google Chrome for Testing 141.0.7390.122 \n", "141.0.7390.122"},
		{"Google Chrome 141.0.7390.122", "141.0.7390.122"},
		{"Chromium 120.0.6099.109", "120.0.6099.109"},
		{"something went wrong", ""},
	}
	for _, tt := range tests {
		if got := parseBrowserVersion(tt.banner); got != tt.want {
			t.Errorf("parseBrowserVersion(%q) = %q, want %q", tt.banner, got, tt.want)
		}
	}
}

func TestCacheBuildDir(t *testing.T) {
	tests := []struct {
		bin  string
		want string
	}{
		{"/home/a/.cache/ms-playwright/chromium-1187/chrome-linux/chrome", "/home/a/.cache/ms-playwright/chromium-1187"},
		{"/home/a/.cache/ms-playwright/chromium_headless_shell-1187/chrome-linux/headless_shell", "/home/a/.cache/ms-playwright/chromium_headless_shell-1187"},
		{"/home/a/.cache/puppeteer/chrome/linux-131.0.6778.87/chrome-linux64/chrome", "/home/a/.cache/puppeteer/chrome/linux-131.0.6778.87"},
		{"/usr/bin/chromium", "/usr/bin"},
	}
	for _, tt := range tests {
		if got := cacheBuildDir(tt.bin); got != tt.want {
			t.Errorf("cacheBuildDir(%q) = %q, want %q", tt.bin, got, tt.want)
		}
	}
}

func TestFixAdvice(t *testing.T) {
	unmanaged := "pkg:generic/chromium@141.0.7390.122?path=/home/a/.cache/ms-playwright/chromium-1187&unmanaged=true"
	if got, want := FixAdvice(unmanaged), "update the tool that bundles it (e.g. Playwright) and delete old builds under /home/a/.cache/ms-playwright/chromium-1187"; got != want {
		t.Errorf("FixAdvice(unmanaged) = %q, want %q", got, want)
	}
	managed := "pkg:generic/chromium@140.0.7339.80?path=/usr/bin"
	if got, want := FixAdvice(managed), "upgrade the package"; got != want {
		t.Errorf("FixAdvice(managed) = %q, want %q", got, want)
	}
	if got := FixAdvice("pkg:deb/openssl@3.0.13"); got != "" {
		t.Errorf("FixAdvice(deb package) = %q, want empty", got)
	}
}
