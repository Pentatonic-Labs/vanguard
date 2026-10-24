package fixer

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

// bumpSeparator separates the "old" and "new" sides of a dependency-bump
// suggestion. A bump suggestion must contain "<old> -> <new>".
const bumpSeparator = " -> "

// parseBump extracts the old and new version strings from a dependency-bump
// suggestion of the form "old -> new".
func parseBump(suggestion string) (old, new string, err error) {
	i := strings.Index(suggestion, bumpSeparator)
	if i < 0 {
		return "", "", fmt.Errorf("not a dependency-bump suggestion (want %q): %q", "old -> new", suggestion)
	}
	old = strings.TrimSpace(suggestion[:i])
	new = strings.TrimSpace(suggestion[i+len(bumpSeparator):])
	if old == "" || new == "" {
		return "", "", fmt.Errorf("dependency-bump suggestion has empty old/new: %q", suggestion)
	}
	if old == new {
		return "", "", fmt.Errorf("dependency-bump suggestion old == new (%q)", old)
	}
	return old, new, nil
}

// Apply performs the dependency bump in the finding's fix.suggestion, editing
// the appropriate manifest file under dir, and returns the resulting unified
// diff. Known ecosystems (golang, pypi, npm) get precise single-line edits;
// unknown ecosystems fall back to a best-effort string replacement. Apply
// mutates files on disk; callers should run it against a worktree or copy,
// never a live checkout.
func Apply(f findings.Finding, dir string) ([]byte, error) {
	if f.Fix == nil {
		return nil, fmt.Errorf("finding %q has no fix", f.ID)
	}
	old, new, err := parseBump(f.Fix.Suggestion)
	if err != nil {
		return nil, err
	}
	eco, name := purlEcosystemAndName(f.Target.Ref)
	switch eco {
	case "golang":
		return editVersionLine(dir, "go.mod", name, new, goVersionInLine)
	case "pypi":
		return editVersionLine(dir, "requirements.txt", name, new, requirementsVersionInLine)
	case "npm":
		return editVersionLine(dir, "package.json", name, new, packageJSONVersionInLine)
	default:
		return replaceAllVersions(dir, old, new)
	}
}

// replaceAllVersions is the legacy, imprecise fallback: it replaces every
// occurrence of old with new in text files under dir. It is used only for
// ecosystems without a precise manifest handler.
func replaceAllVersions(dir, old, new string) ([]byte, error) {
	var out bytes.Buffer
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".venv", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil // skip binary files
		}
		if !bytes.Contains(data, []byte(old)) {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		newData := bytes.ReplaceAll(data, []byte(old), []byte(new))
		diff, err := unifiedDiff(rel, rel, data, newData)
		if err != nil {
			return err
		}
		out.Write(diff)

		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(path, newData, info.Mode().Perm())
	})
	if err != nil {
		return nil, err
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("no files under %q contain %q", dir, old)
	}
	return out.Bytes(), nil
}

// unifiedDiff returns a unified diff between old and new file content for
// in-place replacements (the line counts must match). It is a simple diff, not
// a full insert/delete diff, which is sufficient for version bumps.
func unifiedDiff(aPath, bPath string, old, new []byte) ([]byte, error) {
	aLines := splitLines(old)
	bLines := splitLines(new)
	if len(aLines) != len(bLines) {
		return nil, fmt.Errorf("replacement changed line count in %s; v1 diff only supports in-place edits", aPath)
	}

	changed := make([]bool, len(aLines))
	for i := range aLines {
		changed[i] = aLines[i] != bLines[i]
	}

	const ctx = 3 // context lines around each hunk
	type hunk struct{ start, end int }
	var hunks []hunk
	i := 0
	for i < len(aLines) {
		if !changed[i] {
			i++
			continue
		}
		h := hunk{start: i - ctx, end: i}
		if h.start < 0 {
			h.start = 0
		}
		j := i
		for j < len(aLines) {
			if changed[j] {
				h.end = j
				j++
				continue
			}
			runStart := j
			for j < len(aLines) && !changed[j] {
				j++
			}
			if j >= len(aLines) {
				h.end = j - 1
				break
			}
			if j-runStart >= 2*ctx {
				h.end = runStart + ctx - 1
				break
			}
			// short unchanged run: merge into the same hunk
		}
		if h.end >= len(aLines) {
			h.end = len(aLines) - 1
		}
		hunks = append(hunks, h)
		i = j
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- a/%s\n+++ b/%s\n", aPath, bPath)
	for _, h := range hunks {
		n := h.end - h.start + 1
		fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n", h.start+1, n, h.start+1, n)
		for x := h.start; x <= h.end; x++ {
			if changed[x] {
				fmt.Fprintf(&buf, "-%s\n+%s\n", aLines[x], bLines[x])
			} else {
				fmt.Fprintf(&buf, " %s\n", aLines[x])
			}
		}
	}
	return buf.Bytes(), nil
}

// splitLines splits content into lines, stripping a single trailing newline so
// "a\nb\n" and "a\nb" both yield ["a", "b"].
func splitLines(b []byte) []string {
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}
