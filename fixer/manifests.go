package fixer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// versionLocator finds the byte range of the version token on a manifest line
// that declares `name`, returning ok=false when the line is not the
// declaration. The returned range covers only the numeric version, so any range
// prefix ("v", "^", "~", ">=", ...) is preserved by the edit.
type versionLocator func(line, name string) (start, end int, ok bool)

// editVersionLine finds the single line in filename that declares name and
// replaces its version token with version, returning a unified diff. Only that
// one line is modified.
func editVersionLine(dir, filename, name, version string, loc versionLocator) ([]byte, error) {
	path := filepath.Join(dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filename, err)
	}
	lines := splitLines(data)
	var out bytes.Buffer
	edited := false
	for _, line := range lines {
		s, e, ok := loc(line, name)
		if !ok {
			out.WriteString(line + "\n")
			continue
		}
		out.WriteString(line[:s] + version + line[e:] + "\n")
		edited = true
	}
	if !edited {
		return nil, fmt.Errorf("%s not found in %s", name, filename)
	}
	newData := out.Bytes()
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, newData, info.Mode().Perm()); err != nil {
		return nil, fmt.Errorf("write %s: %w", filename, err)
	}
	return unifiedDiff(filename, filename, data, newData)
}

// versionNumberStart returns the byte offset of the first digit in a version
// spec, so range prefixes ("v", "^", "~", ">=", ...) are preserved.
func versionNumberStart(spec string) int {
	for i := 0; i < len(spec); i++ {
		if spec[i] >= '0' && spec[i] <= '9' {
			return i
		}
	}
	return 0
}

// goVersionInLine locates the version token on a go.mod require line, handling
// both the single-line form ("require <module> <version>") and indented block
// entries ("<module> <version>").
func goVersionInLine(line, module string) (start, end int, ok bool) {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "require ")
	fields := strings.Fields(trimmed)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == module {
			idx := strings.Index(line, fields[i+1])
			if idx >= 0 {
				return idx + versionNumberStart(fields[i+1]), idx + len(fields[i+1]), true
			}
		}
	}
	return 0, 0, false
}

// requirementsVersionInLine locates the version token on a requirements.txt
// line of the form "name<op>version".
func requirementsVersionInLine(line, pkg string) (start, end int, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return 0, 0, false
	}
	for _, op := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"} {
		prefix := pkg + op
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		fields := strings.Fields(trimmed[len(prefix):])
		if len(fields) == 0 {
			return 0, 0, false
		}
		idx := strings.Index(line, fields[0])
		if idx >= 0 {
			return idx + versionNumberStart(fields[0]), idx + len(fields[0]), true
		}
	}
	return 0, 0, false
}

// packageJSONVersionInLine locates the version token on a package.json
// dependency line of the form `"name": "version"`.
func packageJSONVersionInLine(line, pkg string) (start, end int, ok bool) {
	needle := `"` + pkg + `": "`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return 0, 0, false
	}
	start = idx + len(needle)
	if endQ := strings.IndexByte(line[start:], '"'); endQ >= 0 {
		end := start + endQ
		return start + versionNumberStart(line[start:end]), end, true
	}
	return 0, 0, false
}
