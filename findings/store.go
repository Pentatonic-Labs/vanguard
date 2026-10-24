package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// DefaultDataDir is where findings and run state are stored by default.
const DefaultDataDir = ".vanguard"

// Load reads every *.json file in dir and returns the union of their findings.
// Each file may hold a single finding object or an array of findings. A missing
// dir yields an empty slice (not an error), so a fresh checkout renders empty.
func Load(dir string) ([]Finding, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read findings dir: %w", err)
	}
	var out []Finding
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, parseFindings(b)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Save writes findings to dir/<name>.json as an indented JSON array, creating
// the directory if needed.
func Save(dir, name string, list []Finding) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create findings dir: %w", err)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}
	return nil
}

func parseFindings(b []byte) []Finding {
	var arr []Finding
	if err := json.Unmarshal(b, &arr); err == nil {
		return arr
	}
	var one Finding
	if err := json.Unmarshal(b, &one); err == nil {
		return []Finding{one}
	}
	return nil
}
