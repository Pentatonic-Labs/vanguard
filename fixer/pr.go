package fixer

import (
	"fmt"
	"strings"

	"github.com/Pentatonic-Labs/vanguard/findings"
)

// Proposal is a ready-to-submit pull request. In v1 it is rendered locally;
// nothing is pushed or opened on GitHub.
type Proposal struct {
	Title string
	Body  string
	Diff  []byte
}

// Propose renders a PR title and body for the finding and its patch.
func Propose(f findings.Finding, patch []byte) Proposal {
	return Proposal{
		Title: fmt.Sprintf("fix: %s", summarize(f.Vuln.Summary)),
		Body: fmt.Sprintf(
			"## Summary\n\n%s\n\n## Finding\n\n- **ID**: %s\n- **Severity**: %s\n- **CWE**: %s\n\n## Fix\n\n%s\n\n## Patch\n\n```diff\n%s\n```\n",
			f.Vuln.Summary,
			f.ID,
			f.Vuln.Severity,
			strings.Join(f.Vuln.CWE, ", "),
			suggestion(f),
			string(patch),
		),
		Diff: patch,
	}
}

// summarize reduces a multi-line summary to a single, bounded line for a title.
func summarize(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const max = 72
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func suggestion(f findings.Finding) string {
	if f.Fix != nil && f.Fix.Suggestion != "" {
		return f.Fix.Suggestion
	}
	return "manual remediation required"
}
