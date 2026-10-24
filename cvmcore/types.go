package cvmcore

// Vuln is the canonical vulnerability record, normalized from any source.
// Every ingest adapter maps its source format into this shape.
type Vuln struct {
	ID            string         // e.g. "CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx", "USN-1234-1"
	Source        string         // one of: "kev", "osv", "nvd", "usn", "rhsa", "dsa", "msrc"
	PURLs         []string       // affected package purls (may be empty when only CPEs are known)
	CPEs          []string       // affected CPE 2.3 strings (may be empty)
	Affected      []VersionRange // affected version ranges
	Severity      string         // "critical" | "high" | "medium" | "low" | "unknown"
	CVSS          float64        // 0.0 when unknown
	EPSS          float64        // 0.0 when unknown
	InKEV         bool           // present in CISA KEV (actively exploited)
	ExploitStatus string         // "none" | "poc" | "active"
	Summary       string
}

// VersionRange is an ecosystem-specific affected range using OSV semantics:
// a package is vulnerable if its version is >= Introduced and < Fixed.
type VersionRange struct {
	Purl       string // purl of the affected package (empty means "any package")
	Ecosystem  string // e.g. "deb", "rpm", "python", "npm", "go"
	Introduced string // empty means "all versions"
	Fixed      string // empty means "no fix yet"
}

// Match couples a vulnerability to the installed packages it affects.
type Match struct {
	Vuln      Vuln
	Packages  []string // purls of matched installed packages
	Reachable bool     // whether the vulnerable code path is reachable (placeholder)
}

// Action is the remediation action decided at triage.
type Action string

const (
	ActionAutoFix Action = "auto-fix"
	ActionPropose Action = "propose"
	ActionAlert   Action = "alert"
)

// Decision is the triage output for a single match.
type Decision struct {
	Match  Match
	Action Action
	Score  float64
}
