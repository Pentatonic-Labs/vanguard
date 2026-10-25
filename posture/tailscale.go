package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TailscaleChecker performs read-only posture checks against the local
// Tailscale node, mapping each check to the Tailworm findings
// (https://tailworm.com/ — a security assessment of Tailscale v1.104.2 and
// headscale v0.29.5).
//
// Every command it runs is a read-only `tailscale` subcommand (version,
// status, lock status, debug prefs, serve status). It never mutates node or
// tailnet state, and never probes remote peers — consistent with the posture
// package's read-only contract.
//
// Checks:
//   - tailscaled version vs the audited v1.104.2 release (no vendor fix
//     announced as of the report)
//   - tailscaled running state
//   - Tailnet Lock (disabled by default → findings 1–3 full impact chain)
//   - Tailscale SSH server on this node (findings 1, 2, 3, 5 precondition)
//   - tailnet-wide SSH capability (advisory)
//   - serve TCP→unix-socket forwards (finding 7/8)
//   - app-connector advertisement (finding 4)
//   - node key expiry (remediation: "give identities a clock")
//   - auto-update (remediation: receive the vendor fix when it ships)
//   - self-hosted headscale control plane (finding 6)
type TailscaleChecker struct {
	cfg *config
}

// NewTailscaleChecker returns a checker for the local node. No credentials are
// required: it shells out to the read-only `tailscale` client on the host.
func NewTailscaleChecker(opts ...Option) *TailscaleChecker {
	return &TailscaleChecker{cfg: applyOptions(opts)}
}

// ts runs a read-only `tailscale` subcommand and returns its combined output.
func (c *TailscaleChecker) ts(ctx context.Context, args ...string) ([]byte, error) {
	return c.cfg.runCmd(ctx, "tailscale", args...)
}

// Check runs all Tailworm posture checks against the local node.
func (c *TailscaleChecker) Check(ctx context.Context) ([]Result, error) {
	if _, err := c.ts(ctx, "version"); err != nil {
		return []Result{{
			Service: "tailscale",
			Check:   "tailscale present",
			Pass:    false,
			Detail:  "tailscale CLI not found on PATH; cannot assess Tailworm exposure",
		}}, nil
	}

	results := make([]Result, 0, 12)
	results = append(results, c.checkVersion(ctx))
	results = append(results, c.checkStatus(ctx)...)
	results = append(results, c.checkLock(ctx))
	results = append(results, c.checkPrefs(ctx)...)
	results = append(results, c.checkServe(ctx))
	return results, nil
}

// tailwormAuditedVersion is the release the Tailworm report verified its
// findings against. Releases at or below this are treated as affected until a
// vendor fix ships.
var tailwormAuditedVersion = semver{1, 104, 2}

type semver struct{ major, minor, patch int }

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

func parseSemver(s string) (semver, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return semver{major, minor, patch}, true
}

func (a semver) lessEq(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch <= b.patch
}

func (v semver) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func (c *TailscaleChecker) checkVersion(ctx context.Context) Result {
	out, err := c.ts(ctx, "version")
	if err != nil {
		return Result{Service: "tailscale", Check: "tailscaled version", Pass: false, Detail: "could not read `tailscale version`"}
	}
	v, ok := parseSemver(firstLine(out))
	if !ok {
		return Result{Service: "tailscale", Check: "tailscaled version", Pass: false, Detail: fmt.Sprintf("unparseable version %q", firstLine(out))}
	}
	if v.lessEq(tailwormAuditedVersion) {
		return Result{
			Service: "tailscale",
			Check:   "tailscaled version",
			Pass:    false,
			Detail: fmt.Sprintf(
				"tailscaled %s is at or below the audited %s; Tailworm findings apply and no vendor fix is announced as of the report — apply the operator mitigations and re-check when a fix ships",
				v.String(), tailwormAuditedVersion.String()),
		}
	}
	return Result{
		Service: "tailscale",
		Check:   "tailscaled version",
		Pass:    true,
		Detail:  fmt.Sprintf("tailscaled %s is newer than the audited release; re-verify it includes the vendor fix", v.String()),
	}
}

func (c *TailscaleChecker) checkStatus(ctx context.Context) []Result {
	const unreadable = "could not read `tailscale status --json`"
	out, err := c.ts(ctx, "status", "--json")
	if err != nil {
		return []Result{{Service: "tailscale", Check: "tailscaled running", Pass: false, Detail: unreadable}}
	}
	var st struct {
		BackendState string `json:"BackendState"`
		Self         struct {
			KeyExpiry    string                     `json:"KeyExpiry"`
			Capabilities []string                   `json:"Capabilities"`
			CapMap       map[string]json.RawMessage `json:"CapMap"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return []Result{{Service: "tailscale", Check: "tailscaled running", Pass: false, Detail: unreadable}}
	}

	state := st.BackendState
	if state == "" {
		state = "unknown"
	}
	results := []Result{{
		Service: "tailscale",
		Check:   "tailscaled running",
		Pass:    st.BackendState == "Running",
		Detail:  "backend state: " + state,
	}}

	if hasSSHCapability(st.Self.Capabilities) || hasCapMapKey(st.Self.CapMap, sshCapability) {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "tailnet-wide SSH capability",
			Pass:    false,
			Detail:  "SSH is available tailnet-wide (cap/ssh advertised); rewrite SSH rules to per-pair grants and disable forwarding per Tailworm mitigations",
		})
	} else {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "tailnet-wide SSH capability",
			Pass:    true,
			Detail:  "SSH capability not advertised to this node; Tailscale SSH not enabled tailnet-wide",
		})
	}

	results = append(results, Result{
		Service: "tailscale",
		Check:   "node key expiry",
		Pass:    keyExpirySet(st.Self.KeyExpiry),
		Detail:  keyExpiryDetail(st.Self.KeyExpiry),
	})
	return results
}

const sshCapability = "https://tailscale.com/cap/ssh"

func hasSSHCapability(caps []string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, sshCapability) {
			return true
		}
	}
	return false
}

func hasCapMapKey(m map[string]json.RawMessage, key string) bool {
	for k := range m {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func keyExpirySet(s string) bool {
	if s == "" || s == "null" {
		return false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return false
	}
	return t.Year() > 2000
}

func keyExpiryDetail(s string) string {
	if keyExpirySet(s) {
		return "node key expires at " + s
	}
	return "node has no key expiry; enable node-key expiry on server fleets so stolen identity material cannot persist indefinitely (Tailworm remediation)"
}

func (c *TailscaleChecker) checkLock(ctx context.Context) Result {
	out, err := c.ts(ctx, "lock", "status")
	if err != nil {
		return Result{Service: "tailscale", Check: "tailnet lock", Pass: false, Detail: "could not read `tailscale lock status`"}
	}
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "not enabled") {
		return Result{
			Service: "tailscale",
			Check:   "tailnet lock",
			Pass:    false,
			Detail:  "Tailnet Lock is disabled; a stolen node key can enroll a rogue device (Tailworm full impact chain). Enable Tailnet Lock.",
		}
	}
	if strings.Contains(lower, "is enabled") {
		return Result{Service: "tailscale", Check: "tailnet lock", Pass: true, Detail: "Tailnet Lock is enabled"}
	}
	return Result{Service: "tailscale", Check: "tailnet lock", Pass: false, Detail: "could not determine tailnet lock state"}
}

func (c *TailscaleChecker) checkPrefs(ctx context.Context) []Result {
	const unreadable = "could not read `tailscale debug prefs`"
	out, err := c.ts(ctx, "debug", "prefs")
	if err != nil {
		return []Result{{Service: "tailscale", Check: "tailscale prefs", Pass: false, Detail: unreadable + "; SSH-server, connector, auto-update and control-plane checks skipped"}}
	}
	var p struct {
		RunSSH       bool   `json:"RunSSH"`
		ControlURL   string `json:"ControlURL"`
		AppConnector struct {
			Advertise bool `json:"Advertise"`
		} `json:"AppConnector"`
		AutoUpdate struct {
			Check bool `json:"Check"`
			Apply bool `json:"Apply"`
		} `json:"AutoUpdate"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		return []Result{{Service: "tailscale", Check: "tailscale prefs", Pass: false, Detail: "could not parse `tailscale debug prefs`"}}
	}

	var results []Result

	if p.RunSSH {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "tailscale SSH server",
			Pass:    false,
			Detail:  "SSH server is running on this node; Tailworm findings 1–3 and 5 apply (socket forwarding runs as root). Restrict rules to per-pair grants and disable forwarding.",
		})
	} else {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "tailscale SSH server",
			Pass:    true,
			Detail:  "Tailscale SSH server is not running on this node",
		})
	}

	if p.AppConnector.Advertise {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "app connector advertised",
			Pass:    false,
			Detail:  "node advertises the app-connector capability; Tailworm finding 4 (unrestricted egress selection through the connector) applies",
		})
	} else {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "app connector advertised",
			Pass:    true,
			Detail:  "no app connector advertised on this node",
		})
	}

	if p.AutoUpdate.Check && p.AutoUpdate.Apply {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "auto-update",
			Pass:    true,
			Detail:  "auto-update enabled; the vendor fix will be applied when it ships",
		})
	} else {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "auto-update",
			Pass:    false,
			Detail:  "auto-update not fully enabled; upgrade manually when the Tailworm vendor fix ships",
		})
	}

	if isSelfHosted(p.ControlURL) {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "headscale control plane",
			Pass:    false,
			Detail:  "self-hosted control plane (" + p.ControlURL + "); Tailworm finding 6 (unauthenticated memory-exhaustion and onboarding lockout) applies — set memory limits, rate-limit registration, and restrict network exposure",
		})
	} else {
		results = append(results, Result{
			Service: "tailscale",
			Check:   "control plane",
			Pass:    true,
			Detail:  "SaaS control plane (" + p.ControlURL + "); headscale denial-of-service findings do not apply to this node",
		})
	}
	return results
}

// isSelfHosted reports whether the control URL points at a self-hosted
// headscale instance rather than the Tailscale SaaS control plane.
func isSelfHosted(controlURL string) bool {
	return controlURL != "" && !strings.Contains(controlURL, "tailscale.com")
}

func (c *TailscaleChecker) checkServe(ctx context.Context) Result {
	out, err := c.ts(ctx, "serve", "status", "--json")
	if err != nil {
		// Not configured, or an older client without serve status: no
		// TCP forwards exist to flag.
		return Result{
			Service: "tailscale",
			Check:   "serve tcp→unix forwards",
			Pass:    true,
			Detail:  "no serve configuration detected (or serve status unavailable)",
		}
	}
	var s struct {
		TCP map[string]json.RawMessage `json:"TCP"`
	}
	if err := json.Unmarshal(out, &s); err != nil {
		return Result{
			Service: "tailscale",
			Check:   "serve tcp→unix forwards",
			Pass:    false,
			Detail:  "could not parse `tailscale serve status --json`",
		}
	}
	var forwards []string
	for port, raw := range s.TCP {
		var tcp struct {
			TCPForward string `json:"TCPForward"`
		}
		if json.Unmarshal(raw, &tcp) == nil && strings.HasPrefix(strings.ToLower(tcp.TCPForward), "unix:") {
			forwards = append(forwards, port+" → "+tcp.TCPForward)
		}
	}
	if len(forwards) == 0 {
		return Result{
			Service: "tailscale",
			Check:   "serve tcp→unix forwards",
			Pass:    true,
			Detail:  "no TCP forwards target unix sockets (Tailworm finding 7 not present)",
		}
	}
	sort.Strings(forwards)
	return Result{
		Service: "tailscale",
		Check:   "serve tcp→unix forwards",
		Pass:    false,
		Detail:  "TCP forwards target unix sockets (Tailworm finding 7: remote reach into the localapi / docker.sock / systemd class): " + strings.Join(forwards, "; "),
	}
}
