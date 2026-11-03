package posture

// This file holds the on-host runtime posture checks: what this machine is
// actually doing right now, rather than what a SaaS API says about it. Every
// check is read-only. Paths are resolved under a configurable root so the same
// code can be pointed at a mounted snapshot (or a fixture tree in tests) and
// never has to touch the host it runs on.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ServiceName is the Service value used by the on-host runtime checks.
const ServiceName = "runtime"

// DefaultSensitivePorts are ports that should never listen on every interface:
// common model-serving servers (8000, 8043, 8787, 8790, 8888, 8890, 9800), the
// Node inspector (9229) and the Chrome DevTools protocol (9222).
var DefaultSensitivePorts = []int{8000, 8043, 8787, 8790, 8888, 8890, 9222, 9229, 9800}

// browserBinaries are the Chromium-family executable names that honour
// --no-sandbox. Matching is on argv[0]'s base name only.
var browserBinaries = map[string]bool{
	"chrome":                true,
	"chromium":              true,
	"chromium-browser":      true,
	"headless_shell":        true,
	"chrome-headless-shell": true,
}

// Runtime runs read-only on-host posture checks under Root (normally "/").
//
// The zero value is not usable: call NewRuntime. Fields are exported so callers
// (and tests) can widen or narrow what counts as a sensitive listener.
type Runtime struct {
	Root            string
	SensitivePorts  []int
	WorkerPortRange [2]int   // high ports that are sensitive only when a worker owns them
	WorkerUsers     []string // process users that make a high port sensitive
	Now             time.Time
	AptTimeout      time.Duration
	// RunApt simulates an upgrade and returns apt-get's output. It is
	// injectable so tests never shell out to the host's package manager; when
	// nil, the check shells out only if Root is the live filesystem.
	RunApt func(ctx context.Context, timeout time.Duration) ([]byte, error)
}

// NewRuntime returns a Runtime reading from root ("" and "/" both mean the
// live filesystem).
func NewRuntime(root string) *Runtime {
	if root == "" {
		root = "/"
	}
	return &Runtime{
		Root:            root,
		SensitivePorts:  DefaultSensitivePorts,
		WorkerPortRange: [2]int{30000, 65535},
		WorkerUsers:     []string{"node", "workerd"},
		Now:             time.Now(),
		AptTimeout:      60 * time.Second,
		RunApt:          nil, // the live apt-get, unless a caller or test injects one
	}
}

func (r *Runtime) path(elem ...string) string {
	return filepath.Join(append([]string{r.Root}, elem...)...)
}

// Results runs every on-host check. Checks report problems as failing Results
// with evidence and a fix, never as errors: a host where a file is missing is a
// reportable posture state, not a broken checker.
func (r *Runtime) Results(ctx context.Context) []Result {
	var out []Result
	out = append(out, r.UnsandboxedBrowsers()...)
	out = append(out, r.WildcardListeners()...)
	out = append(out, r.PatchLag(ctx)...)
	out = append(out, r.PendingReboot()...)
	return out
}

// pass reports a check that found nothing to fix.
func pass(check, detail string) Result {
	return Result{Service: ServiceName, Check: check, Pass: true, Detail: detail}
}

// ---------------------------------------------------------------------------
// Unsandboxed browsers
// ---------------------------------------------------------------------------

// procInfo is the slice of /proc/<pid> the browser check needs.
type procInfo struct {
	pid  int
	argv []string
	name string // /proc/<pid>/status Name (kernel comm)
	uid  string
	ppid int
}

// UnsandboxedBrowsers flags Chromium-family processes started with
// --no-sandbox. Renderers and zygotes inherit the flag from the browser root,
// so children are collapsed into one finding per root process.
func (r *Runtime) UnsandboxedBrowsers() []Result {
	const check = "unsandboxed browsers"
	procs := r.processes()
	users := r.passwdUsers()

	var results []Result
	for _, pid := range sortedPids(procs) {
		p := procs[pid]
		if len(p.argv) == 0 || !browserBinaries[filepath.Base(p.argv[0])] {
			continue
		}
		if !hasFlag(p.argv[1:], "--no-sandbox") || isBrowserChild(p, procs) {
			continue
		}

		remote := hasFlagPrefix(p.argv[1:], "--remote-debugging-")
		user, home := users.lookup(p.uid)
		keys := hasSSHKeys(r.homePath(home))

		severity := "medium"
		if remote || keys {
			severity = "high"
		}

		parent := "unknown"
		if pp, ok := procs[p.ppid]; ok && pp.name != "" {
			parent = pp.name
		}
		evidence := fmt.Sprintf("pid %d, user %q, binary %s, parent %q", p.pid, user, p.argv[0], parent)
		if remote {
			evidence += ", remote debugging enabled"
		}
		if keys {
			evidence += ", the user's home holds SSH keys"
		}
		results = append(results, Result{
			Service:  ServiceName,
			Check:    check,
			Pass:     false,
			Severity: severity,
			Detail:   evidence,
			Fix: "Drop --no-sandbox: it removes the browser's process sandbox, so a hostile page can " +
				"run code as that user. Run the browser in a container with its own user namespace instead.",
		})
	}

	if len(results) == 0 {
		return []Result{pass(check, "no Chromium-family process is running with --no-sandbox")}
	}
	return results
}

// isBrowserChild reports whether p is a Chromium helper (renderer, zygote, GPU
// process) rather than the root of a browser. Helpers either carry an explicit
// --type= role or are the very same binary launched by the same binary.
func isBrowserChild(p procInfo, procs map[int]procInfo) bool {
	if hasFlagPrefix(p.argv[1:], "--type=") {
		return true
	}
	parent, ok := procs[p.ppid]
	if !ok || len(parent.argv) == 0 {
		return false
	}
	return parent.argv[0] == p.argv[0] && browserBinaries[filepath.Base(parent.argv[0])]
}

// hasFlag reports whether args contains name exactly.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// hasFlagPrefix reports whether any arg starts with prefix.
func hasFlagPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// userDB maps a uid string to the user name and home directory from passwd.
type userDB map[string]struct{ name, home string }

func (u userDB) lookup(uid string) (name, home string) {
	if e, ok := u[uid]; ok {
		return e.name, e.home
	}
	return "uid " + uid, ""
}

// passwdUsers reads etc/passwd under the root. A missing file yields an empty
// map: the checks then report the numeric uid instead of a name.
func (r *Runtime) passwdUsers() userDB {
	users := userDB{}
	data, err := os.ReadFile(r.path("etc/passwd"))
	if err != nil {
		return users
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 6 || strings.HasPrefix(f[0], "#") {
			continue
		}
		users[f[2]] = struct{ name, home string }{name: f[0], home: f[5]}
	}
	return users
}

// hasSSHKeys reports whether home holds private keys (a .ssh/id_* file).
func hasSSHKeys(home string) bool {
	if home == "" {
		return false
	}
	matches, err := filepath.Glob(filepath.Join(home, ".ssh", "id_*"))
	return err == nil && len(matches) > 0
}

// homePath resolves a passwd home directory under the configured root, so the
// check reads a fixture tree or a mounted snapshot rather than the live host.
func (r *Runtime) homePath(home string) string {
	if home == "" {
		return ""
	}
	return r.path(strings.TrimPrefix(home, string(filepath.Separator)))
}

// processes reads /proc/<pid>/{cmdline,status} for every numeric pid directory.
// Processes that vanish or are unreadable are skipped.
func (r *Runtime) processes() map[int]procInfo {
	procs := map[int]procInfo{}
	entries, err := os.ReadDir(r.path("proc"))
	if err != nil {
		return procs
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(r.path("proc", e.Name(), "cmdline"))
		if err != nil {
			// Unreadable cmdline (kernel thread, or already gone): keep the
			// pid so it can still be reported as a parent.
			raw = nil
		}
		p := procInfo{pid: pid, argv: splitCmdline(raw)}
		if status, err := os.ReadFile(r.path("proc", e.Name(), "status")); err == nil {
			p.name, p.uid, p.ppid = parseStatus(string(status))
		}
		procs[pid] = p
	}
	return procs
}

// splitCmdline splits a NUL-separated /proc/<pid>/cmdline.
func splitCmdline(raw []byte) []string {
	var argv []string
	for _, field := range strings.Split(string(raw), "\x00") {
		if field != "" {
			argv = append(argv, field)
		}
	}
	return argv
}

// parseStatus pulls Name, Uid and PPid out of a /proc/<pid>/status body.
func parseStatus(status string) (name, uid string, ppid int) {
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Name":
			name = value
		case "Uid":
			uid = strings.Fields(value)[0]
		case "PPid":
			ppid, _ = strconv.Atoi(value)
		}
	}
	return name, uid, ppid
}

// sortedPids returns the pids in ascending order so output is deterministic.
func sortedPids(procs map[int]procInfo) []int {
	pids := make([]int, 0, len(procs))
	for pid := range procs {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids
}

// ---------------------------------------------------------------------------
// Wildcard listeners
// ---------------------------------------------------------------------------

// WildcardListeners flags sensitive ports listening on every interface
// (0.0.0.0 or ::), read from /proc/net/tcp and /proc/net/tcp6. Whether such a
// port is reachable off-box is a network question and not answered here.
func (r *Runtime) WildcardListeners() []Result {
	const check = "wildcard listener"
	users := r.passwdUsers()
	owners := r.socketOwners()

	var results []Result
	for _, file := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		data, err := os.ReadFile(r.path(file))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			l, ok := parseListenLine(line)
			if !ok || !l.wildcard {
				continue
			}
			user, _ := users.lookup(l.uid)
			if !r.sensitivePort(l.port, user) {
				continue
			}

			evidence := fmt.Sprintf("port %d on %s, user %q", l.port, l.address, user)
			if pid, ok := owners[l.inode]; ok {
				evidence += fmt.Sprintf(", pid %d", pid)
				if comm, err := os.ReadFile(r.path("proc", strconv.Itoa(pid), "comm")); err == nil {
					evidence += fmt.Sprintf(" (%s)", strings.TrimSpace(string(comm)))
				}
			}
			results = append(results, Result{
				Service:  ServiceName,
				Check:    check,
				Pass:     false,
				Severity: "high",
				Detail:   evidence,
				Fix: fmt.Sprintf("Bind the service to 127.0.0.1 (or one specific interface) instead of 0.0.0.0 "+
					"and reach port %d through an SSH tunnel or an authenticating reverse proxy.", l.port),
			})
		}
	}

	if len(results) == 0 {
		return []Result{pass(check, "no sensitive port is listening on 0.0.0.0 or ::")}
	}
	return results
}

// sensitivePort reports whether a wildcard listener on port matters: either it
// is on the configured list, or it is a high port owned by a worker user.
func (r *Runtime) sensitivePort(port int, user string) bool {
	for _, p := range r.SensitivePorts {
		if p == port {
			return true
		}
	}
	if port < r.WorkerPortRange[0] || port > r.WorkerPortRange[1] {
		return false
	}
	for _, u := range r.WorkerUsers {
		if u == user {
			return true
		}
	}
	return false
}

// listenLine is one LISTEN row from /proc/net/tcp{,6}.
type listenLine struct {
	address  string // "0.0.0.0" or "[::]"
	port     int
	wildcard bool
	uid      string
	inode    string
}

// parseListenLine parses a /proc/net/tcp{,6} row, returning ok only for rows in
// the LISTEN state (0A).
func parseListenLine(line string) (listenLine, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 || fields[3] != "0A" {
		return listenLine{}, false
	}
	addrHex, portHex, ok := strings.Cut(fields[1], ":")
	if !ok {
		return listenLine{}, false
	}
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return listenLine{}, false
	}
	l := listenLine{
		address:  "0.0.0.0",
		port:     int(port),
		wildcard: strings.Trim(addrHex, "0") == "",
		uid:      fields[7],
		inode:    fields[9],
	}
	if len(addrHex) > 8 {
		l.address = "[::]"
	}
	return l, true
}

// socketOwners maps a socket inode to the pid holding it, by scanning
// /proc/<pid>/fd for "socket:[<inode>]" links. It is best effort: processes the
// caller cannot inspect are simply absent.
func (r *Runtime) socketOwners() map[string]int {
	owners := map[string]int{}
	entries, err := os.ReadDir(r.path("proc"))
	if err != nil {
		return owners
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		fdDir := r.path("proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			pid, _ := strconv.Atoi(e.Name())
			owners[inode] = pid
		}
	}
	return owners
}

// ---------------------------------------------------------------------------
// Patch lag
// ---------------------------------------------------------------------------

// PatchLag reports whether this host patches itself. It is Debian/Ubuntu only:
// hosts without a dpkg database get a single passing "not applicable" result.
//
// Pending security updates come from a read-only `apt-get -s upgrade`; apt's
// simulation carries no publish dates, so "how old is the pending fix" is
// approximated by how long it has been since the last successful upgrade.
func (r *Runtime) PatchLag(ctx context.Context) []Result {
	const (
		checkUnattended = "unattended upgrades"
		checkSecurity   = "pending security updates"
	)
	status, err := os.ReadFile(r.path("var/lib/dpkg/status"))
	if err != nil {
		return []Result{pass(checkSecurity, "no dpkg database (not Debian/Ubuntu); patch lag checks skipped")}
	}

	var out []Result
	installed := dpkgInstalled(string(status), "unattended-upgrades")
	enabled := r.unattendedUpgradesEnabled()
	switch {
	case !installed:
		out = append(out, Result{
			Service: ServiceName, Check: checkUnattended, Severity: "high",
			Detail: "unattended-upgrades is not installed",
			Fix:    "Install unattended-upgrades and enable it so security updates are applied without waiting for someone to log in.",
		})
	case !enabled:
		out = append(out, Result{
			Service: ServiceName, Check: checkUnattended, Severity: "medium",
			Detail: "unattended-upgrades is installed but not enabled",
			Fix:    `Set APT::Periodic::Unattended-Upgrade "1"; in /etc/apt/apt.conf.d/20auto-upgrades (or enable the unattended-upgrades timer).`,
		})
	default:
		out = append(out, pass(checkUnattended, "unattended-upgrades is installed and enabled"))
	}

	pending, aptErr := r.pendingSecurityUpdates(ctx)
	days, haveDays := r.daysSinceLastUpgrade()
	switch {
	case aptErr != nil:
		out = append(out, Result{
			Service: ServiceName, Check: checkSecurity, Pass: true,
			Detail: fmt.Sprintf("unknown, not zero: %v", aptErr),
			Fix:    "Re-run the check once apt's database is readable; the count is unknown rather than zero.",
		})
	case pending == 0:
		out = append(out, pass(checkSecurity, fmt.Sprintf("no pending security updates%s", daysNote(days, haveDays))))
	default:
		severity := "medium"
		if haveDays && days > 7 {
			severity = "high"
		}
		out = append(out, Result{
			Service: ServiceName, Check: checkSecurity, Severity: severity,
			Detail: fmt.Sprintf("%d security update(s) pending%s", pending, daysNote(days, haveDays)),
			Fix:    "Apply the security updates (`apt-get upgrade`) and find out why they are not being applied automatically.",
		})
	}
	return out
}

// daysNote renders the last-upgrade age for a result detail.
func daysNote(days int, ok bool) string {
	if !ok {
		return ", no upgrade recorded in the dpkg log"
	}
	return fmt.Sprintf(", last upgrade %d day(s) ago", days)
}

// dpkgInstalled reports whether name is installed according to a dpkg status
// file.
func dpkgInstalled(status, name string) bool {
	for _, stanza := range strings.Split(status, "\n\n") {
		if !strings.Contains(stanza, "Package: "+name+"\n") && !strings.HasSuffix(stanza, "Package: "+name) {
			continue
		}
		if strings.Contains(stanza, "Status: install ok installed") {
			return true
		}
	}
	return false
}

// unattendedUpgradesEnabled reports whether the host runs unattended-upgrades,
// through apt's periodic configuration or the systemd timer that most current
// releases ship instead.
func (r *Runtime) unattendedUpgradesEnabled() bool {
	if _, err := os.Stat(r.path("etc/systemd/system/timers.target.wants/unattended-upgrades.timer")); err == nil {
		return true
	}
	entries, err := os.ReadDir(r.path("etc/apt/apt.conf.d"))
	if err != nil {
		return false
	}
	enabled := false
	for _, e := range entries { // lexical order: later files win, as apt does
		data, err := os.ReadFile(r.path("etc/apt/apt.conf.d", e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
				continue
			}
			rest, ok := strings.CutPrefix(line, "APT::Periodic::Unattended-Upgrade")
			if !ok {
				continue
			}
			value := strings.Trim(strings.TrimSpace(rest), `";`)
			enabled = value == "1" || value == "true"
		}
	}
	return enabled
}

// pendingSecurityUpdates counts the security upgrades `apt-get -s upgrade`
// would install. An apt that cannot answer (locked database, no lists) yields an
// error so the caller reports unknown instead of a comforting zero.
func (r *Runtime) pendingSecurityUpdates(ctx context.Context) (int, error) {
	run := r.RunApt
	switch {
	case run != nil:
	case r.Root != "/" && r.Root != "":
		// The installed packages were read from a snapshot, so simulating an
		// upgrade against this host's apt database would mix two machines.
		return 0, fmt.Errorf("the package database was read from a snapshot root; pending updates cannot be simulated")
	default:
		run = aptSimulateUpgrade
	}
	out, err := run(ctx, r.AptTimeout)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Inst ") && strings.Contains(strings.ToLower(line), "security") {
			count++
		}
	}
	return count, nil
}

// aptSimulateUpgrade runs a read-only `apt-get -s upgrade`.
func aptSimulateUpgrade(ctx context.Context, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", "-s", "upgrade")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("apt-get -s upgrade: %w", err)
	}
	return out, nil
}

// daysSinceLastUpgrade reports how many days ago the most recent upgrade was
// recorded in /var/log/dpkg.log*.
func (r *Runtime) daysSinceLastUpgrade() (int, bool) {
	newest, ok := r.lastUpgradeTime()
	if !ok {
		return 0, false
	}
	days := int(r.Now.Sub(newest).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return days, true
}

// lastUpgradeTime returns the newest "upgrade" timestamp across the dpkg logs,
// including rotated files.
func (r *Runtime) lastUpgradeTime() (time.Time, bool) {
	matches, err := filepath.Glob(r.path("var/log/dpkg.log*"))
	if err != nil || len(matches) == 0 {
		return time.Time{}, false
	}
	var newest time.Time
	found := false
	for _, file := range matches {
		data, err := os.ReadFile(file)
		if err != nil { // rotated .gz logs are skipped rather than decompressed
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, " upgrade ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ts, err := time.ParseInLocation("2006-01-02 15:04:05", fields[0]+" "+fields[1], time.Local)
			if err == nil && (!found || ts.After(newest)) {
				newest, found = ts, true
			}
		}
	}
	return newest, found
}

// ---------------------------------------------------------------------------
// Pending reboot
// ---------------------------------------------------------------------------

// PendingReboot reports whether the host is running an older kernel than the
// newest installed one, or has a package asking for a restart.
func (r *Runtime) PendingReboot() []Result {
	const check = "pending reboot"
	installedKernel, running, haveKernel := r.kernels()

	var out []Result
	for _, flag := range []string{"var/run/reboot-required", "run/reboot-required"} {
		if _, err := os.Stat(r.path(flag)); err == nil {
			target := running
			if haveKernel {
				target = fmt.Sprintf("%s, newest installed %s", running, installedKernel)
			}
			out = append(out, Result{
				Service: ServiceName, Check: check, Severity: "medium",
				Detail: fmt.Sprintf("a package asked for a restart (/%s is present); running kernel %s", flag, target),
				Fix:    "Reboot at the next maintenance window so the pending kernel and library updates take effect.",
			})
			break
		}
	}

	if haveKernel && compareVersions(installedKernel, running) > 0 {
		out = append(out, Result{
			Service: ServiceName, Check: check, Severity: "medium",
			Detail: fmt.Sprintf("running kernel %s, newest installed %s", running, installedKernel),
			Fix:    "Reboot so the host runs the installed kernel; security fixes in it are not active until then.",
		})
	}

	if len(out) == 0 {
		return []Result{pass(check, fmt.Sprintf("running kernel %s and no reboot requested", running))}
	}
	return out
}

// kernels returns the newest installed linux-image version and the running
// kernel release. haveKernel is false when either is unknown.
func (r *Runtime) kernels() (installed, running string, haveKernel bool) {
	raw, err := os.ReadFile(r.path("proc/sys/kernel/osrelease"))
	if err != nil {
		return "", "", false
	}
	running = strings.TrimSpace(string(raw))

	status, err := os.ReadFile(r.path("var/lib/dpkg/status"))
	if err != nil {
		return "", running, false
	}
	for _, stanza := range strings.Split(string(status), "\n\n") {
		if !strings.Contains(stanza, "Status: install ok installed") {
			continue
		}
		for _, line := range strings.Split(stanza, "\n") {
			name, ok := strings.CutPrefix(line, "Package: linux-image-")
			if !ok || strings.Contains(name, "-dbg") {
				continue
			}
			version := strings.TrimPrefix(name, "unsigned-")
			// Meta packages (linux-image-generic) carry no version of their own.
			if version == "" || version[0] < '0' || version[0] > '9' {
				continue
			}
			if installed == "" || compareVersions(version, installed) > 0 {
				installed = version
			}
		}
	}
	if installed == "" || running == "" {
		return "", running, false
	}
	return installed, running, true
}

// compareVersions compares two dot- or dash-separated version strings segment
// by segment, numerically where both segments are numbers. It is lenient about
// suffixes (6.8.0-51-generic vs 6.8.0-45-generic) rather than a full dpkg
// version comparison.
func compareVersions(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if c := compareSegment(as[i], bs[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

func splitVersion(v string) []string {
	return strings.FieldsFunc(v, func(c rune) bool {
		return c == '.' || c == '-' || c == '~' || c == '+'
	})
}

func compareSegment(a, b string) int {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
		return 0
	}
	return strings.Compare(a, b)
}
