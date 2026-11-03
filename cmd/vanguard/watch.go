package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Pentatonic-Labs/vanguard/cvmcore/fetch"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/pipeline"
	"github.com/Pentatonic-Labs/vanguard/cvmcore/remediate"
	"github.com/Pentatonic-Labs/vanguard/inventory"
	"github.com/Pentatonic-Labs/vanguard/notify"
)

// runWatch runs the reactive loop on a cadence and reports changes: new
// findings, and findings whose fix status flipped (a patch became available,
// or a fix was withdrawn). The first run establishes a baseline.
//
// Every cycle also records a heartbeat and any events under the cache
// directory, and hands the same payload to an operator-supplied transport.
func runWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Duration("interval", time.Hour, "poll interval (e.g. 30m, 1h)")
	notifyCmd := fs.String("notify-cmd", "", "command to run after a cycle with findings; the payload arrives as JSON on stdin")
	notifyWebhook := fs.String("notify-webhook", "", "URL to POST the same JSON to after a cycle with findings")
	fs.Parse(args)

	statePath := filepath.Join(fetch.DefaultCacheDir(), "watch.json")
	hostname, _ := os.Hostname()
	w := &watcher{
		store:         notify.NewStore(fetch.DefaultCacheDir()),
		statePath:     statePath,
		interval:      *interval,
		notifyCmd:     *notifyCmd,
		notifyWebhook: *notifyWebhook,
		hostname:      hostname,
		prev:          loadFixed(statePath),
		firstRun:      !fileExists(statePath),
	}

	for {
		w.cycle(w.scan)
		time.Sleep(w.interval)
	}
}

// watcher is one watch loop's state. Keeping it out of runWatch lets a test run
// a single cycle against a stub scan instead of waiting out an interval.
type watcher struct {
	store         *notify.Store
	statePath     string
	interval      time.Duration
	notifyCmd     string
	notifyWebhook string
	hostname      string
	prev          map[string]string
	firstRun      bool
}

// scanFunc performs one poll: the proposals it found, how many feeds were lost
// while looking, and any fatal error.
type scanFunc func() ([]remediate.Proposal, int64, error)

// scan is the poll the loop performs for real.
func (w *watcher) scan() ([]remediate.Proposal, int64, error) {
	before := feedFailures.Load()
	decisions, err := pipeline.Run(context.Background(), scanConfig())
	lost := feedFailures.Load() - before
	if err != nil {
		return nil, lost, err
	}
	return remediate.Build(decisions, inventory.DetectOSVersion()), lost, nil
}

// cycle runs one poll: print what changed, then record the heartbeat, the event
// log and any transport call. It reports failures on stderr rather than
// returning them — a loop that stops looking because one cycle could not write
// its heartbeat is worse than a gap in the record.
func (w *watcher) cycle(scan scanFunc) {
	started := time.Now()
	proposals, lost, err := scan()
	stamp := time.Now().Format(time.RFC3339)

	if err != nil {
		fmt.Fprintf(os.Stderr, "vanguard: %v\n", err)
		// A cycle that could not look at all is not a quiet cycle, and a
		// transport hears about it for the same reason it hears about lost
		// feeds: otherwise a host that fails every interval is only visible as
		// a heartbeat that stops changing.
		events := []notify.Event{{
			TS:       started,
			Type:     notify.TypeScanIncomplete,
			Hostname: w.hostname,
			Explain:  truncate(err.Error(), explainLimit),
		}}
		w.finish(w.heartbeat(started, false, lost, len(proposals), events), events)
		return
	}

	if !shouldRecordBaseline(lost) {
		// Never baseline a partial scan. A host that cannot resolve
		// osv-vulnerabilities (seen in the field: no DNS) finds nothing, and
		// recording "0 findings" makes every later cycle agree with it.
		fmt.Printf("[%s] SCAN INCOMPLETE: %d feed(s) unavailable — baseline NOT updated, findings unknown\n", stamp, lost)
		fmt.Printf("[%s] next attempt in %s\n", stamp, w.interval.String())
		events := []notify.Event{{
			TS:       started,
			Type:     notify.TypeScanIncomplete,
			Hostname: w.hostname,
			Explain:  fmt.Sprintf("%d feed(s) unavailable — findings unknown, baseline not updated", lost),
		}}
		w.finish(w.heartbeat(started, false, lost, len(proposals), events), events)
		return
	}

	current := map[string]string{}
	byKey := map[string]remediate.Proposal{}
	for _, p := range proposals {
		key := p.VulnID + "|" + p.Purl
		current[key] = p.Fixed
		byKey[key] = p
	}

	newKeys, nowFixed, withdrawn := diffFixed(w.prev, current)

	var events []notify.Event
	switch {
	case w.firstRun:
		fmt.Printf("[%s] baseline: %d proposal(s) recorded; watching for new issues and new patches\n", stamp, len(proposals))
		w.firstRun = false
	default:
		for _, k := range newKeys {
			p := byKey[k]
			fmt.Printf("[%s] NEW %s in %s\n%s\n\n", stamp, p.VulnID, p.Package, p.Explain())
			events = append(events, newEvent(started, notify.TypeNew, w.hostname, p))
		}
		for _, k := range nowFixed {
			p := byKey[k]
			fmt.Printf("[%s] PATCH AVAILABLE %s in %s → upgrade to %s\n    apt-get install --only-upgrade %s=%s\n\n",
				stamp, p.VulnID, p.Package, p.Fixed, p.Package, p.Fixed)
			events = append(events, newEvent(started, notify.TypePatchAvailable, w.hostname, p))
		}
		for _, k := range withdrawn {
			p := byKey[k]
			fmt.Printf("[%s] FIX WITHDRAWN %s in %s (no longer patched)\n\n", stamp, p.VulnID, p.Package)
			events = append(events, newEvent(started, notify.TypeFixWithdrawn, w.hostname, p))
		}
		if len(newKeys)+len(nowFixed)+len(withdrawn) == 0 {
			fmt.Printf("[%s] no changes\n", stamp)
		}
	}
	_ = saveFixed(w.statePath, current)
	// Carry the baseline forward. Diffing against the map loaded before the
	// first cycle would report every finding as new, for ever.
	w.prev = current

	// A complete scan — baseline or not — is the only thing that can say what is
	// still outstanding. An incomplete one never can.
	if err := w.store.WriteFindings(notify.Findings{
		Generated: time.Now(),
		Hostname:  w.hostname,
		Version:   version,
		Proposals: proposals,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "vanguard: findings: %v\n", err)
	}

	w.finish(w.heartbeat(started, true, lost, len(proposals), events), events)

	elapsed := time.Since(started).Round(time.Millisecond)
	fmt.Printf("[%s] next check in %s (last run %s)\n\n", time.Now().Format(time.RFC3339), w.interval.String(), elapsed)
}

// heartbeat summarises one finished cycle.
func (w *watcher) heartbeat(started time.Time, complete bool, lost int64, proposals int, events []notify.Event) notify.Heartbeat {
	hb := notify.Heartbeat{
		Version:        version,
		Hostname:       w.hostname,
		Started:        started,
		Finished:       time.Now(),
		DurationS:      time.Since(started).Seconds(),
		ScanComplete:   complete,
		FeedFailures:   lost,
		ProposalsTotal: proposals,
		IntervalS:      w.interval.Seconds(),
	}
	for _, e := range events {
		hb.Events.Add(e.Type)
	}
	return hb
}

// newEvent wraps a proposal as an event log line.
func newEvent(ts time.Time, typ, hostname string, p remediate.Proposal) notify.Event {
	return notify.Event{TS: ts, Type: typ, Hostname: hostname, Proposal: &p, Explain: p.Explain()}
}

// finish records the cycle: heartbeat first, so liveness never depends on the
// event log, then the events, then the transports. A cycle with no events wakes
// no transport.
func (w *watcher) finish(hb notify.Heartbeat, events []notify.Event) {
	if err := w.store.WriteHeartbeat(hb); err != nil {
		fmt.Fprintf(os.Stderr, "vanguard: heartbeat: %v\n", err)
	}
	if err := w.store.AppendEvents(events); err != nil {
		fmt.Fprintf(os.Stderr, "vanguard: events: %v\n", err)
	}
	if len(events) == 0 {
		return
	}
	payload := notify.Payload{Heartbeat: hb, Events: events}
	if w.notifyCmd != "" {
		if err := notify.RunCommand(w.notifyCmd, payload); err != nil {
			fmt.Fprintf(os.Stderr, "vanguard: notify command failed: %v\n", err)
		}
	}
	if w.notifyWebhook != "" {
		if err := notify.PostWebhook(w.notifyWebhook, payload); err != nil {
			fmt.Fprintf(os.Stderr, "vanguard: notify webhook failed: %v\n", err)
		}
	}
}

// explainLimit caps the free-form text carried by an event: a feed error can
// embed a whole response body, and the event log is one line per event.
const explainLimit = 300

// truncate shortens s to at most n runes, collapsing whitespace so an error
// carrying newlines stays one line, and marking that it was cut.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// shouldRecordBaseline reports whether a scan result may be written as the new
// baseline. A run that lost a feed must not: it did not look, and "did not look"
// recorded as "nothing found" is indistinguishable from a clean box.
func shouldRecordBaseline(feedFailuresLost int64) bool { return feedFailuresLost == 0 }

// diffFixed classifies the transition from a previous scan's fix status (key →
// fixed version) to the current one. An empty fixed version means "no fix known
// yet".
func diffFixed(prev, current map[string]string) (newKeys, nowFixed, withdrawn []string) {
	for k, v := range current {
		old, ok := prev[k]
		if !ok {
			newKeys = append(newKeys, k)
			continue
		}
		if old == "" && v != "" {
			nowFixed = append(nowFixed, k)
		}
		if old != "" && v == "" {
			withdrawn = append(withdrawn, k)
		}
	}
	sort.Strings(newKeys)
	sort.Strings(nowFixed)
	sort.Strings(withdrawn)
	return newKeys, nowFixed, withdrawn
}

type watchState struct {
	Fixed map[string]string `json:"fixed"`
}

func loadFixed(path string) map[string]string {
	fixed := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return fixed
	}
	var st watchState
	if json.Unmarshal(data, &st) == nil {
		for k, v := range st.Fixed {
			fixed[k] = v
		}
	}
	return fixed
}

func saveFixed(path string, fixed map[string]string) error {
	data, err := json.Marshal(watchState{Fixed: fixed})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
