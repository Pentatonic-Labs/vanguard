package main

import (
	"reflect"
	"testing"
)

func TestDiffFixed(t *testing.T) {
	prev := map[string]string{
		"A": "",    // was unfixed
		"B": "1.0", // was fixed
		"C": "2.0", // was fixed
	}
	current := map[string]string{
		"A": "1.2", // -> patch became available
		"B": "1.0", // -> unchanged
		"C": "",    // -> fix withdrawn
		"D": "",    // -> brand new
	}

	newKeys, nowFixed, withdrawn := diffFixed(prev, current)

	if !reflect.DeepEqual(newKeys, []string{"D"}) {
		t.Fatalf("newKeys = %v, want [D]", newKeys)
	}
	if !reflect.DeepEqual(nowFixed, []string{"A"}) {
		t.Fatalf("nowFixed = %v, want [A]", nowFixed)
	}
	if !reflect.DeepEqual(withdrawn, []string{"C"}) {
		t.Fatalf("withdrawn = %v, want [C]", withdrawn)
	}
}

// A feed failure is not "no vulnerabilities". On a host whose DNS died, both
// feeds fail, the scan finds nothing, and recording that as a baseline reports a
// permanently clean box — the exact class of silent-stale-state this tool exists
// to prevent. The guard is that a run which lost a feed never baselines.
func TestFeedFailureIsNotACleanBaseline(t *testing.T) {
	if shouldRecordBaseline(0) != true {
		t.Error("a scan with no feed failures must baseline")
	}
	if shouldRecordBaseline(1) != false {
		t.Error("a scan that lost a feed must NOT baseline — that records an empty result as clean")
	}
}
