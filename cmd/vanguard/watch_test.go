package main

import (
	"reflect"
	"testing"
)

func TestDiffFixed(t *testing.T) {
	prev := map[string]string{
		"A": "",   // was unfixed
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
