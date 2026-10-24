package inventory

import "testing"

func TestOSVEcosystem(t *testing.T) {
	cases := map[string]string{
		"ubuntu":  "Ubuntu",
		"Ubuntu":  "Ubuntu",
		"debian":  "Debian",
		"Debian":  "Debian",
		"alpine":  "Alpine",
		"unknown": "Debian", // conservative default
		"":        "Debian",
	}
	for id, want := range cases {
		if got := OSVEcosystem(id); got != want {
			t.Errorf("OSVEcosystem(%q) = %q, want %q", id, got, want)
		}
	}
}
