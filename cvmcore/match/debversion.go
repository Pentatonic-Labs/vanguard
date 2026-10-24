package match

import "strings"

// compareDebianVersion compares two Debian versions using the dpkg version
// ordering rules, mirroring dpkg's verrevcmp:
//
//   - epoch first (numeric, default 0)
//   - then the upstream version
//   - then the Debian revision (the part after the last hyphen)
//
// Within a component, '~' sorts before everything (including the empty string),
// the empty string sorts before letters, letters sort before other characters,
// and digit runs compare numerically with leading zeros ignored.
//
// It returns -1, 0, or 1.
func compareDebianVersion(a, b string) int {
	aE, aU, aR := splitDebianVersion(a)
	bE, bU, bR := splitDebianVersion(b)
	if c := cmpInt(aE, bE); c != 0 {
		return c
	}
	if c := verrevcmp(aU, bU); c != 0 {
		return c
	}
	return verrevcmp(aR, bR)
}

// splitDebianVersion splits a Debian version into epoch, upstream, and
// revision. The epoch is before the first colon (default 0); the revision is
// everything after the last hyphen.
func splitDebianVersion(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		for _, r := range v[:i] {
			if r >= '0' && r <= '9' {
				epoch = epoch*10 + int(r-'0')
			}
		}
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// verrevcmp compares two Debian version components (upstream or revision)
// using dpkg's algorithm.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Compare non-digit characters, one at a time. A string that has
		// ended compares as the "empty" character (order 0).
		for (i < len(a) && !isDebDigit(a[i])) || (j < len(b) && !isDebDigit(b[j])) {
			if c := debOrder(debByteAt(a, i)) - debOrder(debByteAt(b, j)); c != 0 {
				return cmpInt(c, 0)
			}
			if i < len(a) {
				i++
			}
			if j < len(b) {
				j++
			}
		}

		// Skip leading zeros in each digit run.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}

		// Compare digit runs numerically: a longer run is larger; otherwise
		// the first differing digit decides.
		firstDiff := 0
		for i < len(a) && j < len(b) && isDebDigit(a[i]) && isDebDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDebDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDebDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return cmpInt(firstDiff, 0)
		}
	}
	return 0
}

func debByteAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

func isDebDigit(c byte) bool { return c >= '0' && c <= '9' }

// debOrder returns the dpkg sort weight of a single character: '~' sorts
// before everything, the empty (end) character sorts next, letters next, and
// other characters last.
func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0:
		return 0
	case (c >= '0' && c <= '9'):
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	default:
		return int(c) + 256
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
