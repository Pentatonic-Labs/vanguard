package match

import "testing"

// FuzzCompareDebianVersion ensures the Debian version comparator never panics on
// arbitrary input (version strings come from untrusted feeds).
func FuzzCompareDebianVersion(f *testing.F) {
	for _, c := range canonicalCases {
		f.Add(c.a, c.b)
	}
	f.Add("1:34.0.4-1build3", "0.9.6-1")
	f.Add("", "")
	f.Add("1.0~rc1", "1.0")
	f.Fuzz(func(t *testing.T, a, b string) {
		compareDebianVersion(a, b)
		compareDebianVersion(b, a)
	})
}

// FuzzParseCPE ensures the CPE 2.3 parser never panics on arbitrary input.
func FuzzParseCPE(f *testing.F) {
	for _, s := range []string{
		"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:product:1.0",
		"cpe:2.3:a:openssl:openssl:*",
		"not-a-cpe",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		parseCPE(s)
	})
}
