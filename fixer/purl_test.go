package fixer

import "testing"

func TestPurlEcosystemAndName(t *testing.T) {
	cases := []struct{ purl, eco, name string }{
		{"pkg:golang/github.com/foo/bar@1.2.3", "golang", "github.com/foo/bar"},
		{"pkg:pypi/requests@2.31.0", "pypi", "requests"},
		{"pkg:npm/lodash@4.17.21", "npm", "lodash"},
		{"pkg:deb/openssl@3.0.13", "deb", "openssl"},
		{"not-a-purl", "", ""},
		{"pkg:golang", "golang", ""},
	}
	for _, c := range cases {
		eco, name := purlEcosystemAndName(c.purl)
		if eco != c.eco || name != c.name {
			t.Errorf("purlEcosystemAndName(%q) = (%q, %q), want (%q, %q)", c.purl, eco, name, c.eco, c.name)
		}
	}
}
