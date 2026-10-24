package ingest

import (
	"archive/zip"
	"bytes"
	"testing"
)

// The parsers below consume untrusted feed data, so each must never panic on
// arbitrary input. These fuzz functions exercise exactly that.

func FuzzParseKEV(f *testing.F) {
	f.Add([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-0001"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseKEV(data)
	})
}

func FuzzParseOSV(f *testing.F) {
	f.Add([]byte(`{"id":"GHSA-xxxx-xxxx-xxxx","summary":"x","affected":[{"package":{"ecosystem":"Debian","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.16"}]}]}]}`))
	f.Add([]byte(`{"vulns":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseOSV(data)
	})
}

func FuzzOSVQueryBatch(f *testing.F) {
	f.Add([]byte(`{"results":[{"vulns":[{"id":"X"}]}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseOSVQueryBatch(data)
	})
}

func FuzzOSVExport(f *testing.F) {
	f.Add(mustZip(f, map[string]string{"a.json": `{"id":"X","summary":"test"}`}))
	f.Add([]byte("not a zip"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseOSVExport(data)
	})
}

func FuzzParseNVD(f *testing.F) {
	f.Add([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","descriptions":[{"lang":"en","value":"x"}]}}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseNVD(data)
	})
}

// mustZip builds a minimal in-memory ZIP for seeding FuzzOSVExport.
func mustZip(f *testing.F, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			f.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			f.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		f.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}
