package pipeline

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/Pentatonic-Labs/vanguard/cvmcore"
)

// parsedCache caches parsed OSV vulnerabilities keyed by the export's content
// hash, so an unchanged export is not re-parsed on every poll.
type parsedCache struct {
	dir string
}

func (c parsedCache) path(key string) string {
	return filepath.Join(c.dir, key+".gob")
}

func (c parsedCache) load(key string) ([]cvmcore.Vuln, bool) {
	f, err := os.Open(c.path(key))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var vulns []cvmcore.Vuln
	if err := gob.NewDecoder(f).Decode(&vulns); err != nil {
		return nil, false
	}
	return vulns, true
}

func (c parsedCache) save(key string, vulns []cvmcore.Vuln) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	f, err := os.Create(c.path(key))
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(vulns)
}

// contentHash returns a short content hash of data for use as a cache key.
func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
