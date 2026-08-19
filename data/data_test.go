package data

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type corpusMetadata struct {
	Entries int    `json:"entries"`
	SHA256  string `json:"sha256"`
}

func readCorpusMetadata(t *testing.T) corpusMetadata {
	t.Helper()
	contents, err := os.ReadFile("domains.meta.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata corpusMetadata
	if err := json.Unmarshal(contents, &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestBundledDomainCorpus(t *testing.T) {
	domains := Domains()
	if len(domains) != 1000 {
		t.Fatalf("bundled domain count = %d, want 1000", len(domains))
	}
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain == "" {
			t.Fatal("bundled corpus contains an empty domain")
		}
		if _, ok := seen[domain]; ok {
			t.Fatalf("bundled corpus contains duplicate %q", domain)
		}
		seen[domain] = struct{}{}
	}
	metadata := readCorpusMetadata(t)
	if metadata.Entries != len(domains) {
		t.Fatalf("metadata entry count = %d, want %d", metadata.Entries, len(domains))
	}
}

func TestBundledDomainCorpusChecksum(t *testing.T) {
	domains := Domains()
	canonical := strings.Join(domains, "\n") + "\n"
	digest := sha256.Sum256([]byte(canonical))
	want := hex.EncodeToString(digest[:])
	metadata := readCorpusMetadata(t)
	if metadata.SHA256 != want {
		t.Fatalf("metadata SHA-256 = %q, want %q", metadata.SHA256, want)
	}
}
