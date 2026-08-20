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

func TestBundledResolverCatalogAsset(t *testing.T) {
	contents := ResolverCatalog()
	if strings.TrimSpace(contents) == "" {
		t.Fatal("bundled resolver catalog is empty")
	}
	if !strings.Contains(contents, "version: 1") || !strings.Contains(contents, "resolvers:") {
		t.Fatalf("bundled resolver catalog is missing its versioned root: %q", contents[:min(len(contents), 80)])
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

func TestVerifyCorpus(t *testing.T) {
	metadata, err := VerifyCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Entries != 1000 || metadata.ListID == "" || metadata.Source == "" {
		t.Fatalf("corpus metadata = %#v", metadata)
	}
}

func TestVerifyCorpusReportsEmbeddedMetadataErrors(t *testing.T) {
	oldMetadata := domainsMetadataFile
	t.Cleanup(func() { domainsMetadataFile = oldMetadata })
	metadata, err := VerifyCorpus()
	if err != nil {
		t.Fatal(err)
	}
	domainsMetadataFile = "not-json"
	if _, err := VerifyCorpus(); err == nil || !strings.Contains(err.Error(), "parse embedded corpus metadata") {
		t.Fatalf("malformed metadata error = %v", err)
	}
	metadata.Entries++
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	domainsMetadataFile = string(encoded)
	if _, err := VerifyCorpus(); err == nil || !strings.Contains(err.Error(), "entry count") {
		t.Fatalf("invalid metadata error = %v", err)
	}
}

func TestVerifyCorpusRejectsInvalidMetadataOrDomains(t *testing.T) {
	domains := []string{"example.com", "example.org"}
	digest := sha256.Sum256([]byte(strings.Join(domains, "\n") + "\n"))
	metadata := CorpusMetadata{
		Source:      "fixture",
		ListID:      "fixture",
		RetrievedAt: "2026-01-01",
		Entries:     len(domains),
		SHA256:      hex.EncodeToString(digest[:]),
	}
	if err := verifyCorpus(domains, metadata); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		domains []string
		change  func(*CorpusMetadata)
		want    string
	}{
		{name: "count", domains: domains, change: func(metadata *CorpusMetadata) { metadata.Entries++ }, want: "entry count"},
		{name: "duplicate", domains: []string{"example.com", "example.com"}, change: func(metadata *CorpusMetadata) {}, want: "duplicate"},
		{name: "syntax", domains: []string{"example..com", "example.org"}, change: func(metadata *CorpusMetadata) {}, want: "invalid syntax"},
		{name: "checksum", domains: domains, change: func(metadata *CorpusMetadata) { metadata.SHA256 = strings.Repeat("0", sha256.Size*2) }, want: "checksum mismatch"},
		{name: "invalid checksum", domains: domains, change: func(metadata *CorpusMetadata) { metadata.SHA256 = strings.Repeat("z", sha256.Size*2) }, want: "SHA-256"},
		{name: "metadata", domains: domains, change: func(metadata *CorpusMetadata) { metadata.Source = "" }, want: "missing source"},
		{name: "empty", domains: nil, change: func(metadata *CorpusMetadata) { metadata.Entries = 0 }, want: "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := metadata
			if tc.name == "duplicate" || tc.name == "syntax" {
				candidate.Entries = len(tc.domains)
				digest := sha256.Sum256([]byte(strings.Join(tc.domains, "\n") + "\n"))
				candidate.SHA256 = hex.EncodeToString(digest[:])
			}
			tc.change(&candidate)
			if err := verifyCorpus(tc.domains, candidate); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verification error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidCorpusDomainRejectsMalformedNames(t *testing.T) {
	cases := []string{
		"",
		strings.Repeat("a", 254),
		"example.com.",
		"example..com",
		"-example.com",
		"example-.com",
		strings.Repeat("a", 64) + ".example",
		"example_com",
	}
	for _, domain := range cases {
		if validCorpusDomain(domain) {
			t.Errorf("validCorpusDomain(%q) = true, want false", domain)
		}
	}
}
