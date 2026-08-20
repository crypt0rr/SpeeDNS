// Package data contains the versioned assets shipped with SpeeDNS.
package data

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed domains.txt
var domainsFile string

//go:embed domains.meta.json
var domainsMetadataFile string

//go:embed resolvers.yaml
var resolverCatalogFile string

// CorpusMetadata describes the source and integrity of the embedded domain
// corpus. It is returned by VerifyCorpus and exposed by the corpus command.
type CorpusMetadata struct {
	Source      string `json:"source"`
	ListID      string `json:"list_id"`
	RetrievedAt string `json:"retrieved_at"`
	DownloadURL string `json:"download_url"`
	Entries     int    `json:"entries"`
	SHA256      string `json:"sha256"`
	LicenseNote string `json:"license_note"`
}

// Domains returns the bundled domain corpus as normalized newline-separated
// names. The canonical corpus bytes used for the metadata checksum are these
// names joined by LF and terminated by LF. The caller receives a new slice and
// may safely modify it.
func Domains() []string {
	lines := strings.Split(domainsFile, "\n")
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "" {
			domains = append(domains, strings.TrimSuffix(line, "."))
		}
	}
	return domains
}

// ResolverCatalog returns the embedded, versioned default resolver catalog in
// the same strict YAML format accepted by custom resolver files.
func ResolverCatalog() string {
	return resolverCatalogFile
}

// VerifyCorpus validates the embedded corpus and its pinned provenance
// metadata without accessing the network or filesystem.
func VerifyCorpus() (CorpusMetadata, error) {
	var metadata CorpusMetadata
	if err := json.Unmarshal([]byte(domainsMetadataFile), &metadata); err != nil {
		return CorpusMetadata{}, fmt.Errorf("parse embedded corpus metadata: %w", err)
	}
	if err := verifyCorpus(Domains(), metadata); err != nil {
		return CorpusMetadata{}, err
	}
	return metadata, nil
}

func verifyCorpus(domains []string, metadata CorpusMetadata) error {
	if strings.TrimSpace(metadata.Source) == "" || strings.TrimSpace(metadata.ListID) == "" || strings.TrimSpace(metadata.RetrievedAt) == "" {
		return fmt.Errorf("embedded corpus metadata is missing source, list ID, or retrieval date")
	}
	if metadata.Entries != len(domains) {
		return fmt.Errorf("embedded corpus metadata entry count %d does not match %d domains", metadata.Entries, len(domains))
	}
	if len(domains) == 0 {
		return fmt.Errorf("embedded corpus is empty")
	}
	seen := make(map[string]struct{}, len(domains))
	for index, domain := range domains {
		if !validCorpusDomain(domain) {
			return fmt.Errorf("embedded corpus domain %d %q has invalid syntax", index+1, domain)
		}
		if _, exists := seen[domain]; exists {
			return fmt.Errorf("embedded corpus contains duplicate domain %q", domain)
		}
		seen[domain] = struct{}{}
	}
	if _, err := hex.DecodeString(metadata.SHA256); err != nil || len(metadata.SHA256) != sha256.Size*2 {
		return fmt.Errorf("embedded corpus metadata SHA-256 %q is invalid", metadata.SHA256)
	}
	canonical := strings.Join(domains, "\n") + "\n"
	digest := sha256.Sum256([]byte(canonical))
	calculated := hex.EncodeToString(digest[:])
	if !strings.EqualFold(metadata.SHA256, calculated) {
		return fmt.Errorf("embedded corpus checksum mismatch: metadata %q, calculated %q", metadata.SHA256, calculated)
	}
	return nil
}

func validCorpusDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
