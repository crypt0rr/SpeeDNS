package data

import "testing"

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
}
