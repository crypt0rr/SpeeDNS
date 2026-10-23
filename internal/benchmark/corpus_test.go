package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/domains"
	"github.com/miekg/dns"
)

func loadNormalizedCorpus(tb testing.TB, names []string) domains.LoadResult {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte(strings.Join(names, "\n")+"\n"), 0o600); err != nil {
		tb.Fatal(err)
	}
	loaded, err := domains.LoadTolerant(path, false)
	if err != nil {
		tb.Fatal(err)
	}
	return loaded
}

// TestRunSamplesAnAlreadyNormalizedCorpusAsIs pins that a corpus the domains
// package normalized is sampled without a second normalization pass, and that
// nothing else skips one. Domains is deliberately invalid while the
// normalized list is set: had the engine normalized Domains, query
// construction would fail, so success proves the loaded list was used as is.
func TestRunSamplesAnAlreadyNormalizedCorpusAsIs(t *testing.T) {
	loaded := loadNormalizedCorpus(t, []string{"Example.COM.", "example.org", "example.com"})
	opts := validBenchmarkOptions()
	opts.Full = true
	opts.Domains = []string{"bad..name"}
	opts.NormalizedDomains = loaded.Normalized()
	queries, err := buildQueries(opts)
	if err != nil {
		t.Fatalf("query construction from a normalized corpus failed: %v", err)
	}
	measured := make([]string, 0, len(queries))
	for _, query := range queries {
		measured = append(measured, query.Name)
	}
	sort.Strings(measured)
	if want := "[example.com example.com example.org example.org]"; fmt.Sprint(measured) != want {
		t.Fatalf("measured names = %v, want %s", measured, want)
	}
	if loaded.Names[0] != "example.com" || loaded.Names[1] != "example.org" {
		t.Fatalf("query construction reordered the caller's corpus: %q", loaded.Names)
	}

	// The same Domains without the normalized list is still validated, and so
	// is every Domains a caller builds by hand.
	opts.NormalizedDomains = domains.Normalized{}
	if _, err := buildQueries(opts); err == nil || !strings.Contains(err.Error(), "empty labels") {
		t.Fatalf("unnormalized Domains error = %v, want it validated", err)
	}

	// A normalized corpus is a corpus: Domains may be left empty.
	opts.Domains = nil
	opts.NormalizedDomains = loaded.Normalized()
	if err := validateOptions(opts); err != nil {
		t.Fatalf("validation rejected a normalized corpus with no Domains: %v", err)
	}
	opts.NormalizedDomains = domains.Normalized{}
	if err := validateOptions(opts); err == nil || !strings.Contains(err.Error(), "domain corpus is empty") {
		t.Fatalf("empty corpus error = %v", err)
	}
}

// BenchmarkBuildQueries shows the normalization pass a corpus loaded through
// the domains package no longer pays twice. Both cases sample the default 100
// names from a 100,000-name list; "revalidated" passes it only as Domains, as
// the CLI did. Run with: go test -run '^$' -bench BuildQueries ./internal/benchmark
func BenchmarkBuildQueries(b *testing.B) {
	names := make([]string, 100_000)
	for index := range names {
		names[index] = fmt.Sprintf("name-%d.example.com", index)
	}
	loaded := loadNormalizedCorpus(b, names)
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"normalized", Options{Domains: loaded.Names, NormalizedDomains: loaded.Normalized()}},
		{"revalidated", Options{Domains: loaded.Names}},
	} {
		tc.opts.QueryTypes, tc.opts.Sample, tc.opts.Seed = []uint16{dns.TypeA, dns.TypeAAAA}, DefaultSample, 1
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := buildQueries(tc.opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
