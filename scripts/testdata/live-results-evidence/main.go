// Command live-results-evidence writes one live smoke evidence file per
// transport using the real SpeeDNS report encoder.
//
// scripts/publish-live-results-fixture.sh used to hand-write this evidence as a
// Python literal, so it asserted that scripts/publish-live-results.py works on
// JSON the encoder cannot produce. Building a benchmark.Report here and writing
// it with report.WriteJSON keeps the fixture hermetic - no resolver is ever
// dialled and no network call is made - while still feeding the publisher the
// exact bytes a real run emits.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/report"
)

const (
	fixtureCommit     = "0123456789abcdef0123456789abcdef01234567"
	fixtureCorpusHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixtureOwner      = "Fixture <script>"
	fixturePolicy     = "unfiltered & <test>"
)

// fixtureEndpoints mirror the official smoke endpoints that
// scripts/publish-live-results.py accepts. Only their identity reaches the
// report; nothing here opens a connection.
var fixtureEndpoints = []struct {
	Protocol   catalog.Protocol
	ResolverID string
	Address    string
	Spec       catalog.TransportSpec
}{
	{catalog.UDP, "google", "8.8.8.8", catalog.TransportSpec{Port: 53}},
	{catalog.TCP, "google", "8.8.8.8", catalog.TransportSpec{Port: 53}},
	{catalog.DoH, "google", "dns.google", catalog.TransportSpec{URL: "https://dns.google/dns-query", ServerName: "dns.google"}},
	{catalog.DoT, "google", "dns.google", catalog.TransportSpec{Port: 853, ServerName: "dns.google"}},
	{catalog.DoQ, "quad9", "dns.quad9.net", catalog.TransportSpec{Port: 853, ServerName: "dns.quad9.net"}},
}

func main() {
	outputDir := flag.String("output-dir", "", "directory that receives one evidence file per transport")
	failed := flag.String("failed", "", "comma-separated transports that produced no successful query")
	flag.Parse()
	if err := generate(*outputDir, *failed); err != nil {
		fmt.Fprintf(os.Stderr, "live-results-evidence: %v\n", err)
		os.Exit(1)
	}
}

func generate(outputDir, failed string) error {
	if strings.TrimSpace(outputDir) == "" {
		return fmt.Errorf("--output-dir is required")
	}
	down, err := parseProtocols(failed)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	started := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.UTC)
	for index, endpoint := range fixtureEndpoints {
		target := catalog.Target{
			Resolver: catalog.ResolverProfile{
				ID:         endpoint.ResolverID,
				Name:       "Fixture resolver",
				Owner:      fixtureOwner,
				Policy:     fixturePolicy,
				Addresses:  []string{endpoint.Address},
				Transports: map[catalog.Protocol]catalog.TransportSpec{endpoint.Protocol: endpoint.Spec},
			},
			Protocol: endpoint.Protocol,
			Address:  endpoint.Address,
			Spec:     endpoint.Spec,
		}
		stats := scoredStatistics(index)
		rankings := []benchmark.Ranking{{Protocol: endpoint.Protocol, TargetID: target.ID(), Rank: 1}}
		if down[endpoint.Protocol] {
			// A transport that answered nothing leaves every latency and
			// confidence field at zero and produces no comparable ranking.
			stats = failedStatistics()
			rankings = nil
		}
		run := benchmark.Report{
			StartedAt:  started,
			FinishedAt: started.Add(time.Second),
			Seed:       42,
			Provenance: &benchmark.RunProvenance{
				Version:       "fixture",
				Commit:        fixtureCommit,
				BuildDate:     "fixture",
				OS:            "linux",
				Architecture:  "amd64",
				Protocols:     []catalog.Protocol{endpoint.Protocol},
				CorpusEntries: 1000,
				CorpusSHA256:  fixtureCorpusHash,
				Timeout:       5 * time.Second,
				Concurrency:   1,
			},
			CorpusMode: benchmark.CorpusWarmCache,
			SampleSize: 1,
			Queries:    1,
			QueryTypes: []uint16{1},
			Targets:    []benchmark.TargetResult{{Target: target, Stats: stats}},
			Rankings:   rankings,
		}
		var encoded bytes.Buffer
		if err := report.WriteJSON(&encoded, run, false); err != nil {
			return fmt.Errorf("encode %s evidence: %w", endpoint.Protocol, err)
		}
		path := filepath.Join(outputDir, fmt.Sprintf("%s.json", endpoint.Protocol))
		if err := os.WriteFile(path, encoded.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func parseProtocols(value string) (map[catalog.Protocol]bool, error) {
	selected := make(map[catalog.Protocol]bool)
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		protocol, err := catalog.ParseProtocol(field)
		if err != nil {
			return nil, err
		}
		selected[protocol] = true
	}
	return selected, nil
}

// scoredStatistics describes a transport whose single query succeeded. The
// values vary per transport so the published table is not uniform.
func scoredStatistics(index int) benchmark.Statistics {
	base := 12.0 + float64(index)
	return benchmark.Statistics{
		Total:           1,
		Successes:       1,
		UsableResponses: 1,
		Scored:          1,
		SuccessRate:     1,
		UsableRate:      1,
		MedianMS:        base,
		P95MS:           base + 3,
		MinMS:           base - 2,
		MaxMS:           base + 5,
		MADMS:           1,
		ColdMedianMS:    base * 1.5,
		ScoreMS:         base + 1.3,
		CILowMS:         base - 1,
		CIHighMS:        base + 4,
		Recommended:     true,
	}
}

// failedStatistics describes a transport that opened but never produced a
// usable response, which is the shape that leaves cold_median_ms, ci_low_ms,
// ci_high_ms, and tie at their zero values.
func failedStatistics() benchmark.Statistics {
	return benchmark.Statistics{
		Total:              1,
		Failures:           1,
		FailureRate:        1,
		ScoringFailureRate: 1,
	}
}
