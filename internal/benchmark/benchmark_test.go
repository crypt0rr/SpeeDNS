package benchmark

import (
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
)

func TestBuildQueriesIsDeterministic(t *testing.T) {
	opts := Options{Domains: []string{"a.example", "b.example", "c.example"}, QueryTypes: []uint16{1, 28}, Sample: 2, Seed: 42}
	first, err := buildQueries(opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildQueries(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 4 {
		t.Fatalf("query count = %d, want 4", len(first))
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("query order changed at %d: %#v != %#v", index, first[index], second[index])
		}
	}
}

func TestStatisticsAndRanking(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "test", Name: "Test", Owner: "Test", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "127.0.0.1",
	}
	observations := make([]Observation, 0, 20)
	for index := 0; index < 20; index++ {
		observations = append(observations, Observation{Success: true, Latency: time.Duration(index+1) * time.Millisecond, LatencyMS: float64(index + 1), ResponseClass: "answer"})
	}
	result := TargetResult{Target: target, Observations: observations}
	stats := calculateStatistics(result, 2*time.Second, 1)
	if stats.Scored != 20 || !stats.Recommended {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if stats.MedianMS <= 0 || stats.P95MS < stats.MedianMS || stats.ScoreMS <= 0 {
		t.Fatalf("invalid latency stats: %#v", stats)
	}
}

func TestDivergentResponsesAreExcluded(t *testing.T) {
	results := []TargetResult{
		{Observations: []Observation{{Name: "example.com", QType: 1, Success: true, LatencyMS: 5, ResponseClass: "answer"}}},
		{Observations: []Observation{{Name: "example.com", QType: 1, Success: true, LatencyMS: 2, ResponseClass: "nxdomain"}}},
	}
	markDivergence(results)
	for _, result := range results {
		if !result.Observations[0].Divergent {
			t.Fatal("expected response-class divergence to be marked")
		}
	}
}

func TestPercentileAndMAD(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}
	if got := percentile(values, .5); got != 3 {
		t.Fatalf("median = %v, want 3", got)
	}
	if got := mad(values, 3); got != 1 {
		t.Fatalf("MAD = %v, want 1", got)
	}
}

func TestResolverErrorsAreNotScored(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "test", Name: "Test", Owner: "Test", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "127.0.0.1",
	}
	result := TargetResult{Target: target, Observations: []Observation{
		{Name: "answer.example", Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 20},
		{Name: "servfail.example", Success: true, RCode: dns.RcodeServerFailure, ResponseClass: "rcode-2", LatencyMS: 1},
		{Name: "refused.example", Success: true, RCode: dns.RcodeRefused, ResponseClass: "rcode-5", LatencyMS: 1},
	}}
	stats := calculateStatistics(result, 2*time.Second, 1)
	if stats.Successes != 3 || stats.Failures != 0 {
		t.Fatalf("transport statistics = %#v", stats)
	}
	if stats.UsableResponses != 1 || stats.ResolverFailures != 2 || stats.Scored != 1 {
		t.Fatalf("semantic statistics = %#v", stats)
	}
	if stats.RCodeCounts["SERVFAIL"] != 1 || stats.RCodeCounts["REFUSED"] != 1 {
		t.Fatalf("rcode counts = %#v", stats.RCodeCounts)
	}
	if observationUsable(Observation{Success: true, ResponseClass: "unexpected"}) {
		t.Fatal("unknown response classes should not be usable")
	}
	if formatRCodeCounts(nil) != "" {
		t.Fatal("empty RCODE counts should format as empty")
	}
	if stats.ScoreMS <= 1000 {
		t.Fatalf("resolver-error penalty missing from score: %#v", stats)
	}

	result.Stats = stats
	rankings := makeRankings([]TargetResult{result, {Target: target, Stats: Statistics{Scored: 0, ScoreMS: 0}}})
	if len(rankings) != 1 {
		t.Fatalf("resolver-error target should not be ranked: %#v", rankings)
	}
}

func TestRecommendationRequiresUsableResponses(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "test", Name: "Test", Owner: "Test", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "127.0.0.1",
	}
	observations := make([]Observation, 0, 21)
	for index := 0; index < 20; index++ {
		observations = append(observations, Observation{
			Name: "answer.example", Success: true, Usable: true, RCode: dns.RcodeSuccess,
			ResponseClass: "answer", LatencyMS: float64(index + 1),
		})
	}
	observations = append(observations, Observation{
		Name: "servfail.example", Success: true, RCode: dns.RcodeServerFailure,
		ResponseClass: "rcode-2", LatencyMS: 1,
	})
	stats := calculateStatistics(TargetResult{Target: target, Observations: observations}, 2*time.Second, 1)
	if stats.SuccessRate != 1 || stats.UsableRate >= MinimumRecommendedSuccessRate || stats.Scored != 20 || stats.Recommended {
		t.Fatalf("recommendation ignored unusable response: %#v", stats)
	}

	warnings := collectWarnings([]TargetResult{{
		Target: target,
		Stats:  Statistics{Total: 2, Scored: 1, ResolverFailures: 1, RCodeCounts: map[string]int{"SERVFAIL": 1}},
	}})
	if len(warnings) != 2 || !strings.Contains(strings.Join(warnings, "\n"), "SERVFAIL:1") {
		t.Fatalf("resolver-error warnings = %#v", warnings)
	}
}
