package benchmark

import (
	"testing"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/catalog"
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
