package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/benchmark"
	"github.com/crypt0rr/dns-speedtest/internal/catalog"
)

func TestJSONAndCSVExposeTargetMetadata(t *testing.T) {
	result := benchmark.TargetResult{
		Target: catalog.Target{
			Resolver: catalog.ResolverProfile{ID: "example", Name: "Example", Owner: "Owner", Policy: "unfiltered"},
			Protocol: catalog.DoH,
			Address:  "192.0.2.53",
		},
		Stats: benchmark.Statistics{Total: 2, Successes: 2, Scored: 2, SuccessRate: 1, MedianMS: 4, P95MS: 5, ScoreMS: 4.4},
	}
	run := benchmark.Report{StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0), Seed: 3, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{result}}
	run.Rankings = []benchmark.Ranking{{Protocol: catalog.DoH, TargetID: result.Target.ID(), Rank: 1}}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, run, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\"schema_version\": 1", "\"owner\": \"Owner\"", "\"protocol\": \"doh\""} {
		if !strings.Contains(jsonOutput.String(), expected) {
			t.Fatalf("JSON output missing %q: %s", expected, jsonOutput.String())
		}
	}

	var csvOutput bytes.Buffer
	if err := WriteCSV(&csvOutput, run); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csvOutput.String(), "owner") || !strings.Contains(csvOutput.String(), "Owner") {
		t.Fatalf("CSV output missing owner metadata: %s", csvOutput.String())
	}
}
