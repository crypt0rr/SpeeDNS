package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
)

// updateGolden rewrites internal/report/testdata/golden from the current
// renderers. Regenerating is deliberate: run the suite once without the flag,
// inspect the reported diff, and only then rerun with -update.
var updateGolden = flag.Bool("update", false, "rewrite testdata/golden fixtures")

func goldenReport() benchmark.Report {
	winner := reportTarget("10", "udp", 2, true)
	winner.Observations = []benchmark.Observation{{Name: "example.com", QType: 1, Success: true, Usable: true, LatencyMS: 2}}
	failed := reportTarget("11", "tcp", 0, false)
	failed.Stats = benchmark.Statistics{Total: 2, Failures: 2}
	failed.OpenError = "fixture connection failed"
	run := benchmark.Report{
		Seed: 42, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{failed, winner},
		Rankings: []benchmark.Ranking{{Protocol: "udp", TargetID: winner.Target.ID(), Rank: 1}},
		Warnings: []string{"fixture warning"},
	}
	run.Divergence = []benchmark.DivergenceDetail{
		{
			Name: "example.com", QType: 1, Policy: "unfiltered", Compared: 2,
			Baseline: "answer", Classes: map[string]int{"answer": 1, "nxdomain": 1},
			Excluded: []benchmark.DivergenceExclusion{{
				TargetID: winner.Target.ID(), ResponseClass: "nxdomain", Treatment: "latency-excluded",
			}},
		},
	}
	return run
}

func TestGoldenReports(t *testing.T) {
	run := goldenReport()
	cases := []struct {
		name   string
		render func(*bytes.Buffer) error
	}{
		{name: "table.txt", render: func(output *bytes.Buffer) error {
			return WriteTableWithOptions(output, run, TableOptions{})
		}},
		{name: "details.txt", render: func(output *bytes.Buffer) error {
			return WriteTableWithOptions(output, run, TableOptions{Details: true})
		}},
		{name: "report.json", render: func(output *bytes.Buffer) error {
			return WriteJSON(output, run, false)
		}},
		{name: "report.csv", render: func(output *bytes.Buffer) error {
			return WriteCSV(output, run)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := tc.render(&output); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "golden", tc.name)
			if *updateGolden {
				if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Logf("generated %s:\n%s", path, output.String())
				t.Fatal(err)
			}
			if output.String() != string(want) {
				t.Fatalf("%s changed; review the diff and regenerate deliberately with\n"+
					"\tgo test ./internal/report -run TestGoldenReports -update\nwant:\n%s\ngot:\n%s",
					path, want, output.String())
			}
		})
	}
}
