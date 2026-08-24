package report

import (
	"bytes"
	"strings"
	"time"

	"encoding/csv"
	"encoding/json"
	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"strconv"
	"testing"
)

// TestCSVAgreesWithJSONFieldByField pins the two machine-readable surfaces to
// each other.
//
// Both are produced by separate code paths from the same report, and nothing
// compared them. Swapping two adjacent CSV columns -- success_rate and
// usable_rate, say -- ships a CSV that disagrees with the JSON about the same
// target and metric, and passes every gate: the schema constrains only the
// JSON, the golden fixtures pin each format against itself, and column order
// is asserted nowhere.
//
// The fixture below deliberately gives every numeric field a DISTINCT value.
// Adjacent fields sharing a value is what let a swap hide: a golden file
// records the rendered text, so swapping two equal numbers changes nothing.
func TestCSVAgreesWithJSONFieldByField(t *testing.T) {
	report := contractFixture()

	var jsonBuffer bytes.Buffer
	if err := WriteJSON(&jsonBuffer, report, false); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Results []struct {
			Target struct {
				ID string `json:"id"`
			} `json:"target"`
			Stats map[string]any `json:"stats"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonBuffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}

	var csvBuffer bytes.Buffer
	if err := WriteCSV(&csvBuffer, report); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&csvBuffer).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("CSV has %d rows, want a header and at least one target", len(rows))
	}
	column := make(map[string]int, len(rows[0]))
	for index, name := range rows[0] {
		column[name] = index
	}

	// Every stats field the CSV also publishes must carry the same number the
	// JSON does, for the same target.
	shared := []string{
		"total", "successes", "failures", "usable_responses", "resolver_failures",
		"scored", "divergent", "truncated", "success_rate", "usable_rate",
		"resolver_failure_rate", "scoring_failure_rate", "median_ms", "p95_ms",
		"min_ms", "max_ms", "mad_ms", "cold_median_ms", "score_ms", "ci_low_ms", "ci_high_ms",
	}
	for _, row := range rows[1:] {
		id := row[column["target_id"]]
		var stats map[string]any
		for _, result := range decoded.Results {
			if result.Target.ID == id {
				stats = result.Stats
			}
		}
		if stats == nil {
			t.Fatalf("CSV row %q has no matching JSON result", id)
		}
		for _, field := range shared {
			index, present := column[field]
			if !present {
				t.Fatalf("CSV header lost the %q column", field)
			}
			want, ok := stats[field].(float64)
			if !ok {
				t.Fatalf("JSON stats.%s is missing or not a number for %s", field, id)
			}
			got, err := strconv.ParseFloat(row[index], 64)
			if err != nil {
				t.Fatalf("CSV %s for %s is not a number: %q", field, id, row[index])
			}
			// The CSV renders floats at three decimals, so the JSON value is
			// compared at that precision. The tolerance covers rounding only
			// -- it is far tighter than any swapped or recomputed field.
			if rounded, err := strconv.ParseFloat(strconv.FormatFloat(want, 'f', 3, 64), 64); err == nil {
				want = rounded
			}
			if got != want {
				t.Fatalf("%s disagrees for %s: CSV %v, JSON %v", field, id, got, want)
			}
		}
	}
}

// TestCSVHeaderIsAppendOnly pins the column order. CSV consumers index by
// position, so inserting a column anywhere but the end silently shifts every
// field after it -- a break no schema can see, because CSV has no schema.
func TestCSVHeaderIsAppendOnly(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteCSV(&buffer, contractFixture()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buffer).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// The published prefix as of v0.3.0. New columns append after it; this
	// list must only ever grow at the end.
	published := []string{
		"target_id", "name", "owner", "policy", "address", "protocol", "rank", "recommended", "tie",
		"total", "successes", "failures", "usable_responses", "resolver_failures", "scored", "divergent",
		"truncated", "success_rate", "usable_rate", "resolver_failure_rate", "scoring_failure_rate",
		"rcode_counts", "median_ms", "p95_ms", "min_ms", "max_ms", "mad_ms", "cold_median_ms",
		"score_ms", "ci_low_ms", "ci_high_ms", "open_error", "reconnects", "incomplete",
		"endpoint_url", "tls_server_name", "tls_identity_source", "bootstrap_mode",
		"bootstrap_addresses", "dial_address", "corpus_mode", "corpus_zone", "corpus_nonce",
		"local", "dnssec_verdict",
	}
	if len(rows[0]) < len(published) {
		t.Fatalf("CSV header shrank to %d columns, want at least the %d published ones", len(rows[0]), len(published))
	}
	for index, want := range published {
		if rows[0][index] != want {
			t.Fatalf("CSV column %d is %q, want %q -- columns may only be appended, never inserted or reordered",
				index, rows[0][index], want)
		}
	}
}

// contractFixture builds a report whose every numeric field differs, so a
// swapped assignment cannot hide behind two equal values. The distinctness is
// the point: the existing golden fixtures reuse the same small numbers across
// adjacent fields, which is precisely why a swap between them renders
// identically and passes.
func contractFixture() benchmark.Report {
	target := reportTarget("50", "udp", 0, true)
	target.Stats = benchmark.Statistics{
		Total: 97, Successes: 91, Failures: 6,
		UsableResponses: 88, ResolverFailures: 3, Scored: 71,
		Divergent: 5, Truncated: 2, Reconnects: 4,
		SuccessRate:         91.0 / 97.0,
		FailureRate:         6.0 / 97.0,
		UsableRate:          88.0 / 97.0,
		ResolverFailureRate: 3.0 / 97.0,
		ScoringFailureRate:  0.041,
		MedianMS:            12.25, P95MS: 33.75, MinMS: 4.5, MaxMS: 61.125,
		MADMS: 2.875, ColdMedianMS: 44.5, ScoreMS: 20.625,
		CILowMS: 18.375, CIHighMS: 23.875,
		RCodeCounts: map[string]int{"NOERROR": 88, "SERVFAIL": 3},
	}
	return benchmark.Report{
		Seed: 7, SampleSize: 40, Queries: 80, QueryTypes: []uint16{1, 28},
		Targets:  []benchmark.TargetResult{target},
		Rankings: []benchmark.Ranking{{Protocol: "udp", TargetID: target.Target.ID(), Rank: 1}},
	}
}

// TestRunHeaderLineDescribesTheRun covers the second header line across the
// shapes a report can actually take. Provenance is an optional pointer, and a
// report without it is valid -- the redaction tests build exactly that -- so
// the header must degrade rather than panic.
func TestRunHeaderLineDescribesTheRun(t *testing.T) {
	started := time.Date(2026, 8, 24, 20, 55, 26, 0, time.UTC)
	base := contractFixture()

	for _, testCase := range []struct {
		name   string
		mutate func(*benchmark.Report)
		want   []string
		absent []string
	}{
		{
			name: "fully populated",
			mutate: func(r *benchmark.Report) {
				r.StartedAt, r.FinishedAt = started, started.Add(94500*time.Millisecond)
				r.Provenance = &benchmark.RunProvenance{Version: "0.4.0", OS: "linux", Architecture: "amd64"}
			},
			want: []string{"2026-08-24T20:55:26Z", "94.5s", "1 targets", "0.4.0 linux/amd64"},
		},
		{
			name:   "no provenance at all",
			mutate: func(r *benchmark.Report) { r.StartedAt = started; r.Provenance = nil },
			want:   []string{"2026-08-24T20:55:26Z", "1 targets"},
			absent: []string{"linux/amd64"},
		},
		{
			name: "provenance without a version",
			mutate: func(r *benchmark.Report) {
				r.Provenance = &benchmark.RunProvenance{OS: "darwin", Architecture: "arm64"}
			},
			want: []string{"dev darwin/arm64"},
		},
		{
			name: "provenance without a platform",
			mutate: func(r *benchmark.Report) {
				r.Provenance = &benchmark.RunProvenance{Version: "0.4.0"}
			},
			want:   []string{"0.4.0"},
			absent: []string{"/"},
		},
		{
			name:   "a report with no timing at all",
			mutate: func(r *benchmark.Report) { r.StartedAt, r.FinishedAt, r.Provenance = time.Time{}, time.Time{}, nil },
			want:   []string{"1 targets"},
			absent: []string{"Z |"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			report := base
			testCase.mutate(&report)
			line := runHeaderLine(report)
			for _, want := range testCase.want {
				if !strings.Contains(line, want) {
					t.Fatalf("header %q is missing %q", line, want)
				}
			}
			for _, absent := range testCase.absent {
				if strings.Contains(line, absent) {
					t.Fatalf("header %q unexpectedly contains %q", line, absent)
				}
			}
		})
	}
}

// TestWriteAlignedTablePadsShortRows pins the guard that stops a forgotten
// column from crashing the report.
//
// Three row builders feed the comparison table. Adding a column to the header
// and missing one of them does not misalign the output -- alignedTableLine
// computes a negative pad and panics with "strings: negative Repeat count", so
// the whole report dies. Padding turns that into a visibly empty cell, which a
// reader and a golden diff can both see.
func TestWriteAlignedTablePadsShortRows(t *testing.T) {
	var buffer bytes.Buffer
	err := writeAlignedTable(&buffer,
		[]string{"Rank", "Owner", "Score", "Status"},
		[][]string{{"1", "Owner", "2.00 ms", "QUALIFIED"}, {"2", "Short"}},
	)
	if err != nil {
		t.Fatalf("a short row must render, not fail: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buffer.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want a header and two rows", len(lines))
	}
	if !strings.Contains(lines[2], "Short") {
		t.Fatalf("the short row lost its content: %q", lines[2])
	}
	// The full row must still be aligned against the header.
	if !strings.Contains(lines[1], "QUALIFIED") {
		t.Fatalf("the complete row was damaged: %q", lines[1])
	}
}
