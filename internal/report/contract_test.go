package report

import (
	"bytes"

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
