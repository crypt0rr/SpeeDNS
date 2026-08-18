package report

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/benchmark"
	"github.com/crypt0rr/dns-speedtest/internal/catalog"
)

type failingWriter struct {
	failAt int
	writes int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.failAt > 0 && w.writes == w.failAt {
		return 0, errors.New("writer failed")
	}
	return len(p), nil
}

type fakeCSVWriter struct {
	writes    int
	headerErr error
	rowErr    error
	flushErr  error
}

func (w *fakeCSVWriter) Write(row []string) error {
	w.writes++
	if w.writes == 1 {
		return w.headerErr
	}
	return w.rowErr
}

func (w *fakeCSVWriter) Flush() {}

func (w *fakeCSVWriter) Error() error { return w.flushErr }

func reportTarget(id string, protocol catalog.Protocol, scored int, recommended bool) benchmark.TargetResult {
	return benchmark.TargetResult{
		Target: catalog.Target{
			Resolver: catalog.ResolverProfile{ID: id, Name: "Resolver " + id, Owner: "Owner " + id, Policy: "unfiltered"},
			Protocol: protocol,
			Address:  "192.0.2." + id,
		},
		Stats: benchmark.Statistics{
			Total: 2, Successes: 2, Scored: scored, SuccessRate: 1, MedianMS: 2, P95MS: 3,
			MinMS: 1, MaxMS: 4, MADMS: 0.5, ColdMedianMS: 5, ScoreMS: 2.4,
			CILowMS: 1, CIHighMS: 4, Recommended: recommended,
		},
	}
}

func completeReport() benchmark.Report {
	winner := reportTarget("1", catalog.UDP, 2, true)
	winner.Observations = []benchmark.Observation{{Name: "example.com", QType: 1, Success: true, LatencyMS: 2}}
	winner.Cold = []benchmark.ColdObservation{{Name: "example.com", QType: 1, Success: true, LatencyMS: 5}}
	failed := reportTarget("2", catalog.TCP, 0, false)
	failed.Stats = benchmark.Statistics{}
	failed.OpenError = "open failed"
	missing := reportTarget("3", catalog.DoH, 2, false)
	return benchmark.Report{
		StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0), Seed: 42, SampleSize: 2, Queries: 4,
		QueryTypes: []uint16{1, 65000}, Targets: []benchmark.TargetResult{failed, winner, missing},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.DoH, TargetID: "missing-target", Rank: 1},
			{Protocol: catalog.UDP, TargetID: winner.Target.ID(), Rank: 1},
			{Protocol: catalog.UDP, TargetID: winner.Target.ID(), Rank: 2},
		},
		Warnings: []string{"example warning"},
	}
}

func TestJSONRawAndWriterErrors(t *testing.T) {
	run := completeReport()
	var output bytes.Buffer
	if err := WriteJSON(&output, run, true); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"\"samples\"", "\"cold\"", "example warning"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("raw JSON missing %q: %s", expected, text)
		}
	}
	if err := WriteJSON(&failingWriter{failAt: 1}, run, false); err == nil {
		t.Fatal("expected JSON writer error")
	}
	if got := queryTypes(nil); got != "" {
		t.Fatalf("empty query type string = %q", got)
	}
	if got := queryTypes([]uint16{1, 65000}); got != "A,TYPE65000" {
		t.Fatalf("query type string = %q", got)
	}
}

func TestCSVWriterErrorPathsAndMetadata(t *testing.T) {
	old := newCSVWriter
	t.Cleanup(func() { newCSVWriter = old })
	run := completeReport()
	newCSVWriter = func(io.Writer) csvWriter { return &fakeCSVWriter{headerErr: errors.New("header failed")} }
	if err := WriteCSV(bytes.NewBuffer(nil), run); err == nil || err.Error() != "header failed" {
		t.Fatalf("CSV header error = %v", err)
	}
	newCSVWriter = func(io.Writer) csvWriter { return &fakeCSVWriter{rowErr: errors.New("row failed")} }
	if err := WriteCSV(bytes.NewBuffer(nil), run); err == nil || err.Error() != "row failed" {
		t.Fatalf("CSV row error = %v", err)
	}
	newCSVWriter = func(io.Writer) csvWriter { return &fakeCSVWriter{flushErr: errors.New("flush failed")} }
	if err := WriteCSV(bytes.NewBuffer(nil), run); err == nil || err.Error() != "flush failed" {
		t.Fatalf("CSV flush error = %v", err)
	}

	newCSVWriter = old
	var output bytes.Buffer
	if err := WriteCSV(&output, run); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"target_id", "open_error", "open failed", "Owner 1"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("CSV output missing %q: %s", expected, output.String())
		}
	}
	if got := rankFor(run, "missing"); got != 0 {
		t.Fatalf("missing rank = %d", got)
	}
}

func TestTableSuccessAndAllWriterFailureSites(t *testing.T) {
	run := completeReport()
	var output bytes.Buffer
	if err := WriteTable(&output, run, false); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"Recommendations", "Comparison", "FAIL", "recommended", "Warnings", "example warning"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("table output missing %q: %s", expected, text)
		}
	}
	output.Reset()
	if err := WriteTable(&output, run, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cold") || !strings.Contains(output.String(), "mad") {
		t.Fatalf("detailed table missing cold/MAD: %s", output.String())
	}

	// The complete report has this deterministic write order: header,
	// recommendations heading, the UDP winner, comparison heading, comparison
	// header, failed row, warning heading, warning row.
	for failAt := 1; failAt <= 10; failAt++ {
		writer := &failingWriter{failAt: failAt}
		if err := WriteTable(writer, run, false); err == nil {
			t.Fatalf("failAt=%d did not return an error", failAt)
		}
	}
	if err := WriteTable(&failingWriter{failAt: 7}, run, true); err == nil {
		t.Fatal("detailed row writer failure did not return an error")
	}

	// A ranking without a matching result exercises the recommendation skip.
	missing := run
	missing.Rankings = []benchmark.Ranking{{Protocol: catalog.DoH, TargetID: "does-not-exist", Rank: 1}}
	if err := WriteTable(&bytes.Buffer{}, missing, false); err != nil {
		t.Fatal(err)
	}

	// A compact and detailed scored row each use a different formatting branch.
	rowTarget := reportTarget("4", catalog.UDP, 1, false)
	row := benchmark.Report{
		Seed: 1, SampleSize: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{rowTarget},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: rowTarget.Target.ID(), Rank: 1}},
	}
	if err := WriteTable(&bytes.Buffer{}, row, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteTable(&bytes.Buffer{}, row, true); err != nil {
		t.Fatal(err)
	}
}
