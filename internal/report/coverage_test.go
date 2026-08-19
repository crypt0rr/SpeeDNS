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

type contentFailWriter struct{ needle string }

func (w contentFailWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.needle) {
		return 0, errors.New("content writer failed")
	}
	return len(p), nil
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
	winner.DialAddress = "192.0.2.1:53"
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
	if strings.Contains(text, "dial_address") {
		t.Fatalf("JSON schema unexpectedly exposed human-only dial metadata: %s", text)
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
	for _, expected := range []string{"Recommendations", "Comparisons", "FAILED", "RECOMMENDED", "Warnings", "example warning"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("table output missing %q: %s", expected, text)
		}
	}
	output.Reset()
	if err := WriteTable(&output, run, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Cold") || !strings.Contains(output.String(), "MAD") || !strings.Contains(output.String(), "Dial") || !strings.Contains(output.String(), "192.0.2.1:53") {
		t.Fatalf("detailed table missing cold/MAD/dial: %s", output.String())
	}

	// Exercise every top-level write failure path. Tables buffer their output
	// through tabwriter, so each table flush is a single writer call.
	for failAt := 1; failAt <= 12; failAt++ {
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

func TestTableSeparatesQualifiedAndProvisionalResults(t *testing.T) {
	provisional := reportTarget("1", catalog.UDP, 5, false)
	recommended := reportTarget("2", catalog.UDP, benchmark.MinimumRecommendedSamples, true)
	recommended.Stats.ScoreMS = 4
	provisional.Stats.ScoreMS = 1
	run := benchmark.Report{
		Seed: 42, SampleSize: 5, Queries: 5, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{provisional, recommended},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.UDP, TargetID: provisional.Target.ID(), Rank: 1},
			{Protocol: catalog.UDP, TargetID: recommended.Target.ID(), Rank: 2},
		},
	}

	var output bytes.Buffer
	if err := WriteTable(&output, run, false); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "Recommendations") || !strings.Contains(text, "Owner 2") || !strings.Contains(text, "RECOMMENDED") {
		t.Fatalf("qualified result missing from recommendations: %s", text)
	}
	if strings.Contains(text, "Provisional winners") {
		t.Fatalf("provisional section should be absent when a qualified result exists: %s", text)
	}

	provisional.Stats.ScoreMS = 1
	provisional.Stats.Scored = 5
	run.Targets = []benchmark.TargetResult{provisional}
	run.Rankings = []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: provisional.Target.ID(), Rank: 1}}
	output.Reset()
	if err := WriteTable(&output, run, false); err != nil {
		t.Fatal(err)
	}
	text = output.String()
	for _, expected := range []string{"none qualified", "Provisional winners", "Owner 1", "PROVISIONAL"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("provisional output missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "*recommended*") {
		t.Fatalf("unqualified result was marked recommended: %s", text)
	}
	for _, failAt := range []int{3, 4, 5} {
		if err := WriteTable(&failingWriter{failAt: failAt}, run, false); err == nil {
			t.Fatalf("provisional writer failure at write %d was not returned", failAt)
		}
	}
}

func TestWarningAggregationAndColoredTables(t *testing.T) {
	udpFirst := reportTarget("1", catalog.UDP, 0, false)
	udpFirst.Stats = benchmark.Statistics{Total: 5, Failures: 5}
	udpFirst.OpenError = "dial udp timeout"
	udpSecond := reportTarget("2", catalog.UDP, 0, false)
	udpSecond.Stats = benchmark.Statistics{Total: 5, Failures: 5}
	udpSecond.OpenError = "dial udp timeout"
	partial := reportTarget("3", catalog.DoT, 2, false)
	partial.Stats = benchmark.Statistics{Total: 5, Successes: 2, Failures: 3, Scored: 2, Divergent: 1, Truncated: 1, SuccessRate: .4, ScoreMS: 4}
	run := benchmark.Report{
		Targets: []benchmark.TargetResult{udpFirst, udpSecond, partial},
		Warnings: []string{
			targetWarningLabel(udpFirst) + " could not open a session: dial udp timeout",
			targetWarningLabel(udpFirst) + " had 5/5 failed queries",
			targetWarningLabel(partial) + " had 3/5 failed queries",
			"benchmark interrupted before all targets completed",
		},
	}

	warnings := compactWarnings(run)
	joined := strings.Join(warnings, "\n")
	for _, expected := range []string{
		"udp: 2/2 endpoints unavailable; 10/10 measured queries failed",
		"Resolver 3 192.0.2.3/dot: 3/5 queries failed; 1 divergent responses; 1 truncated responses",
		"benchmark interrupted before all targets completed",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("compact warnings missing %q: %s", expected, joined)
		}
	}
	if strings.Contains(joined, "could not open a session") || strings.Count(joined, "5/5 failed") != 0 {
		t.Fatalf("compact warnings retained duplicate raw details: %s", joined)
	}

	var detailOutput bytes.Buffer
	if err := writeWarnings(&detailOutput, run, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detailOutput.String(), "could not open a session") || !strings.Contains(detailOutput.String(), "5/5 failed queries") {
		t.Fatalf("details omitted raw warning information: %s", detailOutput.String())
	}

	var colorOutput bytes.Buffer
	if err := WriteTableWithOptions(&colorOutput, completeReport(), TableOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colorOutput.String(), ansiGreen+"RECOMMENDED"+ansiReset) {
		t.Fatalf("colored recommendation missing ANSI styling: %q", colorOutput.String())
	}
	var plainOutput bytes.Buffer
	if err := WriteTableWithOptions(&plainOutput, completeReport(), TableOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plainOutput.String(), "\x1b[") {
		t.Fatalf("plain table unexpectedly contains ANSI styling: %q", plainOutput.String())
	}
}

func TestReportFormattingBranchesAndWriteErrors(t *testing.T) {
	if got := styledStatus("OTHER", true); got != "OTHER" {
		t.Fatalf("unknown styled status = %q", got)
	}
	custom := catalog.Protocol("custom")
	customOther := catalog.Protocol("custom-other")
	customTarget := reportTarget("custom", custom, 0, false)
	customOtherTarget := reportTarget("custom-other", customOther, 0, false)
	if protocols := reportProtocols(benchmark.Report{Targets: []benchmark.TargetResult{customTarget, customOtherTarget}}); len(protocols) != 2 || protocols[0] != custom || protocols[1] != customOther {
		t.Fatalf("custom protocol ordering = %#v", protocols)
	}

	ranked := reportTarget("ranked", catalog.UDP, 1, false)
	ranked.Stats.ScoreMS = 1
	unrankedA := reportTarget("unranked-a", catalog.UDP, 0, false)
	unrankedA.Stats = benchmark.Statistics{Total: 1}
	unrankedB := reportTarget("unranked-b", catalog.UDP, 0, false)
	unrankedB.Stats = benchmark.Statistics{Total: 1}
	unrankedC := reportTarget("unranked-c", catalog.UDP, 0, false)
	unrankedC.Stats = benchmark.Statistics{Total: 1}
	unrankedC.Target.Resolver.Owner = unrankedA.Target.Resolver.Owner
	unrankedC.Target.Address = "192.0.2.z"
	comparisonReport := benchmark.Report{
		Targets:  []benchmark.TargetResult{unrankedB, ranked, unrankedA, unrankedC},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: ranked.Target.ID(), Rank: 1}},
	}
	rows := comparisonRows(comparisonReport, catalog.UDP, false, false)
	if len(rows) != 4 || rows[0][0] != "1" || rows[1][1] != "Owner unranked-a" || rows[2][1] != "Owner unranked-a" || rows[3][1] != "Owner unranked-b" {
		t.Fatalf("comparison ordering = %#v", rows)
	}
	if rows[1][0] != "—" || rows[2][0] != "—" || rows[3][0] != "—" {
		t.Fatalf("unranked rows = %#v", rows)
	}

	emptyProtocol := benchmark.Report{Rankings: []benchmark.Ranking{{Protocol: catalog.DoH, TargetID: "missing", Rank: 1}}}
	var emptyOutput bytes.Buffer
	if err := WriteTable(&emptyOutput, emptyProtocol, false); err != nil || !strings.Contains(emptyOutput.String(), "no targets") {
		t.Fatalf("empty protocol report = %v/%s", err, emptyOutput.String())
	}
	emptyReport := benchmark.Report{}
	if err := WriteTable(&bytes.Buffer{}, emptyReport, false); err != nil {
		t.Fatal(err)
	}

	warningReport := benchmark.Report{Warnings: []string{"generic warning"}}
	if err := writeWarnings(&failingWriter{failAt: 1}, warningReport, false); err == nil {
		t.Fatal("warning heading write failure was not returned")
	}
	if err := writeWarnings(&failingWriter{failAt: 2}, warningReport, true); err == nil {
		t.Fatal("warning row write failure was not returned")
	}
	if err := WriteTableWithOptions(&failingWriter{failAt: 3}, emptyReport, TableOptions{}); err == nil {
		t.Fatal("no-recommendation write failure was not returned")
	}
	if err := WriteTableWithOptions(&failingWriter{failAt: 4}, benchmark.Report{Targets: []benchmark.TargetResult{reportTarget("p", catalog.UDP, 1, false)}, Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: "p@192.0.2.p/udp", Rank: 1}}}, TableOptions{}); err == nil {
		t.Fatal("provisional heading write failure was not returned")
	}
	if err := WriteTableWithOptions(&failingWriter{failAt: 4}, emptyProtocol, TableOptions{}); err == nil {
		t.Fatal("comparison heading write failure was not returned")
	}
	if err := WriteTableWithOptions(&failingWriter{failAt: 5}, emptyProtocol, TableOptions{}); err == nil {
		t.Fatal("protocol heading write failure was not returned")
	}
	if err := WriteTableWithOptions(&failingWriter{failAt: 6}, emptyProtocol, TableOptions{}); err == nil {
		t.Fatal("empty protocol row write failure was not returned")
	}
	if err := writeAlignedTable(contentFailWriter{needle: "Header"}, []string{"Header"}, [][]string{{"Value"}}); err == nil {
		t.Fatal("table header write failure was not returned")
	}
	if err := writeAlignedTable(contentFailWriter{needle: "Value"}, []string{"Header"}, [][]string{{"Value"}}); err == nil {
		t.Fatal("table row write failure was not returned")
	}

	provisional := reportTarget("p", catalog.UDP, 1, false)
	provisionalReport := benchmark.Report{
		Targets:  []benchmark.TargetResult{provisional},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: provisional.Target.ID(), Rank: 1}},
	}
	if err := WriteTableWithOptions(contentFailWriter{needle: "INELIGIBLE"}, provisionalReport, TableOptions{}); err == nil {
		t.Fatal("comparison table write failure was not returned")
	}
	warningReportWithTarget := provisionalReport
	warningReportWithTarget.Warnings = []string{"generic warning"}
	if err := WriteTableWithOptions(contentFailWriter{needle: "generic warning"}, warningReportWithTarget, TableOptions{}); err == nil {
		t.Fatal("warning row propagation was not returned")
	}
}
