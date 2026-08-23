package report

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
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
			Total: 2, Successes: 2, UsableResponses: 2, Scored: scored, SuccessRate: 1, UsableRate: 1, MedianMS: 2, P95MS: 3,
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
	missing.Target.Spec = catalog.TransportSpec{
		URL: "https://cdn.example/dns-query", ServerName: "resolver.example",
		BootstrapAddresses: []string{"192.0.2.53", "2001:db8::53"},
	}
	missing.DialAddress = "2001:db8::53:443"
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
	for _, expected := range []string{"\"endpoint_url\": \"https://cdn.example/dns-query\"", "\"tls_server_name\": \"resolver.example\"", "\"tls_identity_source\": \"configured\"", "\"bootstrap_mode\": \"explicit\"", "\"bootstrap_addresses\": [", "\"dial_address\": \"2001:db8::53:443\""} {
		if !strings.Contains(text, expected) {
			t.Fatalf("JSON missing endpoint audit field %q: %s", expected, text)
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
	for _, expected := range []string{"target_id", "open_error", "reconnects", "incomplete", "endpoint_url", "tls_server_name", "bootstrap_mode", "dial_address", "open failed", "Owner 1", "https://cdn.example/dns-query"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("CSV output missing %q: %s", expected, output.String())
		}
	}
	if got := rankFor(run, "missing"); got != 0 {
		t.Fatalf("missing rank = %d", got)
	}
}

func TestCSVFormulaLeadingCellsAreProtected(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{value: "=formula", want: "'=formula"},
		{value: "+formula", want: "'+formula"},
		{value: "-formula", want: "'-formula"},
		{value: "@formula", want: "'@formula"},
		{value: "\tformula", want: "'\tformula"},
		{value: "\rformula", want: "'\rformula"},
		{value: "normal", want: "normal"},
		{value: "", want: ""},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := csvCell(tc.value); got != tc.want {
				t.Fatalf("csvCell(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestCSVFormulaProtectionCoversTargetAndErrorFields(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "=target", Name: "+name", Owner: "-owner", Policy: "@policy"},
		Protocol: catalog.UDP,
		Address:  "\taddress",
	}
	run := benchmark.Report{Targets: []benchmark.TargetResult{{Target: target, OpenError: "\rerror"}}}
	var output bytes.Buffer
	if err := WriteCSV(&output, run); err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(strings.NewReader(output.String()))
	header, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	row, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(header))
	for index, name := range header {
		values[name] = row[index]
	}
	for name, want := range map[string]string{
		"target_id":  "'=target@\taddress/udp",
		"name":       "'+name",
		"owner":      "'-owner",
		"policy":     "'@policy",
		"address":    "'\taddress",
		"open_error": "'\rerror",
	} {
		if values[name] != want {
			t.Fatalf("CSV %s = %q, want %q", name, values[name], want)
		}
	}
}

func TestSystemReportRedactionPreservesRankingsWithoutLocalAddresses(t *testing.T) {
	systemTarget := catalog.Target{
		Resolver: catalog.ResolverProfile{
			ID: "system-stub-127-0-0-53", Name: "System DNS stub (scope: corp.example)",
			Owner: "local stub/forwarder (interface: utun0)", Policy: "local forwarding",
		},
		Protocol: catalog.UDP, Address: "127.0.0.53", Spec: catalog.TransportSpec{Port: 53},
	}
	system := benchmark.TargetResult{
		Target: systemTarget, DialAddress: "127.0.0.53:53", OpenError: "dial udp 127.0.0.53:53: timeout",
		Observations: []benchmark.Observation{{Name: "example.com", Error: "read 127.0.0.53:53: timeout"}},
		Cold:         []benchmark.ColdObservation{{Name: "example.com", Error: "dial 127.0.0.53:53: timeout"}},
		Stats:        benchmark.Statistics{Total: 1, Failures: 1},
	}
	regular := reportTarget("regular", catalog.UDP, 0, false)
	run := benchmark.Report{
		Seed: 7, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{system, regular},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: systemTarget.ID(), Rank: 1}},
		Warnings: []string{
			targetWarningLabel(system) + ": dial 127.0.0.53:53 failed",
			"global diagnostic mentions 127.0.0.53",
		},
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSONWithOptions(&jsonOutput, run, true, JSONOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	jsonText := jsonOutput.String()
	for _, forbidden := range []string{"127.0.0.53", "scope: corp.example", "interface: utun0"} {
		if strings.Contains(jsonText, forbidden) {
			t.Fatalf("redacted JSON leaked %q: %s", forbidden, jsonText)
		}
	}
	for _, expected := range []string{"system-redacted-1@redacted/udp", "System DNS (redacted)", "configured locally (redacted)", "redacted", "global diagnostic mentions redacted"} {
		if !strings.Contains(jsonText, expected) {
			t.Fatalf("redacted JSON missing %q: %s", expected, jsonText)
		}
	}

	var csvOutput bytes.Buffer
	if err := WriteCSVWithOptions(&csvOutput, run, CSVOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	csvText := csvOutput.String()
	if strings.Contains(csvText, "127.0.0.53") || !strings.Contains(csvText, "system-redacted-1@redacted/udp") || !strings.Contains(csvText, "redacted") {
		t.Fatalf("redacted CSV = %s", csvText)
	}

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{Details: true, RedactSystem: true, Protocols: []catalog.Protocol{catalog.UDP}}); err != nil {
		t.Fatal(err)
	}
	tableText := table.String()
	if strings.Contains(tableText, "127.0.0.53") || strings.Contains(tableText, "scope: corp.example") || !strings.Contains(tableText, "System DNS (redacted)") || !strings.Contains(tableText, "redacted") {
		t.Fatalf("redacted table = %s", tableText)
	}

	unsupportedProfile := systemTarget.Resolver
	unsupportedProfile.Transports = map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}}
	table.Reset()
	if err := WriteTableWithOptions(&table, run, TableOptions{RedactSystem: true, Profiles: []catalog.ResolverProfile{unsupportedProfile}, Protocols: []catalog.Protocol{catalog.DoQ}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(table.String(), "127.0.0.53") || !strings.Contains(table.String(), "redacted") {
		t.Fatalf("redacted unsupported matrix = %s", table.String())
	}
	if got := redactResultText(benchmark.TargetResult{Target: systemTarget}, "127.0.0.53", true, "system-redacted-1@redacted/udp"); got != "redacted" {
		t.Fatalf("redaction with no selected dial address = %q", got)
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
	if !strings.Contains(output.String(), "Cold") || !strings.Contains(output.String(), "MAD") || !strings.Contains(output.String(), "Reconnects") || !strings.Contains(output.String(), "Dial") || !strings.Contains(output.String(), "192.0.2.1:53") {
		t.Fatalf("detailed table missing cold/MAD/dial: %s", output.String())
	}
	secure := reportTarget("secure", catalog.DoH, 1, false)
	secure.Target.Spec = catalog.TransportSpec{
		URL: "https://cdn.example/dns-query", ServerName: "resolver.example",
		BootstrapAddresses: []string{"192.0.2.53", "2001:db8::53"},
	}
	secure.DialAddress = "192.0.2.53:443"
	secureRun := benchmark.Report{
		Seed: 1, SampleSize: 1, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{secure},
		Rankings: []benchmark.Ranking{{Protocol: catalog.DoH, TargetID: secure.Target.ID(), Rank: 1}},
	}
	output.Reset()
	if err := WriteTable(&output, secureRun, true); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Endpoint", "TLSName", "resolver.example", "configured", "explicit", "192.0.2.53;2001:db8::53", "https://cdn.example/dns-query"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("detailed endpoint audit missing %q: %s", expected, output.String())
		}
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

func TestDivergenceDetailsAreRenderedAndExported(t *testing.T) {
	first := reportTarget("first", catalog.UDP, 2, false)
	second := reportTarget("second", catalog.UDP, 1, false)
	run := benchmark.Report{
		Seed: 42, SampleSize: 2, Queries: 2, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{first, second},
		Divergence: []benchmark.DivergenceDetail{
			{
				Name: "example.com", QType: 1, Policy: "unfiltered", Compared: 2,
				Baseline: "answer", Classes: map[string]int{"answer": 1, "nxdomain": 1},
				Excluded: []benchmark.DivergenceExclusion{{TargetID: second.Target.ID(), ResponseClass: "nxdomain"}},
			},
		},
	}
	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Divergence details", "baseline=answer", "classes=answer:1,nxdomain:1", second.Target.ID() + "=nxdomain"} {
		if !strings.Contains(table.String(), expected) {
			t.Fatalf("detailed divergence output missing %q: %s", expected, table.String())
		}
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, run, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\"divergence\"", "\"baseline\": \"answer\"", second.Target.ID()} {
		if !strings.Contains(jsonOutput.String(), expected) {
			t.Fatalf("JSON divergence output missing %q: %s", expected, jsonOutput.String())
		}
	}

	ambiguous := run
	ambiguous.Divergence = []benchmark.DivergenceDetail{{
		Name: "ambiguous.example", QType: 1, Policy: "unfiltered", Compared: 2,
		Ambiguous: true, Classes: nil,
	}}
	var ambiguousTable bytes.Buffer
	if err := WriteTableWithOptions(&ambiguousTable, ambiguous, TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ambiguous (no baseline)", "classes=—", "excluded=none"} {
		if !strings.Contains(ambiguousTable.String(), expected) {
			t.Fatalf("ambiguous divergence output missing %q: %s", expected, ambiguousTable.String())
		}
	}
	if err := WriteJSON(&bytes.Buffer{}, ambiguous, false); err != nil {
		t.Fatal(err)
	}
	if got := divergenceClassesText(nil); got != "—" {
		t.Fatalf("empty divergence classes = %q", got)
	}
	if got := divergenceExcludedText(benchmark.DivergenceDetail{}, nil); got != "none" {
		t.Fatalf("empty divergence exclusions = %q", got)
	}
	if err := writeDivergenceDetails(contentFailWriter{needle: "Divergence details"}, run, false); err == nil {
		t.Fatal("divergence header writer failure was not returned")
	}
	if err := writeDivergenceDetails(contentFailWriter{needle: "baseline=answer"}, run, false); err == nil {
		t.Fatal("divergence row writer failure was not returned")
	}
	if err := WriteTableWithOptions(contentFailWriter{needle: "Divergence details"}, run, TableOptions{Details: true}); err == nil {
		t.Fatal("top-level divergence writer failure was not returned")
	}

	system := reportTarget("system-divergence", catalog.UDP, 1, false)
	redacted := run
	redacted.Targets = append(redacted.Targets, system)
	redacted.Divergence = []benchmark.DivergenceDetail{{
		Name: "system.example", QType: 1, Policy: "unfiltered", Compared: 2,
		Baseline: "answer", Classes: map[string]int{"answer": 1, "nxdomain": 1},
		Excluded: []benchmark.DivergenceExclusion{{TargetID: system.Target.ID(), ResponseClass: "nxdomain"}},
	}}
	var redactedJSON bytes.Buffer
	if err := WriteJSONWithOptions(&redactedJSON, redacted, false, JSONOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redactedJSON.String(), system.Target.ID()) || !strings.Contains(redactedJSON.String(), "system-redacted-1@redacted/udp") {
		t.Fatalf("redacted divergence JSON = %s", redactedJSON.String())
	}
	var redactedTable bytes.Buffer
	if err := WriteTableWithOptions(&redactedTable, redacted, TableOptions{Details: true, RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redactedTable.String(), system.Target.ID()) || !strings.Contains(redactedTable.String(), "system-redacted-1@redacted/udp") {
		t.Fatalf("redacted divergence table = %s", redactedTable.String())
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
	rcodeOnly := reportTarget("4", catalog.TCP, 0, false)
	rcodeOnly.Stats = benchmark.Statistics{Total: 5, Successes: 5, ResolverFailures: 5, RCodeCounts: map[string]int{"SERVFAIL": 5}}
	divergentOnly := reportTarget("5", catalog.DoQ, 0, false)
	divergentOnly.Stats = benchmark.Statistics{Total: 2, Successes: 2, UsableResponses: 2, Divergent: 2}
	run := benchmark.Report{
		Targets: []benchmark.TargetResult{udpFirst, udpSecond, partial, rcodeOnly, divergentOnly},
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
	incomplete := reportTarget("incomplete", catalog.UDP, 0, false)
	incomplete.Incomplete = true
	incomplete.OpenError = "context canceled"
	incompleteReport := benchmark.Report{Targets: []benchmark.TargetResult{incomplete}}
	if incompleteWarnings := strings.Join(compactWarnings(incompleteReport), "\n"); !strings.Contains(incompleteWarnings, "incomplete; excluded from ranking") {
		t.Fatalf("compact incomplete warning missing: %s", incompleteWarnings)
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

func TestWarningAggregationCollapsesUnavailableIPv6Targets(t *testing.T) {
	failedIPv4 := reportTarget("v4", catalog.UDP, 1, false)
	failedIPv6UDP := reportTarget("v6-udp", catalog.UDP, 0, false)
	failedIPv6UDP.Target.Address = "2001:db8::1"
	failedIPv6UDP.Stats = benchmark.Statistics{Total: 4, Failures: 4}
	failedIPv6DoH := reportTarget("v6-doh", catalog.DoH, 0, false)
	failedIPv6DoH.Target.Address = "2001:db8::2"
	failedIPv6DoH.Stats = benchmark.Statistics{Total: 4, Failures: 4}
	run := benchmark.Report{
		Targets: []benchmark.TargetResult{failedIPv4, failedIPv6UDP, failedIPv6DoH},
		Warnings: []string{
			targetWarningLabel(failedIPv6UDP) + " had 4/4 failed queries",
			targetWarningLabel(failedIPv6DoH) + " had 4/4 failed queries",
		},
	}

	warnings := compactWarnings(run)
	if len(warnings) != 1 || warnings[0] != "IPv6: 2/2 endpoints unavailable across udp,doh; no usable IPv6 path detected" {
		t.Fatalf("IPv6 warning aggregation = %#v", warnings)
	}
	if strings.Contains(warnings[0], "2001:db8") {
		t.Fatalf("IPv6 warning leaked endpoint addresses: %#v", warnings)
	}

	availableIPv6 := failedIPv6DoH
	availableIPv6.Stats = benchmark.Statistics{Total: 4, Successes: 4, UsableResponses: 4, Scored: 4}
	partial := benchmark.Report{Targets: []benchmark.TargetResult{failedIPv4, failedIPv6UDP, availableIPv6}}
	partialWarnings := strings.Join(compactWarnings(partial), "\n")
	if strings.Contains(partialWarnings, "no usable IPv6 path detected") || !strings.Contains(partialWarnings, "v6-udp") {
		t.Fatalf("partial IPv6 failures were over-aggregated: %s", partialWarnings)
	}

	if !transportUnavailable(benchmark.TargetResult{OpenError: "dial failed"}) {
		t.Fatal("open failure with no measurements was not treated as unavailable")
	}
	if transportUnavailable(benchmark.TargetResult{}) {
		t.Fatal("empty target was treated as unavailable")
	}
	if transportUnavailable(benchmark.TargetResult{Incomplete: true, OpenError: "context canceled"}) {
		t.Fatal("incomplete target was treated as unavailable")
	}
}

func TestResolverOutcomeMetricsAreVisible(t *testing.T) {
	result := reportTarget("semantic", catalog.UDP, 1, false)
	result.Stats = benchmark.Statistics{
		Total: 3, Successes: 3, UsableResponses: 1, ResolverFailures: 2, Scored: 1,
		SuccessRate: 1, UsableRate: 1.0 / 3.0, ScoreMS: 4,
		RCodeCounts: map[string]int{"SERVFAIL": 2, "NOERROR": 1},
	}
	run := benchmark.Report{
		Seed: 42, SampleSize: 3, Queries: 3, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{result},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: result.Target.ID(), Rank: 1}},
	}

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	text := table.String()
	for _, expected := range []string{"Usable", "ResolverFail", "RCodes", "33.33%", "NOERROR:1,SERVFAIL:2"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("semantic table output missing %q: %s", expected, text)
		}
	}
	warnings := strings.Join(compactWarnings(run), "\n")
	if !strings.Contains(warnings, "2 unusable DNS responses (NOERROR:1,SERVFAIL:2)") {
		t.Fatalf("semantic warning missing response-code counts: %s", warnings)
	}

	var jsonOutput bytes.Buffer
	result.Observations = []benchmark.Observation{{Success: true, Usable: false, RCode: 2, ResponseClass: "rcode-2"}}
	run.Targets[0] = result
	if err := WriteJSON(&jsonOutput, run, true); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"\"usable\": false", "\"rcode\": 2", "\"usable_rate\": 0.3333333333333333"} {
		if !strings.Contains(jsonOutput.String(), expected) {
			t.Fatalf("semantic JSON output missing %q: %s", expected, jsonOutput.String())
		}
	}

	var csvOutput bytes.Buffer
	if err := WriteCSV(&csvOutput, run); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"usable_responses", "resolver_failures", "usable_rate", "rcode_counts"} {
		if !strings.Contains(csvOutput.String(), expected) {
			t.Fatalf("semantic CSV output missing %q: %s", expected, csvOutput.String())
		}
	}
}

func TestProtocolMatrixAndTruthfulStatuses(t *testing.T) {
	statuses := []struct {
		name  string
		stats benchmark.Statistics
		want  string
	}{
		{name: "unreachable", stats: benchmark.Statistics{Total: 2, Failures: 2}, want: "FAILED"},
		{name: "servfail only", stats: benchmark.Statistics{Total: 2, Successes: 2, ResolverFailures: 2}, want: "INELIGIBLE"},
		{name: "divergent only", stats: benchmark.Statistics{Total: 2, Successes: 2, Divergent: 2}, want: "INELIGIBLE"},
		{name: "incomplete", stats: benchmark.Statistics{Total: 2, Successes: 2, Scored: 2}, want: "INCOMPLETE"},
		{name: "provisional", stats: benchmark.Statistics{Total: 5, Successes: 5, Scored: 5}, want: "INELIGIBLE"},
		{name: "qualified", stats: benchmark.Statistics{Total: 20, Successes: 20, Scored: 20, Recommended: true}, want: "QUALIFIED"},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			result := benchmark.TargetResult{Stats: tc.stats, Incomplete: tc.name == "incomplete"}
			if got := resultStatus(result); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}

	profile := catalog.ResolverProfile{
		ID: "matrix", Name: "Matrix resolver", Owner: "Matrix owner", Policy: "unfiltered",
		Addresses: []string{"192.0.2.1"}, Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}},
	}
	target := catalog.Target{Resolver: profile, Protocol: catalog.UDP, Address: "192.0.2.1", Spec: profile.Transports[catalog.UDP]}
	result := benchmark.TargetResult{Target: target, Stats: benchmark.Statistics{Total: 5, Successes: 5, Scored: 5, SuccessRate: 1, ScoreMS: 2}}
	run := benchmark.Report{
		Seed: 42, SampleSize: 5, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{result},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: target.ID(), Rank: 1}},
	}
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, run, TableOptions{Details: true, Profiles: []catalog.ResolverProfile{profile}, Protocols: []catalog.Protocol{catalog.UDP, catalog.DoQ}}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"Protocol UDP", "Protocol DOQ", "Matrix owner", "192.0.2.1", "—"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("matrix output missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "Protocol TCP") || strings.Contains(text, "Protocol DOT") {
		t.Fatalf("matrix output included unselected protocols: %s", text)
	}
	custom := catalog.Protocol("custom")
	customOther := catalog.Protocol("custom-other")
	if got := tableProtocols(benchmark.Report{}, TableOptions{Protocols: []catalog.Protocol{customOther, custom}}); len(got) != 2 || got[0] != custom || got[1] != customOther {
		t.Fatalf("custom table protocol ordering = %#v", got)
	}
	presentUnsupported := run
	presentUnsupported.Targets = append(presentUnsupported.Targets, benchmark.TargetResult{Target: catalog.Target{Resolver: profile, Protocol: catalog.DoQ, Address: "192.0.2.1"}})
	if rows := comparisonRowsForTable(presentUnsupported, catalog.DoQ, TableOptions{Details: true, Profiles: []catalog.ResolverProfile{profile}}); len(rows) != 1 || len(rows[0]) != len(comparisonHeaders(true)) {
		t.Fatalf("present unsupported rows = %#v", rows)
	}

	provisional := result
	provisional.Target = catalog.Target{Resolver: profile, Protocol: catalog.TCP, Address: "192.0.2.2", Spec: catalog.TransportSpec{Port: 53}}
	provisional.Stats.Recommended = false
	qualified := result
	qualified.Target = catalog.Target{Resolver: profile, Protocol: catalog.DoH, Address: "192.0.2.3", Spec: catalog.TransportSpec{Port: 443}}
	qualified.Stats = benchmark.Statistics{Total: 20, Successes: 20, Scored: 20, Recommended: true, SuccessRate: 1, ScoreMS: 2}
	run = benchmark.Report{
		Seed: 42, SampleSize: 20, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{provisional, qualified},
		Rankings: []benchmark.Ranking{{Protocol: catalog.TCP, TargetID: provisional.Target.ID(), Rank: 1}, {Protocol: catalog.DoH, TargetID: qualified.Target.ID(), Rank: 1}},
	}
	output.Reset()
	if err := WriteTable(&output, run, false); err != nil {
		t.Fatal(err)
	}
	text = output.String()
	for _, expected := range []string{"Provisional winners", "PROVISIONAL", "RECOMMENDED", "QUALIFIED", "INELIGIBLE"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("status output missing %q: %s", expected, text)
		}
	}
}

func TestReportDoesNotInferUsableRateFromTransportSuccess(t *testing.T) {
	result := reportTarget("zero-usable", catalog.UDP, 0, false)
	result.Stats = benchmark.Statistics{Total: 2, Successes: 2, SuccessRate: 1, UsableRate: 0}
	var output bytes.Buffer
	if err := WriteTable(&output, benchmark.Report{Seed: 1, SampleSize: 2, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{result}}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "100.00%  100.00%") {
		t.Fatalf("report inferred usable rate from transport success: %s", output.String())
	}
	if !strings.Contains(output.String(), "100.00%  0.00%") {
		t.Fatalf("report omitted explicit zero usable rate: %s", output.String())
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

func TestPairedEffectsBelowMinimumSamplesAreNotComparable(t *testing.T) {
	first := reportTarget("first", catalog.UDP, 1, false)
	second := reportTarget("second", catalog.UDP, 1, false)
	reason := "insufficient paired samples (minimum 20)"
	run := benchmark.Report{
		Seed: 42, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{first, second},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: first.Target.ID(), Rank: 1}},
		PairedEffects: []benchmark.PairedEffect{
			{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: first.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 1, Reference: true},
			{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: second.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 1, Reason: reason},
		},
	}
	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	tableText := table.String()
	if !strings.Contains(tableText, "NOT COMPARABLE") {
		t.Fatalf("below-minimum paired row is not marked incomparable: %s", tableText)
	}
	if strings.Contains(tableText, "FASTER") || strings.Contains(tableText, "SLOWER") {
		t.Fatalf("below-minimum paired row rendered a directional verdict: %s", tableText)
	}

	// A stale delta or interval must never reach the table once benchmark has
	// recorded a reason for the effect.
	stale := benchmark.PairedEffect{Samples: 1, MedianDeltaMS: 83.42, CILowMS: 83.42, CIHighMS: 83.42, Reason: reason}
	if got := pairedInterpretation(stale, false); got != "NOT COMPARABLE" {
		t.Fatalf("below-minimum interpretation = %q", got)
	}
	if pairedDeltaText(stale) != "—" || pairedCIText(stale) != "—" {
		t.Fatalf("below-minimum formatting = %q/%q", pairedDeltaText(stale), pairedCIText(stale))
	}
	if strings.Contains(tableText, "83.42") {
		t.Fatalf("below-minimum paired row rendered a delta: %s", tableText)
	}
}

func TestPairedEffectsAreRenderedExportedAndRedacted(t *testing.T) {
	first := reportTarget("first", catalog.UDP, 2, true)
	second := reportTarget("second", catalog.UDP, 2, false)
	system := reportTarget("system-paired", catalog.UDP, 2, false)
	system.Target.Resolver.Name = "System DNS (scope: corp)"
	system.Target.Resolver.Owner = "local forwarding (interface: utun0)"
	system.Target.Address = "127.0.0.53"
	effects := []benchmark.PairedEffect{
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: second.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 2, MedianDeltaMS: 0, CILowMS: -1, CIHighMS: 1, Indistinguishable: true},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: first.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 2, Reference: true},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: system.Target.ID(), ReferenceTargetID: system.Target.ID(), Samples: 2, MedianDeltaMS: 2, CILowMS: 1, CIHighMS: 3},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: "missing-target", ReferenceTargetID: first.Target.ID(), Reason: "no shared scored samples"},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: second.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 1, MedianDeltaMS: -2, CILowMS: -2, CIHighMS: -2},
		{Protocol: catalog.TCP, Policy: "z-policy", TargetID: second.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 1, MedianDeltaMS: 1, CILowMS: 1, CIHighMS: 1},
		{Protocol: catalog.TCP, Policy: "a-policy", TargetID: first.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 1, Reference: true},
	}
	run := benchmark.Report{
		Seed: 42, SampleSize: 2, Queries: 2, QueryTypes: []uint16{1},
		Targets:       []benchmark.TargetResult{first, second, system},
		Rankings:      []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: first.Target.ID(), Rank: 1}, {Protocol: catalog.UDP, TargetID: second.Target.ID(), Rank: 2}},
		PairedEffects: effects,
	}

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{Color: true, RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	tableText := table.String()
	for _, expected := range []string{"Paired latency effects", "Median Δ", "NO CLEAR DIFFERENCE", "REFERENCE", "NOT COMPARABLE", "FASTER", "SLOWER", ansiYellow} {
		if !strings.Contains(tableText, expected) {
			t.Fatalf("paired table missing %q: %s", expected, tableText)
		}
	}
	if strings.Contains(tableText, system.Target.ID()) || !strings.Contains(tableText, "redacted") {
		t.Fatalf("paired table leaked system identity: %s", tableText)
	}
	if pairedEffectTargetText(run, "missing-target", true) != "—" {
		t.Fatalf("missing paired target label = %q", pairedEffectTargetText(run, "missing-target", true))
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSONWithOptions(&jsonOutput, run, false, JSONOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	jsonText := jsonOutput.String()
	for _, expected := range []string{"\"paired_effects\"", "\"reference_target_id\"", "\"indistinguishable\": true", "system-redacted-1@redacted/udp"} {
		if !strings.Contains(jsonText, expected) {
			t.Fatalf("paired JSON missing %q: %s", expected, jsonText)
		}
	}
	if strings.Contains(jsonText, system.Target.ID()) || strings.Contains(jsonText, "127.0.0.53") {
		t.Fatalf("paired JSON leaked system identity: %s", jsonText)
	}

	if pairedDeltaText(benchmark.PairedEffect{}) != "—" || pairedCIText(benchmark.PairedEffect{}) != "—" {
		t.Fatal("empty paired effect formatting did not use placeholders")
	}
	if got := pairedInterpretation(benchmark.PairedEffect{Reference: true}, false); got != "REFERENCE" {
		t.Fatalf("reference interpretation = %q", got)
	}
	if got := pairedInterpretation(benchmark.PairedEffect{}, false); got != "NOT COMPARABLE" {
		t.Fatalf("unavailable interpretation = %q", got)
	}
	if got := pairedInterpretation(benchmark.PairedEffect{Samples: 1, MedianDeltaMS: 0}, false); got != "NO CLEAR DIFFERENCE" {
		t.Fatalf("zero interpretation = %q", got)
	}
	if got := pairedInterpretation(benchmark.PairedEffect{Samples: 1, MedianDeltaMS: -1}, false); got != "FASTER" {
		t.Fatalf("faster interpretation = %q", got)
	}
	if got := pairedInterpretation(benchmark.PairedEffect{Samples: 1, MedianDeltaMS: 1}, false); got != "SLOWER" {
		t.Fatalf("slower interpretation = %q", got)
	}

	if err := writePairedEffects(contentFailWriter{needle: "Paired latency effects"}, run, TableOptions{}); err == nil {
		t.Fatal("paired heading writer failure was not returned")
	}
	if err := writePairedEffects(contentFailWriter{needle: "Protocol"}, run, TableOptions{}); err == nil {
		t.Fatal("paired table writer failure was not returned")
	}
	if err := WriteTableWithOptions(contentFailWriter{needle: "Paired latency effects"}, run, TableOptions{}); err == nil {
		t.Fatal("top-level paired effect writer failure was not returned")
	}
}

func TestProfileViewShowsTransportCostsConfidenceAndCorpusMetadata(t *testing.T) {
	profile := catalog.ResolverProfile{
		ID: "profile-a", Name: "Profile A", Owner: "Owner A", Policy: "unfiltered",
		Addresses: []string{"192.0.2.1"}, Transports: map[catalog.Protocol]catalog.TransportSpec{
			catalog.UDP: {Port: 53}, catalog.TCP: {Port: 53}, catalog.DoT: {Port: 853, ServerName: "dns.example"},
		},
	}
	other := catalog.ResolverProfile{ID: "profile-b", Name: "Profile B", Owner: "Owner B", Policy: "unfiltered", Addresses: []string{"192.0.2.2"}, Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.DoH: {URL: "https://dns.example/dns-query"}}}
	udp := reportTarget("profile-a", catalog.UDP, 2, true)
	udp.Target.Resolver = profile
	udp.Target.Address = "192.0.2.1"
	udp.Stats = benchmark.Statistics{Total: 2, Successes: 2, Scored: 2, SuccessRate: 1, MedianMS: 3, P95MS: 4, ColdMedianMS: 5, ScoreMS: 3.4, CILowMS: 2, CIHighMS: 5, Recommended: true}
	dot := udp
	dot.Target.Protocol = catalog.DoT
	dot.Stats = benchmark.Statistics{Total: 2, Successes: 2, Scored: 2, SuccessRate: 1, MedianMS: 8, P95MS: 9, ColdMedianMS: 12, ScoreMS: 8.4, CILowMS: 7, CIHighMS: 10}
	system := udp
	system.Target.Resolver = catalog.ResolverProfile{ID: "system-profile", Name: "System DNS (scope: corp)", Owner: "local forwarding (interface: utun0)", Policy: "local", Addresses: []string{"127.0.0.53"}, Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}}}
	system.Target.Address = "127.0.0.53"
	system.Target.Protocol = catalog.UDP
	run := benchmark.Report{
		Seed: 42, CorpusMode: benchmark.CorpusCacheMiss, CorpusZone: "example.com", CorpusNonce: "0123456789abcdef",
		SampleSize: 2, Queries: 2, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{udp, dot, system},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: udp.Target.ID(), Rank: 1}, {Protocol: catalog.DoT, TargetID: dot.Target.ID(), Rank: 1}},
	}
	options := TableOptions{Color: true, ProfileView: true, RedactSystem: true, Profiles: []catalog.ResolverProfile{profile, other, system.Target.Resolver}, Protocols: []catalog.Protocol{catalog.UDP, catalog.TCP, catalog.DoT}}
	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, options); err != nil {
		t.Fatal(err)
	}
	tableText := table.String()
	for _, expected := range []string{"Corpus: cache-miss", "0123456789abcdef", "Profile-level transport view", "Score 95% CI", "Profile A", "NOT MEASURED", "System DNS (redacted)", ansiYellow} {
		if !strings.Contains(tableText, expected) {
			t.Fatalf("profile table missing %q: %s", expected, tableText)
		}
	}
	if strings.Contains(tableText, "127.0.0.53") || strings.Contains(tableText, "system-profile") {
		t.Fatalf("profile table leaked system identity: %s", tableText)
	}
	if placeholderText("") != "—" || placeholderText("zone") != "zone" || profileScoreCIText(benchmark.Statistics{}) != "—" || profileScoreCIText(benchmark.Statistics{Scored: 1, CILowMS: 1, CIHighMS: 2}) != "[1.00, 2.00] ms" {
		t.Fatal("profile placeholder/CI formatting mismatch")
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSONWithOptions(&jsonOutput, run, false, JSONOptions{ProfileView: true, RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	jsonText := jsonOutput.String()
	for _, expected := range []string{"\"corpus_mode\": \"cache-miss\"", "\"corpus_zone\": \"example.com\"", "\"corpus_nonce\": \"0123456789abcdef\"", "\"profile_comparisons\"", "\"transports\"", "\"score_ms\": 3.4", "system-redacted-1@redacted/udp"} {
		if !strings.Contains(jsonText, expected) {
			t.Fatalf("profile JSON missing %q: %s", expected, jsonText)
		}
	}
	if strings.Contains(jsonText, "127.0.0.53") || strings.Contains(jsonText, "system-profile") {
		t.Fatalf("profile JSON leaked system identity: %s", jsonText)
	}
	if len(profileComparisonsForJSON(benchmark.Report{}, nil)) != 0 || len(profileViewRows(benchmark.Report{}, TableOptions{})) != 0 {
		t.Fatal("empty profile views were not empty")
	}
	if plain := profileComparisonsForJSON(run, nil); len(plain) != 2 || plain[0].ID == "system-redacted" {
		t.Fatalf("plain profile comparisons = %#v", plain)
	}
	sameProfileOtherAddress := udp.Target
	sameProfileOtherAddress.Address = "192.0.2.9"
	keys := sortedProfileGroupKeys(map[string]profileGroup{
		"one": {Target: udp.Target}, "two": {Target: sameProfileOtherAddress},
	})
	if len(keys) != 2 {
		t.Fatalf("same-profile address sort = %#v", keys)
	}

	if err := writeProfileView(contentFailWriter{needle: "Profile-level transport view"}, run, options); err == nil {
		t.Fatal("profile view heading writer failure was not returned")
	}
	if err := writeProfileView(contentFailWriter{needle: "Profile"}, run, options); err == nil {
		t.Fatal("profile view table writer failure was not returned")
	}
	if err := writeProfileView(&bytes.Buffer{}, benchmark.Report{}, TableOptions{}); err != nil {
		t.Fatalf("empty profile view = %v", err)
	}
	if err := WriteTableWithOptions(contentFailWriter{needle: "Profile-level transport view"}, run, options); err == nil {
		t.Fatal("top-level profile view writer failure was not returned")
	}
	if err := WriteTableWithOptions(contentFailWriter{needle: "Corpus: cache-miss"}, run, options); err == nil {
		t.Fatal("corpus metadata writer failure was not returned")
	}
}
