package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
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

func TestJSONIncludesAndRedactsRunProvenance(t *testing.T) {
	run := benchmark.Report{
		StartedAt: time.Unix(10, 0), FinishedAt: time.Unix(12, 500000000),
		Provenance: &benchmark.RunProvenance{
			Version: "v0.1.0-alpha.33", Commit: "abc123", BuildDate: "2026-08-20",
			OS: "linux", Architecture: "amd64", Interfaces: []string{"enp1s0", "lo"},
			Protocols: []catalog.Protocol{catalog.UDP, catalog.DoH}, CorpusEntries: 2,
			CorpusSHA256: "ace801686b06c8b2d759d4bad10d00af484d636b25b373c59002031e8c4e1504",
			Timeout:      time.Second, Concurrency: 4,
		},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, run, false); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"\"speedns_version\": \"v0.1.0-alpha.33\"", "\"architecture\": \"amd64\"", "\"corpus_entries\": 2", "\"timeout_ms\": 1000", "\"duration_ms\": 2500", "enp1s0"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("provenance JSON missing %q: %s", expected, text)
		}
	}
	output.Reset()
	if err := WriteJSONWithOptions(&output, run, false, JSONOptions{RedactSystem: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "enp1s0") || !strings.Contains(output.String(), "\"interfaces\"") || !strings.Contains(output.String(), "\"redacted\"") {
		t.Fatalf("redacted provenance JSON = %s", output.String())
	}
}

// TestLocalResolverIsReportedAsNotComparable checks that every output surface
// keeps the local stub's measurement while saying, in the same place, that the
// number cannot be compared with a network resolver.
func TestLocalResolverIsReportedAsNotComparable(t *testing.T) {
	stub := reportTarget("53", catalog.UDP, 2, false)
	stub.Target.Resolver.ID = "system-stub-127-0-0-53"
	stub.Target.Resolver.Name = "System DNS stub"
	stub.Target.Resolver.Owner = "local stub/forwarder"
	stub.Target.Resolver.Policy = "local forwarding (upstream unknown)"
	stub.Target.Resolver.Local = true
	stub.Target.Address = "127.0.0.53"
	stub.Stats.MedianMS = 0.2
	network := reportTarget("1", catalog.UDP, 2, true)

	run := benchmark.Report{
		StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0), Seed: 5, SampleSize: 1, Queries: 1,
		QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{stub, network},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: network.Target.ID(), Rank: 1}},
	}

	if status := resultStatus(stub); status != "NOT COMPARABLE" {
		t.Fatalf("local stub status = %q", status)
	}
	if status := resultStatus(network); status != "QUALIFIED" {
		t.Fatalf("network resolver status = %q", status)
	}
	if rank := rankText(run, stub.Target.ID()); rank != "—" {
		t.Fatalf("local stub rank = %q, want no rank", rank)
	}

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := table.String()
	if !strings.Contains(text, "NOT COMPARABLE") || !strings.Contains(text, "0.20 ms") {
		t.Fatalf("table hid the local stub measurement or caveat: %s", text)
	}
	if !strings.Contains(text, "cache-hit latency excludes the upstream cost") {
		t.Fatalf("table warnings missing the non-comparability reason: %s", text)
	}
	recommended, ok := recommendedResult(run, catalog.UDP)
	if !ok || recommended.Target.ID() != network.Target.ID() {
		t.Fatalf("recommendation = %#v/%v", recommended.Target, ok)
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, run, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonOutput.String(), "\"local\": true") {
		t.Fatalf("JSON target missing the local flag: %s", jsonOutput.String())
	}
	if strings.Count(jsonOutput.String(), "\"local\":") != 1 {
		t.Fatalf("network target should omit the local flag: %s", jsonOutput.String())
	}

	var csvOutput bytes.Buffer
	if err := WriteCSV(&csvOutput, run); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(csvOutput.String()), "\n")
	if len(rows) != 3 || !strings.HasSuffix(rows[0], ",local") {
		t.Fatalf("CSV header missing the local column: %s", csvOutput.String())
	}
	if !strings.HasSuffix(rows[1], ",true") || !strings.HasSuffix(rows[2], ",false") {
		t.Fatalf("CSV local column = %#v", rows[1:])
	}
}

func TestDurationMillisecondsRejectsInvalidRanges(t *testing.T) {
	if got := durationMilliseconds(time.Time{}, time.Now()); got != 0 {
		t.Fatalf("zero start duration = %v, want zero", got)
	}
	if got := durationMilliseconds(time.Unix(2, 0), time.Unix(1, 0)); got != 0 {
		t.Fatalf("reverse duration = %v, want zero", got)
	}
}

func lineContaining(t *testing.T, text string, needle string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no line containing %q in:\n%s", needle, text)
	return ""
}

func tieTableReport() benchmark.Report {
	leader := reportTarget("tie-leader", catalog.UDP, 25, true)
	leader.Stats.Tie = true
	challenger := reportTarget("tie-challenger", catalog.UDP, 25, true)
	challenger.Stats.Tie = true
	distinct := reportTarget("distinct", catalog.TCP, 25, true)
	return benchmark.Report{
		Seed: 42, SampleSize: 2, Queries: 2, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{leader, challenger, distinct},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.UDP, TargetID: leader.Target.ID(), Rank: 1, Tie: true},
			{Protocol: catalog.UDP, TargetID: challenger.Target.ID(), Rank: 2, Tie: true},
			{Protocol: catalog.TCP, TargetID: distinct.Target.ID(), Rank: 1},
		},
	}
}

func TestTableSurfacesConfidenceIntervalTies(t *testing.T) {
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, tieTableReport(), TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(lineContaining(t, text, "Rank"), "Tie") {
		t.Fatalf("comparison header lost the Tie column:\n%s", text)
	}
	if recommendation := lineContaining(t, text, "RECOMMENDED"); !strings.Contains(recommendation, "TIED") {
		t.Fatalf("tied recommended winner is presented as unqualified: %q", recommendation)
	}
	if !strings.Contains(text, "TIED: the 95% score confidence interval overlaps another ranked target") {
		t.Fatalf("tie explanation missing from recommendation block:\n%s", text)
	}
	for _, owner := range []string{"Owner tie-leader", "Owner tie-challenger"} {
		if row := lineContaining(t, text, owner); !strings.Contains(row, "TIED") {
			t.Fatalf("comparison row for %s hides the tie: %q", owner, row)
		}
	}
	if row := lineContaining(t, text, "Owner distinct"); strings.Contains(row, "TIED") {
		t.Fatalf("untied target marked as tied: %q", row)
	}
}

func TestTableTieMarkerIsColoredAndOmittedWhenAbsent(t *testing.T) {
	var colored bytes.Buffer
	if err := WriteTableWithOptions(&colored, tieTableReport(), TableOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colored.String(), ansiYellow+"TIED"+ansiReset) {
		t.Fatalf("TIED rendered without color emphasis:\n%s", colored.String())
	}

	untied := tieTableReport()
	for index := range untied.Targets {
		untied.Targets[index].Stats.Tie = false
	}
	for index := range untied.Rankings {
		untied.Rankings[index].Tie = false
	}
	var plain bytes.Buffer
	if err := WriteTableWithOptions(&plain, untied, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "TIED") {
		t.Fatalf("untied report claims a tie:\n%s", plain.String())
	}
}

func TestTableFlagsTiedProvisionalWinnerAndPropagatesNoteError(t *testing.T) {
	provisional := reportTarget("tie-provisional", catalog.UDP, 1, false)
	provisional.Stats.Tie = true
	run := benchmark.Report{
		Seed: 42, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{provisional},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: provisional.Target.ID(), Rank: 1, Tie: true}},
	}
	var output bytes.Buffer
	if err := WriteTableWithOptions(&output, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	if provisionalRow := lineContaining(t, output.String(), "PROVISIONAL"); !strings.Contains(provisionalRow, "TIED") {
		t.Fatalf("tied provisional winner hides the tie: %q", provisionalRow)
	}
	if !strings.Contains(output.String(), "TIED: the 95% score confidence interval") {
		t.Fatalf("tie explanation missing for provisional winner:\n%s", output.String())
	}
	if err := WriteTableWithOptions(contentFailWriter{needle: "TIED: the"}, run, TableOptions{}); err == nil {
		t.Fatal("tie note write failure was not returned")
	}
}
