package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/textwidth"
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

func TestDurationMillisecondsRejectsInvalidRanges(t *testing.T) {
	if got := durationMilliseconds(time.Time{}, time.Now()); got != 0 {
		t.Fatalf("zero start duration = %v, want zero", got)
	}
	if got := durationMilliseconds(time.Unix(2, 0), time.Unix(1, 0)); got != 0 {
		t.Fatalf("reverse duration = %v, want zero", got)
	}
}

// Columns are padded by terminal cells, so every column following a wide, a
// fullwidth or a combining-mark owner name must still start at one offset.
func TestAlignedTableAlignsByDisplayWidth(t *testing.T) {
	headers := []string{"Owner", "Address", "Status"}
	rows := [][]string{
		{"東京", "192.0.2.1", "QUALIFIED"},
		{"ＡＢＣ", "192.0.2.2", "FAILED"},
		{"e\u0301clair", "192.0.2.3", "INELIGIBLE"},
		{"plain-ascii", "192.0.2.4", "QUALIFIED"},
	}
	var output bytes.Buffer
	if err := writeAlignedTable(&output, headers, rows); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != len(rows)+1 {
		t.Fatalf("table lines = %d, want %d: %q", len(lines), len(rows)+1, output.String())
	}
	offset := -1
	for _, line := range lines {
		column := strings.Index(line, "192.0.2.")
		if column < 0 {
			column = strings.Index(line, "Address")
		}
		cells := textwidth.Display(line[:column])
		if offset < 0 {
			offset = cells
		}
		if cells != offset {
			t.Fatalf("address column starts at cell %d, want %d: %q", cells, offset, line)
		}
		if strings.HasSuffix(line, " ") {
			t.Fatalf("trailing column was padded: %q", line)
		}
	}
	// "plain-ascii" is the widest owner at eleven cells, so the two-cell
	// margin plus the owner plus two padding cells start addresses at cell 15.
	if offset != 15 {
		t.Fatalf("address column offset = %d, want 15", offset)
	}
}

// styledStatus cells carry zero-width ANSI codes; they must not widen a column.
func TestAlignedTableIgnoresColourCodesInWidths(t *testing.T) {
	var plain, coloured bytes.Buffer
	headers := []string{"Status", "Owner", "Note"}
	if err := writeAlignedTable(&plain, headers, [][]string{{styledStatus("FAILED", false), "owner", "note"}}); err != nil {
		t.Fatal(err)
	}
	if err := writeAlignedTable(&coloured, headers, [][]string{{styledStatus("FAILED", true), "owner", "note"}}); err != nil {
		t.Fatal(err)
	}
	stripped := strings.ReplaceAll(coloured.String(), ansiRed, "")
	stripped = strings.ReplaceAll(stripped, ansiReset, "")
	if stripped != plain.String() {
		t.Fatalf("coloured table = %q, want %q once the codes are removed", stripped, plain.String())
	}
}
