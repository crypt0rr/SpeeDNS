package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	internalreport "github.com/crypt0rr/SpeeDNS/internal/report"
	"github.com/crypt0rr/SpeeDNS/report"
	"github.com/crypt0rr/SpeeDNS/schema"
)

// publicTypes lists every document type in the public contract together with
// the schema definition that describes it. The root report is keyed by "$".
var publicTypes = map[string]any{
	"$":                    report.Report{},
	"run":                  report.Run{},
	"provenance":           report.Provenance{},
	"target":               report.Target{},
	"statistics":           report.Statistics{},
	"result":               report.Result{},
	"observation":          report.Observation{},
	"cold_observation":     report.ColdObservation{},
	"ranking":              report.Ranking{},
	"paired_effect":        report.PairedEffect{},
	"divergence":           report.DivergenceDetail{},
	"divergence_exclusion": report.DivergenceExclusion{},
	"profile_transport":    report.ProfileTransport{},
	"profile_comparison":   report.ProfileComparison{},
}

// freeFormObjectKeys hold caller-supplied map keys rather than contract keys.
var freeFormObjectKeys = map[string]bool{"rcode_counts": true, "classes": true}

// exhaustiveReport populates every optional field of the report document so
// that the emitted JSON exercises the whole contract.
func exhaustiveReport() benchmark.Report {
	stats := benchmark.Statistics{
		Total: 2, Successes: 2, Failures: 1, UsableResponses: 2, ResolverFailures: 1, Scored: 2,
		Divergent: 1, Truncated: 1, Reconnects: 1, SuccessRate: 1, FailureRate: 0.5, UsableRate: 1,
		ResolverFailureRate: 0.5, ScoringFailureRate: 0.25, RCodeCounts: map[string]int{"NXDOMAIN": 1},
		MedianMS: 2, P95MS: 3, MinMS: 1, MaxMS: 4, MADMS: 0.5, ColdMedianMS: 5, ScoreMS: 2.4,
		CILowMS: 1, CIHighMS: 4, Recommended: true, Tie: true,
	}
	udp := benchmark.TargetResult{
		Target: catalog.Target{
			Resolver: catalog.ResolverProfile{ID: "1", Name: "Resolver 1", Owner: "Owner 1", Policy: "unfiltered"},
			Protocol: catalog.UDP, Address: "192.0.2.1",
		},
		Stats:       stats,
		DialAddress: "192.0.2.1:53",
		Observations: []benchmark.Observation{{
			Name: "example.com", QType: 1, LatencyMS: 2, Success: true, Usable: true, RCode: 3,
			Truncated: true, ResponseClass: "answer", Divergent: true, DivergenceBaseline: "answer",
			Reconnected: true, Error: "sample error",
		}},
		Cold: []benchmark.ColdObservation{{
			Name: "example.com", QType: 1, LatencyMS: 5, Success: true, Error: "cold error",
		}},
	}
	doh := benchmark.TargetResult{
		Target: catalog.Target{
			Resolver: catalog.ResolverProfile{ID: "1", Name: "Resolver 1", Owner: "Owner 1", Policy: "unfiltered"},
			Protocol: catalog.DoH, Address: "192.0.2.1",
			Spec: catalog.TransportSpec{
				URL: "https://resolver.example/dns-query", ServerName: "resolver.example",
				BootstrapAddresses: []string{"192.0.2.53"},
			},
		},
		Stats: stats, OpenError: "open failed", Incomplete: true, DialAddress: "192.0.2.53:443",
	}
	return benchmark.Report{
		StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0), Seed: 42,
		CorpusMode: "static", CorpusZone: "example.invalid", CorpusNonce: "abc123",
		SampleSize: 2, Queries: 4, QueryTypes: []uint16{1, 28},
		Targets: []benchmark.TargetResult{udp, doh},
		Provenance: &benchmark.RunProvenance{
			Version: "dev", Commit: "unknown", BuildDate: "unknown", OS: "linux", Architecture: "amd64",
			Interfaces: []string{"lo"}, Protocols: []catalog.Protocol{catalog.UDP, catalog.DoH},
			CorpusEntries: 2, CorpusSHA256: strings.Repeat("0", 64), Timeout: time.Second, Concurrency: 1,
		},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: udp.Target.ID(), Rank: 1, Tie: true}},
		PairedEffects: []benchmark.PairedEffect{{
			Protocol: catalog.UDP, Policy: "unfiltered", TargetID: udp.Target.ID(),
			ReferenceTargetID: udp.Target.ID(), Samples: 2, MedianDeltaMS: 0.5, CILowMS: -1, CIHighMS: 1,
			Indistinguishable: true, Reference: true, Reason: "reference target",
		}},
		Divergence: []benchmark.DivergenceDetail{{
			Name: "example.com", QType: 1, Policy: "unfiltered", Compared: 2, Baseline: "answer",
			Ambiguous: true, Classes: map[string]int{"answer": 2},
			Excluded: []benchmark.DivergenceExclusion{{
				TargetID: udp.Target.ID(), ResponseClass: "nxdomain", Treatment: "excluded",
			}},
		}},
		Warnings: []string{"example warning"},
	}
}

func exhaustiveJSON(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	options := internalreport.JSONOptions{ProfileView: true}
	if err := internalreport.WriteJSONWithOptions(&output, exhaustiveReport(), true, options); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func documentKeys(t *testing.T, value any, keys map[string]bool) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			keys[key] = true
			if !freeFormObjectKeys[key] {
				documentKeys(t, nested, keys)
			}
		}
	case []any:
		for _, nested := range typed {
			documentKeys(t, nested, keys)
		}
	}
}

func typeKeys(structure any) map[string]bool {
	keys := make(map[string]bool)
	value := reflect.TypeOf(structure)
	for index := 0; index < value.NumField(); index++ {
		name, _, _ := strings.Cut(value.Field(index).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// difference returns the keys of left that right does not contain.
func difference(left, right map[string]bool) []string {
	var names []string
	for name := range left {
		if !right[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// compareKeys fails with the exact keys that only one side declares.
func compareKeys(t *testing.T, source string, contract, public map[string]bool) {
	t.Helper()
	if extra := difference(contract, public); len(extra) > 0 {
		t.Fatalf("%s has keys the public types do not carry: %v", source, extra)
	}
	if extra := difference(public, contract); len(extra) > 0 {
		t.Fatalf("the public types have fields %s does not contain: %v", source, extra)
	}
}

// TestPublicTypesDecodeEveryEmittedField is the drift gate. It fails when the
// encoder emits a key the public types do not carry, when a public field is
// never emitted, or when decoding through the public types loses a value.
func TestPublicTypesDecodeEveryEmittedField(t *testing.T) {
	emitted := exhaustiveJSON(t)

	decoder := json.NewDecoder(bytes.NewReader(emitted))
	decoder.DisallowUnknownFields()
	var document report.Report
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("emitted report does not fit the public types: %v", err)
	}

	reencoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var before, after any
	for _, pair := range []struct {
		data   []byte
		target *any
	}{{emitted, &before}, {reencoded, &after}} {
		reader := json.NewDecoder(bytes.NewReader(pair.data))
		reader.UseNumber()
		if err := reader.Decode(pair.target); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("decoding through the public types changed the document:\nbefore: %s\nafter:  %s", emitted, reencoded)
	}

	emittedKeys := make(map[string]bool)
	documentKeys(t, before, emittedKeys)
	declaredKeys := make(map[string]bool)
	for _, structure := range publicTypes {
		for key := range typeKeys(structure) {
			declaredKeys[key] = true
		}
	}
	compareKeys(t, "the encoder output", emittedKeys, declaredKeys)
}

// TestPublicTypesMatchPublishedSchema keeps the public types in step with
// schema/report-v1.json, which is the published form of the same contract.
func TestPublicTypesMatchPublishedSchema(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(schema.ReportV1(), &document); err != nil {
		t.Fatal(err)
	}
	definitions, ok := document["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema has no $defs object")
	}
	sections := map[string]any{"$": document}
	for name, definition := range definitions {
		sections[name] = definition
	}
	for name, section := range sections {
		if name == "protocol" {
			continue
		}
		structure, ok := publicTypes[name]
		if !ok {
			t.Fatalf("schema definition %q has no public type", name)
		}
		properties, ok := section.(map[string]any)["properties"].(map[string]any)
		if !ok {
			t.Fatalf("schema definition %q has no properties", name)
		}
		schemaKeys := make(map[string]bool, len(properties))
		for key := range properties {
			schemaKeys[key] = true
		}
		compareKeys(t, "schema definition "+strconv.Quote(name), schemaKeys, typeKeys(structure))
	}
	protocols := definitions["protocol"].(map[string]any)["enum"].([]any)
	want := []report.Protocol{report.UDP, report.TCP, report.DoH, report.DoT, report.DoQ}
	if len(protocols) != len(want) {
		t.Fatalf("schema protocol enum %v does not match %v", protocols, want)
	}
	for index, value := range protocols {
		if value != want[index].String() {
			t.Fatalf("schema protocol %v does not match %v", value, want[index])
		}
	}
}

func TestDecodeGoldenReport(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "internal", "report", "testdata", "golden", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := report.Parse(golden)
	if err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != report.SchemaVersion || len(document.Results) == 0 {
		t.Fatalf("unexpected golden report: %+v", document.Run)
	}
	slowest := 0.0
	for _, result := range document.Results {
		if result.Target.Protocol != report.TCP && result.Target.Protocol != report.UDP {
			t.Fatalf("unexpected protocol %q", result.Target.Protocol)
		}
		if result.Stats.MedianMS > slowest {
			slowest = result.Stats.MedianMS
		}
	}
	if slowest <= 0 {
		t.Fatalf("golden report has no measured median: %+v", document.Results)
	}
	if len(document.Rankings) == 0 || document.Rankings[0].Rank != 1 {
		t.Fatalf("unexpected rankings: %+v", document.Rankings)
	}
}

func TestDecodeRejectsOtherSchemaVersions(t *testing.T) {
	if _, err := report.Parse([]byte(`{"schema_version": 2}`)); !errors.Is(err, report.ErrUnsupportedSchemaVersion) {
		t.Fatalf("schema version error = %v", err)
	}
	if _, err := report.Parse([]byte(`{`)); err == nil || errors.Is(err, report.ErrUnsupportedSchemaVersion) {
		t.Fatalf("malformed report error = %v", err)
	}
}

func TestDecodeIgnoresAdditiveFields(t *testing.T) {
	document, err := report.Decode(strings.NewReader(
		`{"schema_version": 1, "run": {"seed": 7}, "results": [], "rankings": [], "future_key": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if document.Run.Seed != 7 {
		t.Fatalf("unexpected run: %+v", document.Run)
	}
}
