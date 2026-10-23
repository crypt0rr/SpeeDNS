package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// writeJSONAsOneValue is how the JSON report used to be written, and the
// reference the streamed writer must reproduce byte for byte: the whole
// document built as one JSONReport value and encoded by one json.Encoder
// indenting by two spaces.
func writeJSONAsOneValue(writer io.Writer, run benchmark.Report, raw bool, options JSONOptions) error {
	redactedIDs := redactedTargetIDs(run, options.RedactSystem)
	document := jsonEnvelope(run, options, redactedIDs)
	document.Results = make([]JSONResult, 0, len(run.Targets))
	for _, result := range run.Targets {
		document.Results = append(document.Results, jsonResultFor(result, raw, options, redactedIDs))
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func encodedJSON(run benchmark.Report, raw bool, options JSONOptions) ([]byte, error) {
	var output bytes.Buffer
	err := writeJSONAsOneValue(&output, run, raw, options)
	return output.Bytes(), err
}

func requireStreamedJSONMatches(t *testing.T, name string, run benchmark.Report, raw bool, options JSONOptions) {
	t.Helper()
	want, err := encodedJSON(run, raw, options)
	if err != nil {
		t.Fatalf("%s: reference encoding failed: %v", name, err)
	}
	var got bytes.Buffer
	if err := WriteJSONWithOptions(&got, run, raw, options); err != nil {
		t.Fatalf("%s: streamed encoding failed: %v", name, err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		index := 0
		for index < len(want) && index < got.Len() && want[index] == got.Bytes()[index] {
			index++
		}
		start := max(0, index-80)
		t.Fatalf("%s: streamed JSON differs from the encoder at byte %d of %d/%d:\nwant ...%q\ngot  ...%q",
			name, index, len(want), got.Len(), want[start:min(len(want), index+80)], got.Bytes()[start:min(got.Len(), index+80)])
	}
}

// TestJSONReportMembersMatchTheStreamer pins JSONReport's top-level members,
// in order and with their omission rules, to the ones WriteJSONWithOptions
// writes by hand. Without it a new optional member that jsonEnvelope sets from
// a new benchmark.Report field would be dropped from every report while the
// equivalence tests pass, because their reports never fill it and the
// reference encoder omits it too. When this fails, teach the streamer the new
// member in the same position and with the same rule, then update the list.
func TestJSONReportMembersMatchTheStreamer(t *testing.T) {
	want := []string{
		"schema_version",
		"run",
		"results",
		"rankings",
		"paired_effects,omitempty",
		"profile_comparisons,omitempty",
		"divergence,omitempty",
		"warnings,omitempty",
	}
	reportType := reflect.TypeOf(JSONReport{})
	got := make([]string, 0, reportType.NumField())
	for index := 0; index < reportType.NumField(); index++ {
		got = append(got, reportType.Field(index).Tag.Get("json"))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("JSONReport members = %q, want the %q WriteJSONWithOptions streams", got, want)
	}
}

// TestStreamedJSONMatchesTheEncoderOnFixtures covers the fixture reports the
// rest of the suite renders, under every option combination, plus an empty
// report: its results and rankings are written as empty arrays, never null,
// because the streamer writes results itself and jsonEnvelope always builds a
// non-nil rankings slice, and every optional top-level member is omitted.
func TestStreamedJSONMatchesTheEncoderOnFixtures(t *testing.T) {
	fixtures := map[string]benchmark.Report{
		"golden":   goldenReport(),
		"complete": completeReport(),
		"hostile":  hostileReport(),
		"dnssec":   dnssecReport(),
		"empty":    {},
	}
	for name, run := range fixtures {
		for _, raw := range []bool{false, true} {
			for _, options := range []JSONOptions{{}, {RedactSystem: true}, {ProfileView: true}, {RedactSystem: true, ProfileView: true}} {
				requireStreamedJSONMatches(t, fmt.Sprintf("%s raw=%v %+v", name, raw, options), run, raw, options)
			}
		}
	}
}

// jsonFuzzText returns short strings that exercise every escaping rule the
// encoder applies: HTML characters, quotes and backslashes, control
// characters, U+2028/U+2029, invalid UTF-8, and plain text.
func jsonFuzzText(rng *rand.Rand) string {
	pieces := []string{"", "a", "resolver", "<b>", "&amp;", `"quoted"`, `back\slash`, "\x00", "\x1b[31m", "\t\n",
		"\u2028", "\u2029", "\u202e", "é", "日本", "\xff", "dns.example", "1.1.1.1", "2001:db8::1"}
	var builder strings.Builder
	for count := rng.Intn(4); count > 0; count-- {
		builder.WriteString(pieces[rng.Intn(len(pieces))])
	}
	return builder.String()
}

func jsonFuzzFloat(rng *rand.Rand) float64 {
	switch rng.Intn(6) {
	case 0:
		return 0
	case 1:
		return float64(rng.Intn(5000))
	case 2:
		return rng.Float64() * 1e-7
	case 3:
		return rng.ExpFloat64() * 1e22
	default:
		return rng.ExpFloat64() * 40
	}
}

func jsonFuzzTarget(rng *rand.Rand, index int) catalog.Target {
	protocols := []catalog.Protocol{catalog.UDP, catalog.TCP, catalog.DoH, catalog.DoT, catalog.DoQ}
	id := fmt.Sprintf("fuzz-%d%s", index, jsonFuzzText(rng))
	if rng.Intn(4) == 0 {
		id = fmt.Sprintf("system-%d", index)
	}
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{
			ID: id, Name: jsonFuzzText(rng), Owner: jsonFuzzText(rng), Policy: jsonFuzzText(rng),
			Local: rng.Intn(5) == 0,
		},
		Protocol: protocols[rng.Intn(len(protocols))],
		Address:  fmt.Sprintf("192.0.2.%d", index%250),
		Spec:     catalog.TransportSpec{Port: 53 + rng.Intn(1000), ServerName: jsonFuzzText(rng)},
	}
	if target.Protocol == catalog.DoH {
		target.Spec.URL = "https://dns.example/dns-query?" + jsonFuzzText(rng)
	}
	if rng.Intn(3) == 0 {
		target.Spec.BootstrapAddresses = []string{"192.0.2.53", jsonFuzzText(rng)}
	}
	return target
}

func jsonFuzzStats(rng *rand.Rand) benchmark.Statistics {
	stats := benchmark.Statistics{
		Total: rng.Intn(4000), Successes: rng.Intn(4000), Failures: rng.Intn(10), Scored: rng.Intn(4000),
		SuccessRate: rng.Float64(), UsableRate: rng.Float64(), MedianMS: jsonFuzzFloat(rng), P95MS: jsonFuzzFloat(rng),
		MinMS: jsonFuzzFloat(rng), MaxMS: jsonFuzzFloat(rng), MADMS: jsonFuzzFloat(rng), ColdMedianMS: jsonFuzzFloat(rng),
		ScoreMS: jsonFuzzFloat(rng), CILowMS: jsonFuzzFloat(rng), CIHighMS: jsonFuzzFloat(rng),
		Recommended: rng.Intn(2) == 0, Tie: rng.Intn(2) == 0, Answers: rng.Intn(100), AnswerRate: rng.Float64(),
	}
	if rng.Intn(2) == 0 {
		stats.RCodeCounts = map[string]int{"NOERROR": rng.Intn(100), "SERVFAIL": rng.Intn(3), jsonFuzzText(rng): 1}
	}
	return stats
}

func jsonFuzzResult(rng *rand.Rand, index, observations int) benchmark.TargetResult {
	result := benchmark.TargetResult{
		Target: jsonFuzzTarget(rng, index), Stats: jsonFuzzStats(rng), Incomplete: rng.Intn(4) == 0,
		DialAddress: []string{"", "192.0.2.1:53", jsonFuzzText(rng)}[rng.Intn(3)],
	}
	if rng.Intn(3) == 0 {
		result.OpenError = "x509: certificate is valid for " + jsonFuzzText(rng)
	}
	for count := 0; count < observations; count++ {
		result.Observations = append(result.Observations, benchmark.Observation{
			Name: fmt.Sprintf("name-%d.example", count), QType: uint16(1 + rng.Intn(64)), LatencyMS: jsonFuzzFloat(rng),
			Success: rng.Intn(9) != 0, Usable: rng.Intn(9) != 0, RCode: rng.Intn(3), Truncated: rng.Intn(50) == 0,
			AuthenticatedData: rng.Intn(2) == 0, ResponseClass: []string{"", "answer", "nodata", "nxdomain", "rcode-2"}[rng.Intn(5)],
			Divergent: rng.Intn(20) == 0, DivergenceBaseline: []string{"", "answer", "ambiguous"}[rng.Intn(3)],
			Reconnected: rng.Intn(40) == 0, Error: []string{"", "i/o timeout", jsonFuzzText(rng)}[rng.Intn(3)],
		})
	}
	for count := rng.Intn(4); count > 0; count-- {
		result.Cold = append(result.Cold, benchmark.ColdObservation{
			Name: "example.com", QType: 1, LatencyMS: jsonFuzzFloat(rng), Success: rng.Intn(2) == 0, Error: jsonFuzzText(rng),
		})
	}
	if rng.Intn(3) == 0 {
		result.DNSSEC = &benchmark.DNSSECAssessment{Verdict: "validating", Reason: jsonFuzzText(rng), Probes: []benchmark.DNSSECProbe{
			{Role: "signed", Name: "good-a.test.dnssec-tools.org", QType: 1, LatencyMS: jsonFuzzFloat(rng), Success: true, Answers: 1, AuthenticatedData: true},
			{Role: "bogus", Name: "dnssec-failed.org", QType: 1, RCode: 2, ResponseCode: "SERVFAIL", Error: jsonFuzzText(rng)},
		}}
	}
	return result
}

// jsonFuzzReport builds a report whose every optional section is present or
// absent at random, so each member's omission rule is exercised both ways.
func jsonFuzzReport(rng *rand.Rand, targets, observations int) benchmark.Report {
	started := time.Date(2026, 10, 23, 9, rng.Intn(60), rng.Intn(60), rng.Intn(1e9), time.UTC)
	run := benchmark.Report{
		StartedAt: started, FinishedAt: started.Add(time.Duration(rng.Int63n(int64(time.Hour)))),
		Seed: rng.Int63() - rng.Int63(), SampleSize: rng.Intn(1000), Queries: rng.Intn(2000),
		CorpusMode: []string{"", benchmark.CorpusWarmCache, benchmark.CorpusCacheMiss}[rng.Intn(3)],
		CorpusZone: jsonFuzzText(rng), CorpusNonce: jsonFuzzText(rng),
	}
	if rng.Intn(2) == 0 {
		run.QueryTypes = []uint16{1, 28}
	}
	if rng.Intn(3) != 0 {
		run.Provenance = &benchmark.RunProvenance{
			Version: "v0.7.0", Commit: jsonFuzzText(rng), BuildDate: "2026-10-23", OS: "linux", Architecture: "amd64",
			Interfaces: []string{"eth0", jsonFuzzText(rng)}, Protocols: []catalog.Protocol{catalog.UDP, catalog.DoH},
			CorpusEntries: rng.Intn(1e6), CorpusSHA256: "800d075a", Timeout: 2 * time.Second, Concurrency: 1 + rng.Intn(8),
			Family: "auto", DNSSEC: rng.Intn(2) == 0,
		}
	}
	for index := 0; index < targets; index++ {
		run.Targets = append(run.Targets, jsonFuzzResult(rng, index, rng.Intn(observations+1)))
	}
	if rng.Intn(4) != 0 {
		run.Rankings = []benchmark.Ranking{}
	}
	for _, result := range run.Targets {
		if rng.Intn(2) == 0 {
			run.Rankings = append(run.Rankings, benchmark.Ranking{Protocol: result.Target.Protocol, TargetID: result.Target.ID(), Rank: 1 + rng.Intn(5), Tie: rng.Intn(2) == 0})
		}
		if rng.Intn(3) == 0 {
			run.PairedEffects = append(run.PairedEffects, benchmark.PairedEffect{
				Protocol: result.Target.Protocol, Policy: jsonFuzzText(rng), TargetID: result.Target.ID(), ReferenceTargetID: run.Targets[0].Target.ID(),
				Samples: rng.Intn(200), MedianDeltaMS: jsonFuzzFloat(rng) - jsonFuzzFloat(rng), CILowMS: -jsonFuzzFloat(rng), CIHighMS: jsonFuzzFloat(rng),
				Indistinguishable: rng.Intn(2) == 0, Reason: jsonFuzzText(rng),
			})
		}
		if rng.Intn(4) == 0 {
			run.Warnings = append(run.Warnings, benchmark.TargetWarning(result.Target, "had "+jsonFuzzText(rng)))
		}
	}
	if rng.Intn(2) == 0 {
		run.Divergence = append(run.Divergence, benchmark.DivergenceDetail{
			Name: "divergent.example", QType: 1, Policy: jsonFuzzText(rng), Compared: 3, Baseline: "answer",
			Classes: map[string]int{"answer": 2, "nxdomain": 1}, Excluded: []benchmark.DivergenceExclusion{{TargetID: "x", ResponseClass: "nxdomain", Treatment: "latency-excluded"}},
		})
	}
	if rng.Intn(2) == 0 {
		run.Warnings = append(run.Warnings, benchmark.RunWarning(jsonFuzzText(rng)))
	}
	return run
}

// TestStreamedJSONMatchesTheEncoderOnRandomReports is the byte-identity proof
// for streaming: hundreds of random reports, with and without --raw, redaction
// and profile view, plus a report of several megabytes whose results cross the
// stream's buffer many times, must each be written exactly as one json.Encoder
// writes the whole document.
func TestStreamedJSONMatchesTheEncoderOnRandomReports(t *testing.T) {
	rng := rand.New(rand.NewSource(20261023))
	for trial := 0; trial < 300; trial++ {
		run := jsonFuzzReport(rng, rng.Intn(8), 6)
		options := JSONOptions{RedactSystem: rng.Intn(2) == 0, ProfileView: rng.Intn(2) == 0}
		requireStreamedJSONMatches(t, fmt.Sprintf("trial %d", trial), run, rng.Intn(2) == 0, options)
	}
	large := jsonFuzzReport(rng, 40, 1500)
	requireStreamedJSONMatches(t, "large raw report", large, true, JSONOptions{ProfileView: true})
	requireStreamedJSONMatches(t, "large redacted report", large, true, JSONOptions{RedactSystem: true})
}

// failAfterBytes accepts writes until they would exceed limit bytes and then
// fails every write, counting the failed ones.
type failAfterBytes struct {
	limit    int
	written  int
	failures int
}

func (w *failAfterBytes) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		w.failures++
		return 0, errors.New("destination full")
	}
	w.written += len(p)
	return len(p), nil
}

// TestStreamedJSONReportsEveryFailure covers both ways a streamed document can
// fail: a value encoding/json refuses, which must surface as the encoder's own
// error wherever in the document it sits, and a destination that stops
// accepting bytes partway through the results array, which must stop the
// stream and be returned rather than lost behind the buffer.
func TestStreamedJSONReportsEveryFailure(t *testing.T) {
	for name, poison := range map[string]func(*benchmark.Report){
		"result": func(run *benchmark.Report) { run.Targets[1].Stats.MedianMS = math.NaN() },
		"paired effect": func(run *benchmark.Report) {
			run.PairedEffects = []benchmark.PairedEffect{{TargetID: "x", MedianDeltaMS: math.Inf(1)}}
		},
	} {
		run := completeReport()
		poison(&run)
		_, referenceErr := encodedJSON(run, false, JSONOptions{})
		err := WriteJSON(io.Discard, run, false)
		if err == nil || referenceErr == nil || err.Error() != referenceErr.Error() {
			t.Fatalf("%s: streamed error %v, encoder error %v", name, err, referenceErr)
		}
	}

	large := jsonFuzzReport(rand.New(rand.NewSource(7)), 30, 1000)
	encoded, err := encodedJSON(large, true, JSONOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < 4*jsonStreamBufferSize {
		t.Fatalf("fixture is %d bytes, too small to fail inside the results array", len(encoded))
	}
	destination := &failAfterBytes{limit: 2 * jsonStreamBufferSize}
	if err := WriteJSON(destination, large, true); err == nil || err.Error() != "destination full" {
		t.Fatalf("streamed write to a failing destination returned %v", err)
	}
	// The first failure ends the stream: nothing further is offered to the
	// destination, so the remaining results are never encoded either.
	if destination.failures != 1 || destination.written > destination.limit {
		t.Fatalf("destination saw %d failed writes after %d bytes, want the stream to stop at the first", destination.failures, destination.written)
	}
}

// BenchmarkWriteJSONRaw compares streaming a --full --raw sized report with
// encoding it as one value. B/op is the point: the single-value encoder holds
// the compact document and an indented copy of it on top of every result,
// while the stream holds one result. Run with:
//
//	go test -run '^$' -bench WriteJSONRaw -benchmem ./internal/report
func BenchmarkWriteJSONRaw(b *testing.B) {
	run := jsonFuzzReport(rand.New(rand.NewSource(84)), 84, 2000)
	b.Run("streamed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := WriteJSON(io.Discard, run, true); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("single-value", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := writeJSONAsOneValue(io.Discard, run, true, JSONOptions{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
