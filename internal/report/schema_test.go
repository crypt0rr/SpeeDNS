package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/schematest"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/crypt0rr/SpeeDNS/schema"
)

// schemaReport is completeReport with everything the schema describes and the
// minimal fixtures leave out: provenance, paired effects -- a reference, a
// measured delta and one below the sample floor -- a divergence detail with
// an ambiguous plurality and exclusions, and the connection a target made.
// Each section is validated as encoded, so a renamed field in any of them
// fails against the schema's additionalProperties:false.
func schemaReport() benchmark.Report {
	run := completeReport()
	run.Provenance = &benchmark.RunProvenance{
		Version: "dev", Commit: "unknown", BuildDate: "unknown", OS: "linux", Architecture: "amd64",
		Interfaces: []string{"lo"}, Protocols: []catalog.Protocol{catalog.UDP}, CorpusEntries: 1,
		CorpusSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout:      time.Second, Concurrency: 1, Family: "auto",
	}
	run.Targets[2].Connection = transport.ConnectionInfo{RemoteAddress: "[2001:db8::53]:443", TLSVersion: "TLS 1.3", HTTPProtocol: "h2"}
	winner := run.Targets[1].Target.ID()
	run.PairedEffects = []benchmark.PairedEffect{
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: winner, ReferenceTargetID: winner, Reference: true, Indistinguishable: true},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: "other@192.0.2.9/udp", ReferenceTargetID: winner, Samples: 40, MedianDeltaMS: 1.5, CILowMS: 0.5, CIHighMS: 2.5},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: "few@192.0.2.8/udp", ReferenceTargetID: winner, Samples: 3, Reason: "fewer than 20 paired samples"},
	}
	run.Divergence = []benchmark.DivergenceDetail{
		{
			Name: "example.com", QType: 1, Policy: "unfiltered", Compared: 3, Baseline: "answer",
			Classes:  map[string]int{"answer": 2, "nxdomain": 1},
			Excluded: []benchmark.DivergenceExclusion{{TargetID: winner, ResponseClass: "nxdomain", Treatment: "latency-excluded"}},
		},
		{Name: "example.org", QType: 28, Policy: "unfiltered", Compared: 2, Ambiguous: true, Classes: map[string]int{"answer": 1, "nodata": 1}},
	}
	return run
}

func TestJSONReportsMatchPublishedSchema(t *testing.T) {
	run := schemaReport()
	cases := []struct {
		name    string
		write   func(*bytes.Buffer) error
		wantRaw bool
	}{
		{name: "normal", write: func(output *bytes.Buffer) error { return WriteJSON(output, run, false) }},
		{name: "raw", write: func(output *bytes.Buffer) error { return WriteJSON(output, run, true) }, wantRaw: true},
		{name: "profile view", write: func(output *bytes.Buffer) error {
			return WriteJSONWithOptions(output, run, true, JSONOptions{ProfileView: true})
		}, wantRaw: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := tc.write(&output); err != nil {
				t.Fatal(err)
			}
			if err := schematest.Validate(schema.ReportV1(), output.Bytes()); err != nil {
				t.Fatalf("JSON does not match schema: %v\n%s", err, output.String())
			}
			for _, section := range []string{`"paired_effects"`, `"divergence"`, `"remote_address"`, `"http_protocol"`} {
				if !bytes.Contains(output.Bytes(), []byte(section)) {
					t.Fatalf("the schema fixture lost its %s section, so it is no longer validated:\n%s", section, output.String())
				}
			}
			if tc.wantRaw && !bytes.Contains(output.Bytes(), []byte(`"samples"`)) {
				t.Fatal("raw report did not include samples")
			}
		})
	}
}

// TestEncoderStillEmitsFieldsTheSchemaNoLongerRequires guards the other half
// of #253. status, answers, answer_rate, family and dnssec were added to the
// schema's required lists after v0.3.0, which made the v1 schema reject every
// older v1 report; they are optional again, but every report this release
// writes must still carry them.
func TestEncoderStillEmitsFieldsTheSchemaNoLongerRequires(t *testing.T) {
	var output bytes.Buffer
	if err := WriteJSON(&output, schemaReport(), false); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Run struct {
			Provenance map[string]any `json:"provenance"`
		} `json:"run"`
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"family", "dnssec"} {
		if _, ok := decoded.Run.Provenance[field]; !ok {
			t.Fatalf("provenance.%s is no longer emitted", field)
		}
	}
	for _, result := range decoded.Results {
		stats, _ := result["stats"].(map[string]any)
		for _, field := range []string{"answers", "answer_rate"} {
			if _, ok := stats[field]; !ok {
				t.Fatalf("stats.%s is no longer emitted: %v", field, result)
			}
		}
		if _, ok := result["status"]; !ok {
			t.Fatalf("status is no longer emitted: %v", result)
		}
	}
}

// TestReleasedReportsMatchTheCurrentSchema pins the schema_version contract:
// report-v1.json must accept every version 1 report any release wrote. The
// required lists grew in v0.4.0 (status, answers, answer_rate) and v0.6.0
// (family, dnssec) while schema_version stayed 1, so the published schema
// rejected v0.1.0-v0.5.x output and a consumer selecting rules by version
// could not validate archived reports.
//
// testdata/released holds what those releases produced, vendored because CI
// checks out a shallow clone and the tags are not there to read:
//   - golden-vX.json is internal/report/testdata/golden/report.json at that
//     tag, taken with git show, one per distinct golden: v0.1.0, v0.2.0 (also
//     v0.3.0) and v0.4.0 (also v0.5.0 through v0.6.9, and still the current
//     golden). The goldens carry no provenance.
//   - provenance-vX.json is that release's own encoder writing the report its
//     schema test validated: completeReport() with run provenance, raw. They
//     cover provenance before family and dnssec existed.
//   - complete-vX.json is that release's own encoder writing schemaReport()
//     raw with --profile-view, every optional section filled. v0.7.0 added
//     remote_address, tls_version and http_protocol to the target.
//
// The golden alone did not change when v0.6.0 added fields to provenance, so
// a release that adds a field vendors a report its own encoder writes with
// every optional section, such as schemaReport() encoded raw.
func TestReleasedReportsMatchTheCurrentSchema(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "released", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var names []string
	for _, path := range paths {
		names = append(names, filepath.Base(path))
	}
	want := "complete-v0.7.0.json golden-v0.1.0.json golden-v0.2.0.json golden-v0.4.0.json provenance-v0.1.0.json provenance-v0.3.0.json provenance-v0.5.0.json"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("released fixtures = %s, want %s", got, want)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			document, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := schematest.Validate(schema.ReportV1(), document); err != nil {
				t.Fatalf("a report v1 wrote no longer matches the v1 schema: %v", err)
			}
		})
	}
	// The current golden is validated beside them: it is the only fixture
	// whose divergence section the golden test byte-compares.
	golden, err := os.ReadFile(filepath.Join("testdata", "golden", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := schematest.Validate(schema.ReportV1(), golden); err != nil {
		t.Fatalf("the current golden report does not match the schema: %v", err)
	}
}

// TestJSONReportWithNoComparableResultsMatchesSchema covers the case the tool
// exists to reveal: every endpoint failed, so nothing is ranked. The published
// schema requires "rankings" to be an array, and a nil slice marshals as null.
func TestJSONReportWithNoComparableResultsMatchesSchema(t *testing.T) {
	failed := reportTarget("1", catalog.UDP, 0, false)
	failed.Stats = benchmark.Statistics{}
	failed.OpenError = "open failed"
	run := benchmark.Report{
		StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0), Seed: 42,
		SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
		Targets: []benchmark.TargetResult{failed},
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, run, false); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte(`"rankings": null`)) {
		t.Fatalf("rankings marshalled as null:\n%s", output.String())
	}
	if err := schematest.Validate(schema.ReportV1(), output.Bytes()); err != nil {
		t.Fatalf("JSON does not match schema: %v\n%s", err, output.String())
	}
}

// TestStatisticsCarryEveryLiveResultsField checks encoder output against the
// live-results contract that scripts/publish-live-results.py enforces. The
// publisher requires every key in $defs/stats, so an omitempty tag on a field
// that is zero for a failed transport silently breaks the publish job while the
// report schema still validates.
func TestStatisticsCarryEveryLiveResultsField(t *testing.T) {
	var liveSchema map[string]any
	if err := json.Unmarshal(schema.LiveResultsV1(), &liveSchema); err != nil {
		t.Fatal(err)
	}
	defs, ok := liveSchema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("live-results schema has no $defs")
	}
	stats, ok := defs["stats"].(map[string]any)
	if !ok {
		t.Fatal("live-results schema has no $defs/stats")
	}
	required, ok := stats["required"].([]any)
	if !ok || len(required) == 0 {
		t.Fatal("live-results $defs/stats has no required list")
	}

	// A transport that never produced a usable response leaves every latency
	// and confidence field at zero; that is exactly when omitempty bites.
	for _, name := range []string{"all-failed", "scored"} {
		t.Run(name, func(t *testing.T) {
			result := reportTarget("1", catalog.UDP, 0, false)
			if name == "all-failed" {
				result.Stats = benchmark.Statistics{Total: 1, Failures: 1}
			}
			encoded, err := json.Marshal(result.Stats)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, key := range required {
				field, ok := key.(string)
				if !ok {
					t.Fatalf("required entry %#v is not a string", key)
				}
				if _, present := decoded[field]; !present {
					t.Fatalf("stats.%s is missing from encoder output: %s", field, encoded)
				}
			}
		})
	}
}
