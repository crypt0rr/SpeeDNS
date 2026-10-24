package compare

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/safetext"
	"github.com/crypt0rr/SpeeDNS/internal/schematest"
	"github.com/crypt0rr/SpeeDNS/schema"
)

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }
func strPtr(v string) *string { return &v }
func boolPtr(v bool) *bool    { return &v }

// baseReport builds a minimal comparable report. Tests mutate one field at a
// time from it, so a failure names exactly what caused it.
func baseReport(path string) Report {
	return Report{
		Path:          path,
		SchemaVersion: intPtr(1),
		Run: &Run{
			StartedAt:        time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC),
			Seed:             int64Ptr(7),
			SampleSize:       intPtr(20),
			QueriesPerTarget: intPtr(40),
			QueryTypes:       []int{1, 28},
			CorpusMode:       "warm-cache",
			Provenance: &Provenance{
				Version: "0.6.0", Commit: "abc12345", OS: "linux", Architecture: "amd64",
				Interfaces:    []string{"eth0"},
				CorpusEntries: intPtr(1000), CorpusSHA256: strPtr("800d075a"),
				TimeoutMS: int64Ptr(2000), Concurrency: intPtr(4),
				Family: strPtr("auto"), DNSSEC: boolPtr(false),
			},
		},
		Results: []Result{{
			Target: Target{ID: "a@1.1.1.1/udp", Address: "1.1.1.1", Protocol: "udp"},
			Status: "qualified",
			Stats: Stats{
				Total: 40, Successes: 40, UsableResponses: 40, Answers: 20, Scored: 40,
				RCodeCounts: map[string]int{"NOERROR": 40},
			},
		}},
	}
}

// TestGateRefusesOnEveryRunIdentityField walks the comparability contract. Each
// row must both fire on a difference and name the field, and the refusal must
// carry no count from either report -- a refused comparison that leaks a number
// invites the reader to compare it anyway.
func TestGateRefusesOnEveryRunIdentityField(t *testing.T) {
	for _, testCase := range []struct {
		field  string
		mutate func(*Report)
	}{
		{"run.seed", func(r *Report) { r.Run.Seed = int64Ptr(9) }},
		{"run.sample_size", func(r *Report) { r.Run.SampleSize = intPtr(50) }},
		{"run.queries_per_target", func(r *Report) { r.Run.QueriesPerTarget = intPtr(100) }},
		{"run.query_types", func(r *Report) { r.Run.QueryTypes = []int{1} }},
		{"run.corpus_mode", func(r *Report) { r.Run.CorpusMode = "other" }},
		{"provenance.corpus_sha256", func(r *Report) { r.Run.Provenance.CorpusSHA256 = strPtr("deadbeef") }},
		{"provenance.corpus_entries", func(r *Report) { r.Run.Provenance.CorpusEntries = intPtr(500) }},
		{"provenance.timeout_ms", func(r *Report) { r.Run.Provenance.TimeoutMS = int64Ptr(4000) }},
		{"provenance.concurrency", func(r *Report) { r.Run.Provenance.Concurrency = intPtr(10) }},
		{"provenance.family", func(r *Report) { r.Run.Provenance.Family = strPtr("4") }},
		{"provenance.dnssec", func(r *Report) { r.Run.Provenance.DNSSEC = boolPtr(true) }},
		{"provenance.speedns_version", func(r *Report) { r.Run.Provenance.Version = "0.7.0" }},
	} {
		t.Run(testCase.field, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&current)
			diff := Compare(baseline, current)
			if diff.Comparable() {
				t.Fatalf("%s differing must refuse the comparison", testCase.field)
			}
			named := false
			for _, blocker := range diff.Blockers {
				if blocker.Field == testCase.field {
					named = true
					if blocker.Reason == "" {
						t.Fatalf("%s blocked without a reason", testCase.field)
					}
				}
			}
			if !named {
				t.Fatalf("blockers %#v do not name %s", diff.Blockers, testCase.field)
			}
			if len(diff.Findings) != 0 {
				t.Fatalf("a refused comparison produced findings: %#v", diff.Findings)
			}
			// No count from either report may appear in the refusal.
			var buffer bytes.Buffer
			if err := WriteTable(&buffer, diff); err != nil {
				t.Fatal(err)
			}
			for _, leaked := range []string{"usable", "NOERROR", "qualified"} {
				if strings.Contains(buffer.String(), leaked) {
					t.Fatalf("the refusal leaked %q from a report:\n%s", leaked, buffer.String())
				}
			}
		})
	}
}

// TestGateRefusesCacheMissUnconditionally covers the one rule with no override.
// Cache-miss runs generate fresh names each time, so no two of them asked the
// same questions -- and an equal nonce would prove the second run read the
// first run's cached answers, which is worse.
func TestGateRefusesCacheMissUnconditionally(t *testing.T) {
	for _, side := range []string{"baseline", "current"} {
		t.Run(side, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			target := &current
			if side == "baseline" {
				target = &baseline
			}
			target.Run.CorpusMode = "cache-miss"
			diff := Compare(baseline, current)
			if diff.Comparable() {
				t.Fatal("a cache-miss run must never be compared")
			}
		})
	}
}

// TestGateRefusesWhenAGatedFieldIsAbsent covers the absent-versus-zero trap: a
// report written before a field existed omits it, and decoding an absent bool
// as false would silently compare a DNSSEC run against a plain one.
func TestGateRefusesWhenAGatedFieldIsAbsent(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Run.Provenance.DNSSEC = nil
	diff := Compare(baseline, current)
	if diff.Comparable() {
		t.Fatal("an absent gated field must refuse rather than read as its zero value")
	}
	if !strings.Contains(diff.Blockers[0].Current, "not recorded") {
		t.Fatalf("blocker should say the field is not recorded: %#v", diff.Blockers[0])
	}
}

// TestIdenticalRunsProduceNoFindings is the case that matters most: two runs of
// the same command must be silent, because that is what makes any finding
// meaningful.
func TestIdenticalRunsProduceNoFindings(t *testing.T) {
	diff := Compare(baseReport("a.json"), baseReport("b.json"))
	if !diff.Comparable() {
		t.Fatalf("identical runs must be comparable: %#v", diff.Blockers)
	}
	if len(diff.Findings) != 0 {
		t.Fatalf("identical runs produced findings: %#v", diff.Findings)
	}
	if diff.Compared != 1 {
		t.Fatalf("compared %d endpoints, want 1", diff.Compared)
	}
}

// TestStatusFlipBelowTheFloorIsSuppressed closes the attack that broke the
// original design: status is a threshold on a measured count, so one dropped
// datagram at the 99% bar flips qualified to ineligible without anything
// changing about the resolver.
func TestStatusFlipBelowTheFloorIsSuppressed(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Results[0].Stats.UsableResponses = 39
	current.Results[0].Status = "ineligible"

	diff := Compare(baseline, current)
	for _, finding := range diff.Findings {
		if finding.Code == "STATUS" {
			t.Fatalf("a one-response crossing must not be a status finding: %#v", finding)
		}
	}
	suppressed := false
	for _, suppression := range diff.Suppressions {
		if suppression.Reason == "boundary-crossing" {
			suppressed = true
			if !strings.Contains(suppression.Detail, "39/40") {
				t.Fatalf("the suppression must show the deciding counts: %q", suppression.Detail)
			}
		}
	}
	if !suppressed {
		t.Fatal("the suppression must be named, never silent")
	}

	// A drop well beyond the floor is a real finding.
	current.Results[0].Stats.UsableResponses = 20
	real := Compare(baseline, current)
	found := false
	for _, finding := range real.Findings {
		if finding.Code == "STATUS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a 20-response drop must be reported: %#v", real.Findings)
	}
}

// TestResponseFloorSpendsTheDocumentedBudget pins the floor to the project's
// own tolerance: MinimumRecommendedSuccessRate is 0.99, so 1% of responses may
// move without being a behaviour change, and never fewer than two.
func TestResponseFloorSpendsTheDocumentedBudget(t *testing.T) {
	for _, testCase := range []struct{ total, want int }{
		{0, 2}, {40, 2}, {100, 2}, {200, 2}, {8700, 87},
	} {
		if got := responseFloor(testCase.total); got != testCase.want {
			t.Fatalf("responseFloor(%d) = %d, want %d", testCase.total, got, testCase.want)
		}
	}
}

// TestFindingsCoverTheBehaviourCodes exercises each code that reports what a
// resolver did.
func TestFindingsCoverTheBehaviourCodes(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Report)
		want   string
	}{
		{"unreachable", func(r *Report) { r.Results[0].OpenError = "i/o timeout" }, "OPEN"},
		{"all queries failed", func(r *Report) { r.Results[0].Stats.Successes = 0 }, "FAILED"},
		{"different matrix", func(r *Report) { r.Results[0].Stats.Total = 30 }, "QUERIES"},
		{"usable dropped", func(r *Report) { r.Results[0].Stats.UsableResponses = 10 }, "USABLE"},
		{"answers dropped", func(r *Report) { r.Results[0].Stats.Answers = 0 }, "ANSWERS"},
		{"truncation appeared", func(r *Report) { r.Results[0].Stats.Truncated = 9 }, "TRUNCATED"},
		{"rcode moved", func(r *Report) { r.Results[0].Stats.RCodeCounts = map[string]int{"NOERROR": 10, "SERVFAIL": 30} }, "RCODE"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&current)
			diff := Compare(baseline, current)
			found := false
			for _, finding := range diff.Findings {
				if finding.Code == testCase.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("want a %s finding, got %#v", testCase.want, diff.Findings)
			}
		})
	}
}

// TestSuppressionsAreNamedNotSilent covers every case the tool declines to
// compare. A reader must be able to tell "nothing changed" from "this was not
// checked".
func TestSuppressionsAreNamedNotSilent(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Report, *Report)
		want   string
	}{
		{"local resolver", func(b, c *Report) { c.Results[0].Target.Local = true }, "local-position"},
		{"interrupted run", func(b, c *Report) { c.Results[0].Incomplete = true }, "incomplete-target"},
		{"different denominator", func(b, c *Report) { c.Results[0].Stats.Total = 30 }, "denominator-mismatch"},
		{"redacted identity", func(b, c *Report) {
			b.Results[0].Target.ID = "system-redacted-1@x/udp"
			c.Results[0].Target.ID = "system-redacted-1@x/udp"
		}, "redacted-identity"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&baseline, &current)
			diff := Compare(baseline, current)
			found := false
			for _, suppression := range diff.Suppressions {
				if suppression.Reason == testCase.want {
					found = true
					if suppression.Detail == "" {
						t.Fatalf("%s suppression carries no explanation", testCase.want)
					}
				}
			}
			if !found {
				t.Fatalf("want a %s suppression, got %#v", testCase.want, diff.Suppressions)
			}
		})
	}
}

// TestDNSSECReportsOnlyDecidedTransitions covers the rule that an incomplete
// probe is not a validation change: assessDNSSEC reports inconclusive whenever
// a probe fails to complete, which one lost packet achieves.
func TestDNSSECReportsOnlyDecidedTransitions(t *testing.T) {
	for _, testCase := range []struct {
		before, after string
		wantFinding   bool
	}{
		{"validating", "not-validating", true},
		{"not-validating", "validating", true},
		{"validating", "inconclusive", false},
		{"inconclusive", "validating", false},
	} {
		t.Run(testCase.before+"->"+testCase.after, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			baseline.Results[0].DNSSEC = &DNSSEC{Verdict: testCase.before}
			current.Results[0].DNSSEC = &DNSSEC{Verdict: testCase.after}
			diff := Compare(baseline, current)
			found := false
			for _, finding := range diff.Findings {
				if finding.Code == "DNSSEC" {
					found = true
				}
			}
			if found != testCase.wantFinding {
				t.Fatalf("%s -> %s: finding=%v, want %v", testCase.before, testCase.after, found, testCase.wantFinding)
			}
			if !testCase.wantFinding && len(diff.Suppressions) == 0 {
				t.Fatal("an undecided transition must still be disclosed")
			}
		})
	}
}

// TestPresenceReportsBothDirections covers a target appearing and vanishing.
func TestPresenceReportsBothDirections(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Results[0].Target.ID = "b@9.9.9.9/udp"
	diff := Compare(baseline, current)
	if len(diff.Findings) != 2 {
		t.Fatalf("want an added and a removed target, got %#v", diff.Findings)
	}
	for _, finding := range diff.Findings {
		if finding.Code != "PRESENCE" {
			t.Fatalf("unexpected finding %#v", finding)
		}
	}
}

// TestRequireEvaluatesNamedConditions covers the CI gate, including that an
// unknown name is a usage error rather than a silent pass.
func TestRequireEvaluatesNamedConditions(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Results[0].Stats.Successes = 0
	diff := Compare(baseline, current)

	results, err := Require(diff, []string{"no-new-failed-targets", "no-behaviour-change"})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.Passed {
			t.Fatalf("%s should not pass on a failed target", result.Name)
		}
	}
	clean := Compare(baseReport("a.json"), baseReport("b.json"))
	results, err = Require(clean, RequireNames())
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if !result.Passed {
			t.Fatalf("%s should pass on identical runs: %s", result.Name, result.Detail)
		}
	}
	if _, err := Require(clean, []string{"no-such-condition"}); err == nil {
		t.Fatal("an unknown condition must be a usage error")
	}
}

// TestNoNewFailedTargetsReadsDirection pins #230. OPEN and FAILED findings are
// reported both ways, because a recovery is a behaviour change; the gate must
// not read them both ways, or a baseline saved during an outage fails CI the
// moment the resolver comes back. A dead target that only the current run has
// is a failure the run introduced, unless it is local or interrupted.
func TestNoNewFailedTargetsReadsDirection(t *testing.T) {
	dead := func(result *Result) {
		result.Stats.Successes, result.Stats.UsableResponses, result.Stats.Answers, result.Stats.Scored = 0, 0, 0, 0
		result.Stats.RCodeCounts = map[string]int{}
	}
	added := func(change func(*Result)) func(*Report, *Report) {
		return func(_, current *Report) {
			extra := baseReport("").Results[0]
			extra.Target = Target{ID: "b@9.9.9.9/udp", Address: "9.9.9.9", Protocol: "udp"}
			change(&extra)
			current.Results = append(current.Results, extra)
		}
	}
	for _, testCase := range []struct {
		name   string
		mutate func(baseline, current *Report)
		// finding is a code the diff must still report, so the direction is
		// read by the gate rather than dropped from the findings.
		finding string
		detail  string // empty means the condition passes
	}{
		{name: "recovery from dead", mutate: func(b, _ *Report) { dead(&b.Results[0]) }, finding: "FAILED"},
		{name: "open error cleared", mutate: func(b, _ *Report) {
			dead(&b.Results[0])
			b.Results[0].OpenError = "dial udp: i/o timeout"
		}, finding: "OPEN"},
		{name: "open error cleared while still failing", mutate: func(b, c *Report) {
			dead(&b.Results[0])
			dead(&c.Results[0])
			b.Results[0].OpenError = "dial udp: i/o timeout"
		}, finding: "OPEN"},
		{name: "dead in both runs", mutate: func(b, c *Report) { dead(&b.Results[0]); dead(&c.Results[0]) }},
		{name: "removed target is not a new failure", mutate: func(_, c *Report) {
			c.Results[0].Target.ID = "b@9.9.9.9/udp"
		}, finding: "PRESENCE"},
		{name: "healthy added target", mutate: added(func(*Result) {}), finding: "PRESENCE"},
		{name: "dead added local target", mutate: added(func(r *Result) {
			dead(r)
			r.Target.Local = true
		}), finding: "PRESENCE"},
		{name: "dead added interrupted target", mutate: added(func(r *Result) {
			dead(r)
			r.Incomplete = true
		}), finding: "PRESENCE"},
		{name: "healthy to dead", mutate: func(_, c *Report) { dead(&c.Results[0]) },
			finding: "FAILED", detail: "a@1.1.1.1/udp: successes 40 -> 0"},
		{name: "open error appeared", mutate: func(_, c *Report) { c.Results[0].OpenError = "connection refused" },
			finding: "OPEN", detail: "a@1.1.1.1/udp: opened -> connection refused"},
		{name: "dead added target", mutate: added(dead),
			finding: "PRESENCE", detail: "b@9.9.9.9/udp: only in the current run, with successes 0 of 40"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&baseline, &current)
			diff := Compare(baseline, current)
			if testCase.finding != "" {
				reported := false
				for _, finding := range diff.Findings {
					reported = reported || finding.Code == testCase.finding
				}
				if !reported {
					t.Fatalf("the diff must still report %s: %#v", testCase.finding, diff.Findings)
				}
			}
			results, err := Require(diff, []string{"no-new-failed-targets"})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.detail == "" {
				if !results[0].Passed {
					t.Fatalf("must pass, failed with %q", results[0].Detail)
				}
				return
			}
			if results[0].Passed || results[0].Detail != testCase.detail {
				t.Fatalf("result = %#v, want a failure with %q", results[0], testCase.detail)
			}
		})
	}
}

// TestOutputNeverNamesALatencyStatistic is the claim boundary, enforced.
// Latency is the one thing this feature must never report, in any format.
func TestOutputNeverNamesALatencyStatistic(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Results[0].Stats.UsableResponses = 10
	current.Results[0].Status = "ineligible"
	diff := Compare(baseline, current)

	for _, render := range []struct {
		name  string
		write func(*bytes.Buffer) error
	}{
		{"table", func(b *bytes.Buffer) error { return WriteTable(b, diff) }},
		{"json", func(b *bytes.Buffer) error { return WriteJSON(b, diff, nil) }},
	} {
		t.Run(render.name, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := render.write(&buffer); err != nil {
				t.Fatal(err)
			}
			text := buffer.String()
			// "p95" and "score" appear once each in the fixed explanation of
			// why latency is absent; a VALUE would appear as a field name.
			for _, forbidden := range []string{"median_ms", "p95_ms", "score_ms", "ci_low", "ci_high", "faster", "slower", "regressed", "improved"} {
				if strings.Contains(text, forbidden) {
					t.Fatalf("%s output names %q; the diff must never claim a latency difference:\n%s", render.name, forbidden, text)
				}
			}
		})
	}
}

// TestWriteJSONMatchesTheCompareSchema validates the emitted document against
// schema/compare-v1.json, in every shape a diff can take. The scenarios
// between them produce every finding code, every suppression reason and every
// condition outcome, and the test reads those enums from the schema itself, so
// renaming a value on either side -- or adding one to the code without the
// schema -- fails here instead of in a consumer.
func TestWriteJSONMatchesTheCompareSchema(t *testing.T) {
	var document struct {
		Definitions map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schema.CompareV1(), &document); err != nil {
		t.Fatal(err)
	}
	enum := func(definition, property string) []string {
		values := append([]string(nil), document.Definitions[definition].Properties[property].Enum...)
		if len(values) == 0 {
			t.Fatalf("compare-v1 $defs/%s.%s has no enum", definition, property)
		}
		sort.Strings(values)
		return values
	}
	if got, want := enum("condition", "name"), RequireNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("compare-v1 condition names = %v, want the --require conditions %v", got, want)
	}

	statusDrop := func(usable, scored int) func(_, c *Report) {
		return func(_, c *Report) {
			c.Results[0].Status = "ineligible"
			c.Results[0].Stats.UsableResponses = usable
			c.Results[0].Stats.Scored = scored
		}
	}
	every := RequireNames()
	scenarios := []struct {
		name     string
		mutate   func(baseline, current *Report)
		required []string
	}{
		{name: "identical, gated", required: every},
		{name: "refused, gated", mutate: func(_, c *Report) { c.Run.Seed = int64Ptr(99) }, required: every},
		{name: "nothing compared, gated", mutate: func(_, c *Report) { c.Results[0].Incomplete = true }, required: every},
		{name: "target added and removed", mutate: func(_, c *Report) { c.Results[0].Target.ID = "b@9.9.9.9/udp" }},
		{name: "open error", mutate: func(_, c *Report) { c.Results[0].OpenError = "i/o timeout" }, required: every},
		{name: "all queries failed", mutate: func(_, c *Report) { c.Results[0].Stats.Successes = 0 }},
		{name: "different matrix", mutate: func(_, c *Report) { c.Results[0].Stats.Total = 30 }},
		{name: "usable dropped with status", mutate: statusDrop(10, 40)},
		{name: "answers dropped", mutate: func(_, c *Report) { c.Results[0].Stats.Answers = 0 }},
		{name: "truncation appeared", mutate: func(_, c *Report) { c.Results[0].Stats.Truncated = 9 }},
		{name: "rcode moved", mutate: func(_, c *Report) {
			c.Results[0].Stats.RCodeCounts = map[string]int{"NOERROR": 10, "SERVFAIL": 30}
		}},
		{name: "boundary crossing", mutate: statusDrop(39, 40)},
		{name: "peer relative", mutate: statusDrop(40, 39)},
		{name: "dnssec decided", mutate: func(b, c *Report) {
			b.Results[0].DNSSEC, c.Results[0].DNSSEC = &DNSSEC{Verdict: "validating"}, &DNSSEC{Verdict: "not-validating"}
		}},
		{name: "dnssec undecided", mutate: func(b, c *Report) {
			b.Results[0].DNSSEC, c.Results[0].DNSSEC = &DNSSEC{Verdict: "validating"}, &DNSSEC{Verdict: "inconclusive"}
		}},
		{name: "local resolver", mutate: func(_, c *Report) { c.Results[0].Target.Local = true }},
		{name: "redacted identity", mutate: func(b, c *Report) {
			b.Results[0].Target.ID, c.Results[0].Target.ID = "system-redacted-1@x/udp", "system-redacted-1@x/udp"
		}},
		{name: "warnings changed", mutate: func(b, c *Report) {
			b.Warnings, c.Warnings = []string{"old warning"}, []string{"new warning"}
		}},
	}
	seen := map[string]map[string]bool{"code": {}, "reason": {}, "outcome": {}}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			if scenario.mutate != nil {
				scenario.mutate(&baseline, &current)
			}
			diff := Compare(baseline, current)
			var conditions []Condition
			if len(scenario.required) > 0 {
				results, err := Require(diff, scenario.required)
				if err != nil {
					t.Fatal(err)
				}
				conditions = Conditions(diff, results)
			}
			var buffer bytes.Buffer
			if err := WriteJSON(&buffer, diff, conditions); err != nil {
				t.Fatal(err)
			}
			if err := schematest.Validate(schema.CompareV1(), buffer.Bytes()); err != nil {
				t.Fatalf("diff JSON does not match compare-v1: %v\n%s", err, buffer.String())
			}
			var decoded struct {
				Comparable bool `json:"comparable"`
			}
			if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil || decoded.Comparable != diff.Comparable() {
				t.Fatalf("comparable = %v, want %v (%v)", decoded.Comparable, diff.Comparable(), err)
			}
			if gated := bytes.Contains(buffer.Bytes(), []byte(`"conditions"`)); gated != (len(conditions) > 0) {
				t.Fatalf("conditions present = %v, want it only when --require ran:\n%s", gated, buffer.String())
			}
			for _, finding := range diff.Findings {
				seen["code"][finding.Code] = true
			}
			for _, suppression := range diff.Suppressions {
				seen["reason"][suppression.Reason] = true
			}
			for _, condition := range conditions {
				seen["outcome"][condition.Outcome] = true
			}
		})
	}
	for key, definition := range map[string]string{"code": "finding", "reason": "suppression", "outcome": "condition"} {
		produced := make([]string, 0, len(seen[key]))
		for value := range seen[key] {
			produced = append(produced, value)
		}
		sort.Strings(produced)
		if got, want := strings.Join(produced, ","), strings.Join(enum(definition, key), ","); got != want {
			t.Fatalf("scenarios produced %s values %s, want every value compare-v1 allows: %s", key, got, want)
		}
	}
}

// TestConditionsNeverPassAGateThatCouldNotEvaluate pins the JSON half of #230:
// a condition's own result holds on a refused diff and on one that compared
// nothing, because it read no finding, and recording that as passed would
// archive a pass for a gate the exit status refused.
func TestConditionsNeverPassAGateThatCouldNotEvaluate(t *testing.T) {
	gate := func(mutate func(baseline, current *Report), names ...string) []Condition {
		baseline, current := baseReport("a.json"), baseReport("b.json")
		mutate(&baseline, &current)
		diff := Compare(baseline, current)
		results, err := Require(diff, names)
		if err != nil {
			t.Fatal(err)
		}
		return Conditions(diff, results)
	}
	refused := gate(func(_, c *Report) { c.Run.Seed = int64Ptr(99) }, "no-behaviour-change")
	if want := (Condition{Name: "no-behaviour-change", Outcome: OutcomeNotEvaluated, Detail: "not evaluated: the runs are not comparable"}); refused[0] != want {
		t.Fatalf("refused condition = %#v, want %#v", refused[0], want)
	}
	unpaired := gate(func(_, c *Report) { c.Results[0].Target.ID = "b@9.9.9.9/udp" }, "no-new-failed-targets", "no-removed-targets")
	want := []Condition{
		{Name: "no-new-failed-targets", Outcome: OutcomeNotEvaluated, Detail: "not evaluated: no endpoint was compared (2 present in only one run)"},
		{Name: "no-removed-targets", Outcome: OutcomeFailed, Detail: "a@1.1.1.1/udp is absent from the current run"},
	}
	if !reflect.DeepEqual(unpaired, want) {
		t.Fatalf("unpaired conditions = %#v, want %#v", unpaired, want)
	}
	passed := gate(func(*Report, *Report) {}, "no-behaviour-change")
	if !passed[0].Passed || passed[0].Outcome != OutcomePassed || passed[0].Detail != "no findings" {
		t.Fatalf("a condition that held over a compared endpoint = %#v, want passed", passed[0])
	}
	for _, condition := range append(refused, unpaired...) {
		if condition.Passed {
			t.Fatalf("a condition the gate did not pass reports passed: %#v", condition)
		}
	}
}

// TestNotComparedSummaryNamesEveryReason covers each way a diff can compare
// nothing, counted in a stable order.
func TestNotComparedSummaryNamesEveryReason(t *testing.T) {
	for _, testCase := range []struct {
		name string
		diff Diff
		want string
	}{
		{name: "empty", want: "neither run has a target"},
		{name: "suppressed and unpaired", diff: Diff{
			Suppressions: []Suppression{{Reason: "local-position"}, {Reason: "incomplete-target"}, {Reason: "local-position"}},
			Findings:     []Finding{{Code: "PRESENCE"}, {Code: "FAILED"}},
		}, want: "1 incomplete-target, 2 local-position, 1 present in only one run"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := NotComparedSummary(testCase.diff); got != testCase.want {
				t.Fatalf("summary = %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestLoadRejectsUnusableInput covers every way a file can fail to be a report.
func TestLoadRejectsUnusableInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, testCase := range []struct{ name, content, wants string }{
		{"notjson.json", "this is not json", "parse"},
		{"noversion.json", `{"run":{}}`, "no schema_version"},
		{"wrongversion.json", `{"schema_version":2,"run":{}}`, "schema_version 2"},
		{"norun.json", `{"schema_version":1}`, "no run section"},
		{"noprovenance.json", `{"schema_version":1,"run":{}}`, "no run.provenance"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := Load(write(testCase.name, testCase.content)); err == nil ||
				!strings.Contains(err.Error(), testCase.wants) {
				t.Fatalf("Load(%s) = %v, want an error mentioning %q", testCase.name, err, testCase.wants)
			}
		})
	}
	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("a missing file must be an error")
	}
	// A directory opens on every supported platform but cannot be read.
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "read "+dir) {
		t.Fatalf("Load(directory) = %v, want a read error", err)
	}
}

// TestLoadCapsTheInputSize pins the boundary of the size cap: an input of
// exactly MaxReportBytes is still a report, one byte more is refused with an
// error that names the limit. A regular file is refused by its size before it
// is read, which the stated byte count in the error shows: a refusal made
// while reading cannot know it. TestLoadStopsReadingAnEndlessStream covers
// inputs without a size. The cap is lowered so the test needs no 256 MiB
// fixture.
func TestLoadCapsTheInputSize(t *testing.T) {
	oldLimit := MaxReportBytes
	t.Cleanup(func() { MaxReportBytes = oldLimit })
	MaxReportBytes = 1 << 20

	document, err := os.ReadFile(writeReportFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// JSON permits trailing whitespace, so padding changes the size and
	// nothing else.
	padded := func(size int64) string {
		path := filepath.Join(t.TempDir(), "padded.json")
		content := append(append([]byte(nil), document...), bytes.Repeat([]byte(" "), int(size)-len(document))...)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := Load(padded(MaxReportBytes)); err != nil {
		t.Fatalf("an input of exactly the cap must load: %v", err)
	}
	oversized := padded(MaxReportBytes + 1)
	_, err = Load(oversized)
	if err == nil || !strings.Contains(err.Error(), oversized) || !strings.Contains(err.Error(), "1 MiB limit") ||
		!strings.Contains(err.Error(), "is 1048577 bytes") {
		t.Fatalf("an input past the cap = %v, want an error naming the path, its size and the limit", err)
	}
}

// TestReadReportInputReadsARegularFileIntoOneBuffer pins that the cap did not
// double the memory a large report costs. A regular file states its size, so
// it is read into one buffer of that size, as os.ReadFile would, instead of
// into chunks that are then copied into a second buffer to be joined.
func TestReadReportInputReadsARegularFileIntoOneBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.json")
	want := bytes.Repeat([]byte(" "), 3*reportReadChunk+7)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	content, err := readReportInput(path)
	if err != nil || !bytes.Equal(content, want) {
		t.Fatalf("readReportInput = %d bytes/%v, want %d bytes", len(content), err, len(want))
	}
	if cap(content) != len(want)+1 {
		t.Fatalf("a %d-byte file was read into a %d-byte buffer, want one buffer of its size plus one", len(want), cap(content))
	}
}

// TestRequireDetailsEscapeReportText covers the gate's failure message. It is
// printed to stderr beside the escaped diff table, and both of its parts come
// from the report files: a target ID carrying a resolver ID from
// --resolver-file, and an open error quoting endpoint-chosen text. A crafted
// report must not reach the terminal through the gate either.
func TestRequireDetailsEscapeReportText(t *testing.T) {
	const (
		hostileID        = "evil\x1b[2K\u202e@1.1.1.1/udp"
		hostileIDEscaped = `evil\x1b[2K\u{202e}@1.1.1.1/udp`
	)
	hostile := func(path string) Report {
		report := baseReport(path)
		report.Results[0].Target.ID = hostileID
		return report
	}
	opened := hostile("b.json")
	opened.Results[0].OpenError = "x509: valid for \x1b[2J\u200bspoofed"
	removed := baseReport("b.json")
	validating, regressed := hostile("a.json"), hostile("b.json")
	validating.Results[0].DNSSEC = &DNSSEC{Verdict: "validating"}
	regressed.Results[0].DNSSEC = &DNSSEC{Verdict: "not-validating"}
	// added puts the hostile target beside the baseline's own, so it is the
	// only PRESENCE finding. Removing the baseline target instead would add a
	// second one, and target IDs sort, so that one would be reported first.
	added := func(stats Stats) Report {
		report := baseReport("b.json")
		extra := hostile("").Results[0]
		extra.Stats = stats
		report.Results = append(report.Results, extra)
		return report
	}
	healthy := baseReport("").Results[0].Stats

	for _, testCase := range []struct {
		name, condition   string
		baseline, current Report
		want              string
	}{
		{"open error", "no-new-failed-targets", hostile("a.json"), opened, hostileIDEscaped + `: opened -> x509: valid for \x1b[2J\u{200b}spoofed`},
		{"dead added target", "no-new-failed-targets", baseReport("a.json"), added(Stats{Total: 40}), hostileIDEscaped + ": only in the current run, with successes 0 of 40"},
		{"removed target", "no-removed-targets", hostile("a.json"), removed, hostileIDEscaped + " is absent from the current run"},
		{"added target", "target-set-identical", baseReport("a.json"), added(healthy), hostileIDEscaped + ": only in the current run"},
		{"validation regression", "no-dnssec-regression", validating, regressed, hostileIDEscaped + " stopped validating"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			results, err := Require(Compare(testCase.baseline, testCase.current), []string{testCase.condition})
			if err != nil {
				t.Fatal(err)
			}
			if results[0].Passed {
				t.Fatalf("%s passed on a hostile report", testCase.condition)
			}
			if results[0].Detail != testCase.want {
				t.Fatalf("detail = %q, want %q", results[0].Detail, testCase.want)
			}
			if again := safetext.Escape(results[0].Detail); again != results[0].Detail {
				t.Fatalf("detail is not fully escaped: %q", results[0].Detail)
			}
		})
	}
}

// TestWriteJSONEscapesReportText covers the machine form of a diff. Every
// string it echoes -- paths, blocker values, target IDs, details, scopes and
// warnings -- comes from the command line or the two report files, so a
// crafted report must not reach a consumer that decodes and prints the JSON,
// just as it cannot reach the escaped table.
func TestWriteJSONEscapesReportText(t *testing.T) {
	const hostileID = "evil\x1b[2K\u202e@1.1.1.1/udp"
	diff := Diff{
		Baseline:        Report{Path: "base\x1b[2J.json"},
		Current:         Report{Path: "current\u2066.json"},
		Blockers:        []Blocker{{Field: "run.seed", Baseline: "1\x1b[2J", Current: "2\u202e", Reason: "the query matrix differs"}},
		Findings:        []Finding{{Code: "FAILED", TargetID: hostileID, Detail: "successes 40 -> 0\u200b"}},
		Suppressions:    []Suppression{{Reason: "local-position", Scope: "scope\x1b", Detail: "detail\u202e"}},
		Disclosures:     []Disclosure{{Reason: "reason", Detail: "disclosed\x1b[H"}},
		AddedWarnings:   []string{"added\x1b[2J"},
		RemovedWarnings: []string{"removed\u2066"},
	}
	conditions := []Condition{{Name: "no-new-failed-targets", Outcome: OutcomeFailed, Detail: hostileID + ": successes 40 -> 0"}}
	var output bytes.Buffer
	if err := WriteJSON(&output, diff, conditions); err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	var walk func(value any)
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			if again := safetext.Escape(typed); again != typed {
				t.Fatalf("decoded JSON kept raw untrusted text: %q", typed)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(document)
	findings := document.(map[string]any)["findings"].([]any)
	if got := findings[0].(map[string]any)["target_id"]; got != `evil\x1b[2K\u{202e}@1.1.1.1/udp` {
		t.Fatalf("target_id = %q, want the escaped form", got)
	}
	recorded := document.(map[string]any)["conditions"].([]any)
	if got := recorded[0].(map[string]any)["detail"]; got != `evil\x1b[2K\u{202e}@1.1.1.1/udp: successes 40 -> 0` {
		t.Fatalf("condition detail = %q, want the escaped form", got)
	}
}
