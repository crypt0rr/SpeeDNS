package compare

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{"json", func(b *bytes.Buffer) error { return WriteJSON(b, diff) }},
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

// TestWriteJSONMatchesTheCompareSchema keeps the emitted document and the
// published contract in step, in both outcomes.
func TestWriteJSONMatchesTheCompareSchema(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Report)
	}{
		{"comparable", func(r *Report) { r.Results[0].Stats.UsableResponses = 10 }},
		{"refused", func(r *Report) { r.Run.Seed = int64Ptr(99) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&current)
			var buffer bytes.Buffer
			if err := WriteJSON(&buffer, Compare(baseline, current)); err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(buffer.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"schema_version", "comparable", "baseline", "current", "blockers", "findings", "not_compared", "disclosures", "warnings", "compared"} {
				if _, ok := document[key]; !ok {
					t.Fatalf("%s JSON has no %q", testCase.name, key)
				}
			}
			if testCase.name == "refused" && document["comparable"] != false {
				t.Fatal("a refused diff must report comparable=false")
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
}
