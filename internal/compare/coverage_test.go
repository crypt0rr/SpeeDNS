package compare

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// failAfterWriter fails on the Nth write. Walking N across a render exercises
// every error return in the writer path, which is how a report gets truncated
// rather than silently half-written when a pipe closes.
type failAfterWriter struct{ remaining int }

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("write failed")
	}
	w.remaining--
	return len(p), nil
}

// TestRenderPropagatesEveryWriteError walks a failing writer across every diff
// shape and both renderers. Every write site must return its error rather than
// continuing to produce a partial document, which is what a closed pipe or a
// full disk looks like.
//
// The shapes matter: one diff cannot reach both the findings branch and the
// within-noise branch, so each is rendered separately.
func TestRenderPropagatesEveryWriteError(t *testing.T) {
	shapes := map[string]Diff{
		"with findings":    richDiff(),
		"within noise":     Compare(baseReport("a.json"), baseReport("b.json")),
		"refused":          refusedDiff(),
		"nothing compared": emptyDiff(),
	}
	for name, diff := range shapes {
		for _, renderer := range []struct {
			label string
			write func(w *failAfterWriter) error
		}{
			{"table", func(w *failAfterWriter) error { return WriteTable(w, diff) }},
			{"json", func(w *failAfterWriter) error { return WriteJSON(w, diff) }},
		} {
			t.Run(name+"/"+renderer.label, func(t *testing.T) {
				// A generous bound: any attempt below the real write count must
				// fail, and once it exceeds the count the render succeeds.
				sawSuccess := false
				for attempt := 0; attempt < 60; attempt++ {
					err := renderer.write(&failAfterWriter{remaining: attempt})
					if err == nil {
						sawSuccess = true
						break
					}
				}
				if !sawSuccess {
					t.Fatal("the render never succeeded even with 60 writes allowed")
				}
				if err := renderer.write(&failAfterWriter{remaining: 0}); err == nil {
					t.Fatal("a writer that fails immediately must produce an error")
				}
			})
		}
	}
}

// emptyDiff is a comparison where nothing was comparable and nothing was said.
func emptyDiff() Diff {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	baseline.Results, current.Results = nil, nil
	baseline.Run.StartedAt, current.Run.StartedAt = time.Time{}, time.Time{}
	baseline.Run.Provenance.Version, current.Run.Provenance.Version = "0.6.0", "0.6.0"
	baseline.Run.Provenance.Family, current.Run.Provenance.Family = strPtr("4"), strPtr("4")
	diff := Compare(baseline, current)
	// Strip the disclosures so the CONTEXT section is skipped entirely.
	diff.Disclosures = nil
	return diff
}

// richDiff exercises every optional section at once: findings, suppressions,
// disclosures and both warning directions.
func richDiff() Diff {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	baseline.Warnings = []string{"a stale warning"}
	current.Warnings = []string{"a fresh warning"}
	current.Results[0].Stats.UsableResponses = 10
	current.Results[0].Status = "ineligible"
	local := Result{
		Target: Target{ID: "local@127.0.0.1/udp", Local: true},
		Status: "not-comparable",
		Stats:  Stats{Total: 40},
	}
	// In BOTH reports: presence is checked before the local rule, so a target
	// in only one of them is reported as added or removed and never reaches it.
	baseline.Results = append(baseline.Results, local)
	current.Results = append(current.Results, local)
	current.Run.Provenance.Version = "0.6.1"
	current.Run.Provenance.Interfaces = []string{"eth0", "docker0"}
	return Compare(baseline, current)
}

func refusedDiff() Diff {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Run.Seed = int64Ptr(99)
	return Compare(baseline, current)
}

// TestDisclosuresCoverEveryContextualDifference walks the things a reader must
// weigh but which never block a comparison.
func TestDisclosuresCoverEveryContextualDifference(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Report, *Report)
		want   string
	}{
		{"arguments reversed", func(b, c *Report) {
			c.Run.StartedAt = b.Run.StartedAt.Add(-2 * time.Hour)
		}, "argument-order"},
		{"different patch version", func(b, c *Report) {
			c.Run.Provenance.Version = "0.6.1"
		}, "build"},
		{"same version, different commit", func(b, c *Report) {
			c.Run.Provenance.Commit = "def67890"
		}, "build"},
		{"unversioned build", func(b, c *Report) {
			b.Run.Provenance.Version, c.Run.Provenance.Version = "dev", "dev"
		}, "build"},
		{"different platform", func(b, c *Report) {
			c.Run.Provenance.OS = "darwin"
		}, "position"},
		{"interface churn", func(b, c *Report) {
			c.Run.Provenance.Interfaces = []string{"eth0", "docker0"}
		}, "interfaces"},
		{"explicit family", func(b, c *Report) {
			b.Run.Provenance.Family, c.Run.Provenance.Family = strPtr("4"), strPtr("4")
		}, "position"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&baseline, &current)
			found := false
			for _, disclosure := range Disclosures(baseline, current) {
				if disclosure.Reason == testCase.want {
					found = true
					if disclosure.Detail == "" {
						t.Fatalf("%s disclosure carries no detail", testCase.want)
					}
				}
			}
			if !found {
				t.Fatalf("want a %s disclosure, got %#v", testCase.want, Disclosures(baseline, current))
			}
		})
	}

	// A report with no timestamps must not invent an elapsed disclosure.
	baseline, current := baseReport("a.json"), baseReport("b.json")
	baseline.Run.StartedAt, current.Run.StartedAt = time.Time{}, time.Time{}
	for _, disclosure := range Disclosures(baseline, current) {
		if disclosure.Reason == "elapsed" || disclosure.Reason == "argument-order" {
			t.Fatalf("a report without timestamps must not produce %q", disclosure.Reason)
		}
	}
}

// TestRequireConditionsCoverBothOutcomes walks each named condition in both
// directions, so a condition that can never fail cannot ship.
func TestRequireConditionsCoverBothOutcomes(t *testing.T) {
	for _, testCase := range []struct {
		condition string
		mutate    func(*Report, *Report)
	}{
		{"no-new-failed-targets", func(b, c *Report) { c.Results[0].Stats.Successes = 0 }},
		{"no-removed-targets", func(b, c *Report) { c.Results = nil }},
		{"target-set-identical", func(b, c *Report) { c.Results[0].Target.ID = "other@2.2.2.2/udp" }},
		{"no-dnssec-regression", func(b, c *Report) {
			b.Results[0].DNSSEC = &DNSSEC{Verdict: "validating"}
			c.Results[0].DNSSEC = &DNSSEC{Verdict: "not-validating"}
		}},
		{"no-behaviour-change", func(b, c *Report) { c.Results[0].Stats.UsableResponses = 0 }},
	} {
		t.Run(testCase.condition, func(t *testing.T) {
			// Passing case.
			clean, err := Require(Compare(baseReport("a.json"), baseReport("b.json")), []string{testCase.condition})
			if err != nil {
				t.Fatal(err)
			}
			if !clean[0].Passed {
				t.Fatalf("%s should pass on identical runs: %s", testCase.condition, clean[0].Detail)
			}
			// Failing case.
			baseline, current := baseReport("a.json"), baseReport("b.json")
			testCase.mutate(&baseline, &current)
			broken, err := Require(Compare(baseline, current), []string{testCase.condition})
			if err != nil {
				t.Fatal(err)
			}
			if broken[0].Passed {
				t.Fatalf("%s should fail here but passed: %s", testCase.condition, broken[0].Detail)
			}
			if broken[0].Detail == "" {
				t.Fatalf("%s failed without saying why", testCase.condition)
			}
		})
	}
}

// TestGateHelpersRenderMissingValues covers the formatting of absent and empty
// fields, which appear only when a report predates a field or omits one.
func TestGateHelpersRenderMissingValues(t *testing.T) {
	if value, ok := optInt(nil); ok || value != "" {
		t.Fatalf("optInt(nil) = %q/%v", value, ok)
	}
	if value, ok := optInt64(nil); ok || value != "" {
		t.Fatalf("optInt64(nil) = %q/%v", value, ok)
	}
	if value, ok := optString(nil); ok || value != "" {
		t.Fatalf("optString(nil) = %q/%v", value, ok)
	}
	if value, ok := optBool(nil); ok || value != "" {
		t.Fatalf("optBool(nil) = %q/%v", value, ok)
	}
	if got := orDash(""); got != "—" {
		t.Fatalf("orDash(empty) = %q", got)
	}
	if got := presence(true, "7"); got != "7" {
		t.Fatalf("presence(true) = %q", got)
	}
	for _, testCase := range []struct{ version, want string }{
		{"", "dev"}, {"v0.6.0", "0.6"}, {"0.6.0", "0.6"}, {"1", "1"},
	} {
		if got := majorMinor(testCase.version); got != testCase.want {
			t.Fatalf("majorMinor(%q) = %q, want %q", testCase.version, got, testCase.want)
		}
	}
	if got := shortCommit("abc"); got != "abc" {
		t.Fatalf("shortCommit(short) = %q", got)
	}
	if got := shortCommit(""); got != "—" {
		t.Fatalf("shortCommit(empty) = %q", got)
	}
	if got := listOrNone(nil); got != "none" {
		t.Fatalf("listOrNone(nil) = %q", got)
	}
	if got := joinInts([]int{1, 28}); got != "1,28" {
		t.Fatalf("joinInts = %q", got)
	}
	if got := absInt(-3); got != 3 {
		t.Fatalf("absInt(-3) = %d", got)
	}
	if got := maxInt(2, 9); got != 9 {
		t.Fatalf("maxInt = %d", got)
	}
	if got := verdictOf(Result{}); got != "" {
		t.Fatalf("verdictOf(no dnssec) = %q", got)
	}
}

// TestBaselineMissingGatedFieldRefuses covers the other side of the
// absent-versus-zero check: the field missing from the BASELINE.
func TestBaselineMissingGatedFieldRefuses(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	baseline.Run.Provenance.Family = nil
	diff := Compare(baseline, current)
	if diff.Comparable() {
		t.Fatal("an absent baseline field must refuse")
	}
	if !strings.Contains(diff.Blockers[0].Baseline, "not recorded") {
		t.Fatalf("blocker = %#v", diff.Blockers[0])
	}
}

// TestPeerRelativeStatusFlipIsSuppressed covers the other status suppression:
// scored excludes divergent responses, which are decided by a plurality vote
// over the other targets present, so a flip turning on scored is a property of
// the cohort rather than of this resolver.
func TestPeerRelativeStatusFlipIsSuppressed(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	current.Results[0].Stats.Scored = 39
	current.Results[0].Status = "ineligible"
	diff := Compare(baseline, current)
	for _, finding := range diff.Findings {
		if finding.Code == "STATUS" {
			t.Fatalf("a scored-driven flip must not be a finding: %#v", finding)
		}
	}
	found := false
	for _, suppression := range diff.Suppressions {
		if suppression.Reason == "peer-relative" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a peer-relative suppression, got %#v", diff.Suppressions)
	}
}

// TestOpenErrorClearingIsReported covers the direction where a target that
// could not be reached becomes reachable.
func TestOpenErrorClearingIsReported(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	baseline.Results[0].OpenError = "i/o timeout"
	diff := Compare(baseline, current)
	for _, finding := range diff.Findings {
		if finding.Code == "OPEN" && strings.Contains(finding.Detail, "-> opened") {
			return
		}
	}
	t.Fatalf("a cleared open error must be reported: %#v", diff.Findings)
}

// TestWriteTableOnAnEmptyComparison covers the shape with nothing to say.
func TestWriteTableOnAnEmptyComparison(t *testing.T) {
	baseline, current := baseReport("a.json"), baseReport("b.json")
	baseline.Results, current.Results = nil, nil
	baseline.Run.StartedAt, current.Run.StartedAt = time.Time{}, time.Time{}
	var buffer bytes.Buffer
	if err := WriteTable(&buffer, Compare(baseline, current)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "no start time") {
		t.Fatalf("a report without a start time should say so:\n%s", buffer.String())
	}
}

// TestRemainingHelperBranches covers the small paths a rendered diff does not
// reach: values that are already short, already non-nil, or already the larger
// of two.
func TestRemainingHelperBranches(t *testing.T) {
	if got := maxInt(9, 2); got != 9 {
		t.Fatalf("maxInt(9,2) = %d", got)
	}
	if got := shortCommit("abcdef1234"); got != "abcdef12" {
		t.Fatalf("shortCommit(long) = %q", got)
	}
	suppressions := []Suppression{{Reason: "local-position"}}
	if got := orEmptySuppressions(suppressions); len(got) != 1 {
		t.Fatalf("orEmptySuppressions passed through %d items", len(got))
	}
	if got := orEmptyBlockers([]Blocker{{Field: "x"}}); len(got) != 1 {
		t.Fatalf("orEmptyBlockers passed through %d items", len(got))
	}
	if got := orEmptyFindings([]Finding{{Code: "OPEN"}}); len(got) != 1 {
		t.Fatalf("orEmptyFindings passed through %d items", len(got))
	}
	if got := orEmptyDisclosures([]Disclosure{{Reason: "build"}}); len(got) != 1 {
		t.Fatalf("orEmptyDisclosures passed through %d items", len(got))
	}
	if got := orEmptyStrings([]string{"a"}); len(got) != 1 {
		t.Fatalf("orEmptyStrings passed through %d items", len(got))
	}
	// The nil branches: JSON must publish an empty array rather than null, so
	// a consumer can iterate without a nil check.
	for name, length := range map[string]int{
		"blockers":     len(orEmptyBlockers(nil)),
		"findings":     len(orEmptyFindings(nil)),
		"suppressions": len(orEmptySuppressions(nil)),
		"disclosures":  len(orEmptyDisclosures(nil)),
		"strings":      len(orEmptyStrings(nil)),
	} {
		if length != 0 {
			t.Fatalf("orEmpty for %s returned %d items from nil", name, length)
		}
	}
	if orEmptyBlockers(nil) == nil || orEmptyFindings(nil) == nil || orEmptySuppressions(nil) == nil ||
		orEmptyDisclosures(nil) == nil || orEmptyStrings(nil) == nil {
		t.Fatal("orEmpty must return an empty slice, never nil, so JSON publishes [] rather than null")
	}
}

// TestLoadAcceptsAWellFormedReport is the success path of the decoder, so a
// change that made every report unreadable would be caught.
func TestLoadAcceptsAWellFormedReport(t *testing.T) {
	path := writeReportFixture(t)
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("a well-formed report must load: %v", err)
	}
	if loaded.Path != path {
		t.Fatalf("Load did not record the path: %q", loaded.Path)
	}
	if loaded.Run.Provenance.Family == nil || *loaded.Run.Provenance.Family != "auto" {
		t.Fatalf("provenance did not decode: %#v", loaded.Run.Provenance)
	}
}

func osWriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func writeReportFixture(t *testing.T) string {
	t.Helper()
	const document = `{
      "schema_version": 1,
      "run": {
        "started_at": "2026-08-25T09:00:00Z",
        "seed": 7, "sample_size": 20, "queries_per_target": 40,
        "query_types": [1, 28], "corpus_mode": "warm-cache",
        "provenance": {
          "speedns_version": "0.6.0", "os": "linux", "architecture": "amd64",
          "corpus_entries": 1000, "corpus_sha256": "800d075a",
          "timeout_ms": 2000, "concurrency": 4, "family": "auto", "dnssec": false
        }
      },
      "results": []
    }`
	path := t.TempDir() + "/report.json"
	if err := osWriteFile(path, document); err != nil {
		t.Fatal(err)
	}
	return path
}
