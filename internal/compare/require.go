package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crypt0rr/SpeeDNS/internal/safetext"
)

// RequireResult is the outcome of one named condition. Detail is printed to
// stderr when the condition fails, and it quotes target IDs and finding
// details read from the two report files, so it is built from escaped text:
// a crafted or hostile report must not reach the terminal through a gate
// failure when the diff table beside it is escaped.
type RequireResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// requireConditions are named categorical conditions only. There is
// deliberately no threshold form such as --fail-if p95>+20%: the quantity such
// a gate would read moves by more than its own threshold between identical
// runs, so it would fire on nothing. Absolute gating already exists and is the
// right tool for it -- speedns run --assert p95<=50ms.
var requireConditions = map[string]func(Diff) (bool, string){
	"no-new-failed-targets": func(d Diff) (bool, string) {
		before, after := d.Baseline.resultByID(), d.Current.resultByID()
		for _, finding := range d.Findings {
			current, inCurrent := after[finding.TargetID]
			if detail, failed := newlyFailed(finding, before[finding.TargetID], current, inCurrent); failed {
				return false, fmt.Sprintf("%s: %s", safetext.Escape(finding.TargetID), safetext.Escape(detail))
			}
		}
		return true, "no target stopped answering or failed to open, and no added target failed outright"
	},
	"no-removed-targets": func(d Diff) (bool, string) {
		for _, finding := range d.Findings {
			if finding.Code == "PRESENCE" && strings.Contains(finding.Detail, "baseline") {
				return false, fmt.Sprintf("%s is absent from the current run", safetext.Escape(finding.TargetID))
			}
		}
		return true, "every baseline target is present in the current run"
	},
	"target-set-identical": func(d Diff) (bool, string) {
		for _, finding := range d.Findings {
			if finding.Code == "PRESENCE" {
				// A PRESENCE detail is a fixed phrase today; escaping it is
				// defensive, so a future detail that quotes a report cannot leak.
				return false, fmt.Sprintf("%s: %s", safetext.Escape(finding.TargetID), safetext.Escape(finding.Detail))
			}
		}
		return true, "both runs measured the same targets"
	},
	"no-dnssec-regression": func(d Diff) (bool, string) {
		for _, finding := range d.Findings {
			if finding.Code == "DNSSEC" && strings.Contains(finding.Detail, "-> not-validating") {
				return false, fmt.Sprintf("%s stopped validating", safetext.Escape(finding.TargetID))
			}
		}
		return true, "no target stopped validating"
	},
	"no-behaviour-change": func(d Diff) (bool, string) {
		if len(d.Findings) > 0 {
			return false, fmt.Sprintf("%d finding(s) reported", len(d.Findings))
		}
		return true, "no findings"
	},
}

// RequireNames lists the accepted conditions, for help text and error messages.
func RequireNames() []string {
	names := make([]string, 0, len(requireConditions))
	for name := range requireConditions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Require evaluates named conditions against a diff. Its results decide nothing
// on a diff that is not comparable, and a pass decides nothing on a diff that
// compared no endpoint: a gate that cannot evaluate must not report a pass, so
// the caller exits 3 for both instead.
func Require(diff Diff, names []string) ([]RequireResult, error) {
	results := make([]RequireResult, 0, len(names))
	for _, name := range names {
		condition, known := requireConditions[name]
		if !known {
			return nil, fmt.Errorf("unknown --require condition %q; choose one of %s", name, strings.Join(RequireNames(), ", "))
		}
		passed, detail := condition(diff)
		results = append(results, RequireResult{Name: name, Passed: passed, Detail: detail})
	}
	return results, nil
}

// Outcomes of a --require condition as the gate decided it.
const (
	OutcomePassed = "passed"
	OutcomeFailed = "failed"
	// OutcomeNotEvaluated is a condition the gate could not evaluate: the runs
	// were not comparable, or no endpoint was compared. It is never a pass.
	OutcomeNotEvaluated = "not-evaluated"
)

// Condition is one --require condition as the compare JSON records it. Passed
// is true only for OutcomePassed, so a consumer that reads nothing else still
// fails closed.
type Condition struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// Conditions turns the results of Require into the gate's verdict on each
// condition, which is also what decides the exit status. A condition's own
// result is not that verdict: on a refused diff every condition reads no
// findings and holds, and on a diff that compared no endpoint a condition
// that holds read no paired count, so both are recorded as not evaluated --
// a gate that could not evaluate must never report a pass. A condition that
// failed on such a pair still failed: a target missing from one run is a real
// finding that needs no pairing.
func Conditions(diff Diff, results []RequireResult) []Condition {
	conditions := make([]Condition, 0, len(results))
	for _, result := range results {
		condition := Condition{Name: result.Name, Outcome: OutcomeFailed, Detail: result.Detail}
		switch {
		case !diff.Comparable():
			condition.Outcome = OutcomeNotEvaluated
			condition.Detail = "not evaluated: the runs are not comparable"
		case !result.Passed:
		case diff.Compared == 0:
			condition.Outcome = OutcomeNotEvaluated
			condition.Detail = fmt.Sprintf("not evaluated: no endpoint was compared (%s)", NotComparedSummary(diff))
		default:
			condition.Passed, condition.Outcome = true, OutcomePassed
		}
		conditions = append(conditions, condition)
	}
	return conditions
}

// NotComparedSummary names why a diff compared no endpoint, counting each
// reason, so a refused gate says what to fix rather than only that it refused.
// With nothing compared the only suppressions are the per-target ones that
// precede pairing, and every remaining target was present in one run only.
func NotComparedSummary(diff Diff) string {
	counts := make(map[string]int)
	for _, suppression := range diff.Suppressions {
		counts[suppression.Reason]++
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	parts := make([]string, 0, len(reasons)+1)
	for _, reason := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", counts[reason], reason))
	}
	unpaired := 0
	for _, finding := range diff.Findings {
		if finding.Code == "PRESENCE" {
			unpaired++
		}
	}
	if unpaired > 0 {
		parts = append(parts, fmt.Sprintf("%d present in only one run", unpaired))
	}
	if len(parts) == 0 {
		return "neither run has a target"
	}
	return strings.Join(parts, ", ")
}

// newlyFailed reports whether a finding records a target the current run lost.
//
// OPEN and FAILED are reported in both directions, because the diff answers
// whether a resolver behaved differently and a recovery is a difference. It is
// not a failure, though: a baseline saved during an outage would otherwise fail
// the gate exactly when the resolver came back. So only the healthy-to-failed
// direction counts here, and the findings themselves stay two-way.
//
// A target present only in the current run has no baseline to regress from,
// but one that failed every query is a failed target the run introduced, and
// passing it would let a dead resolver into a gated set unnoticed. Local and
// interrupted targets are exempt, as they are from every paired comparison: a
// local resolver is never compared, and an interrupted target has proved
// nothing. Redacted identities never reach PRESENCE.
func newlyFailed(finding Finding, baseline, current Result, inCurrent bool) (string, bool) {
	switch finding.Code {
	case "FAILED":
		return finding.Detail, baseline.Stats.Successes > 0 && current.Stats.Successes == 0
	case "OPEN":
		return finding.Detail, baseline.OpenError == "" && current.OpenError != ""
	case "PRESENCE":
		if inCurrent && current.Stats.Successes == 0 && !current.Incomplete && !current.Target.Local {
			return fmt.Sprintf("%s, with successes 0 of %d", finding.Detail, current.Stats.Total), true
		}
	}
	return "", false
}
