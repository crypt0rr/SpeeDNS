package compare

import (
	"fmt"
	"sort"
	"strings"
)

// RequireResult is the outcome of one named condition.
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
				return false, fmt.Sprintf("%s: %s", finding.TargetID, detail)
			}
		}
		return true, "no target stopped answering or failed to open, and no added target failed outright"
	},
	"no-removed-targets": func(d Diff) (bool, string) {
		for _, finding := range d.Findings {
			if finding.Code == "PRESENCE" && strings.Contains(finding.Detail, "baseline") {
				return false, fmt.Sprintf("%s is absent from the current run", finding.TargetID)
			}
		}
		return true, "every baseline target is present in the current run"
	},
	"target-set-identical": func(d Diff) (bool, string) {
		for _, finding := range d.Findings {
			if finding.Code == "PRESENCE" {
				return false, fmt.Sprintf("%s: %s", finding.TargetID, finding.Detail)
			}
		}
		return true, "both runs measured the same targets"
	},
	"no-dnssec-regression": func(d Diff) (bool, string) {
		for _, finding := range d.Findings {
			if finding.Code == "DNSSEC" && strings.Contains(finding.Detail, "-> not-validating") {
				return false, fmt.Sprintf("%s stopped validating", finding.TargetID)
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
