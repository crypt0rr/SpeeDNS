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
		return noFindingWithCode(d, "FAILED", "OPEN")
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
		return noFindingWithCode(d, "PRESENCE")
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

// Require evaluates named conditions against a diff. It is an error to call it
// on a diff that is not comparable: a gate that cannot evaluate must not report
// a pass, and the caller exits 3 for that case instead.
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

func noFindingWithCode(diff Diff, codes ...string) (bool, string) {
	wanted := make(map[string]bool, len(codes))
	for _, code := range codes {
		wanted[code] = true
	}
	for _, finding := range diff.Findings {
		if wanted[finding.Code] {
			return false, fmt.Sprintf("%s: %s", finding.TargetID, finding.Detail)
		}
	}
	return true, "no target became unreachable"
}
