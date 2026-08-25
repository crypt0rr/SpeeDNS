package compare

import (
	"fmt"
	"math"
	"sort"
)

// Finding is one difference in what a resolver did.
type Finding struct {
	Code     string `json:"code"`
	TargetID string `json:"target_id"`
	Detail   string `json:"detail"`
}

// Suppression records a comparison the tool declined to make, and why. Every
// declined comparison is named: silence would leave the reader unable to tell
// "nothing changed" from "this was not checked".
type Suppression struct {
	Reason string `json:"reason"`
	Scope  string `json:"scope"`
	Detail string `json:"detail"`
}

// Diff is the whole answer.
type Diff struct {
	Baseline        Report
	Current         Report
	Blockers        []Blocker
	Findings        []Finding
	Suppressions    []Suppression
	Disclosures     []Disclosure
	AddedWarnings   []string
	RemovedWarnings []string
	Compared        int
}

// Comparable reports whether a comparison was produced at all.
func (d Diff) Comparable() bool { return len(d.Blockers) == 0 }

// responseFloor is the smallest count movement treated as a real difference.
//
// It spends exactly the budget the project already declares acceptable:
// MinimumRecommendedSuccessRate is 0.99, so a run may lose 1% of its responses
// and still be called qualified. The floor of 2 is empirical -- the observed
// run-to-run amplitude of every categorical count across identical runs was
// 0 to 1 responses, and 2 is the smallest integer strictly above that.
func responseFloor(total int) int {
	floor := int(math.Ceil(0.01 * float64(total)))
	if floor < 2 {
		return 2
	}
	return floor
}

// Compare produces the diff. It reports what each resolver did and never how
// fast it did it; see the package comment for why.
func Compare(baseline, current Report) Diff {
	diff := Diff{Baseline: baseline, Current: current, Blockers: Gate(baseline, current)}
	diff.Findings = make([]Finding, 0)
	diff.Suppressions = make([]Suppression, 0)
	if !diff.Comparable() {
		return diff
	}
	diff.Disclosures = Disclosures(baseline, current)
	diff.AddedWarnings, diff.RemovedWarnings = setDifference(baseline.Warnings, current.Warnings)

	before, after := baseline.resultByID(), current.resultByID()
	for _, id := range sortedTargetIDs(before, after) {
		baselineResult, inBaseline := before[id]
		currentResult, inCurrent := after[id]

		// A redacted identity is assigned by position, so the same label can
		// name different resolvers in two runs. Never pair on it.
		if isRedacted(id) {
			diff.Suppressions = append(diff.Suppressions, Suppression{"redacted-identity", id,
				"redacted target identities are assigned by position, so the same label may name a different resolver in each run"})
			continue
		}
		if !inBaseline || !inCurrent {
			side := "only in the current run"
			if inBaseline {
				side = "only in the baseline run"
			}
			diff.Findings = append(diff.Findings, Finding{"PRESENCE", id, side})
			continue
		}
		if baselineResult.Target.Local || currentResult.Target.Local {
			diff.Suppressions = append(diff.Suppressions, Suppression{"local-position", id,
				"a resolver on the measuring host answers from its own cache, so it is never compared"})
			continue
		}
		if baselineResult.Incomplete || currentResult.Incomplete {
			diff.Suppressions = append(diff.Suppressions, Suppression{"incomplete-target", id,
				"an interrupted run measured only part of its matrix, so its counts are not comparable"})
			continue
		}
		diff.Compared++
		diff.appendTargetFindings(id, baselineResult, currentResult)
	}
	sort.SliceStable(diff.Findings, func(i, j int) bool {
		if diff.Findings[i].TargetID != diff.Findings[j].TargetID {
			return diff.Findings[i].TargetID < diff.Findings[j].TargetID
		}
		return diff.Findings[i].Code < diff.Findings[j].Code
	})
	return diff
}

func (d *Diff) appendTargetFindings(id string, baseline, current Result) {
	// Hard facts: no floor applies, because a single lost datagram cannot
	// produce any of them.
	if (baseline.OpenError == "") != (current.OpenError == "") {
		detail := fmt.Sprintf("opened -> %s", orDash(current.OpenError))
		if current.OpenError == "" {
			detail = fmt.Sprintf("%s -> opened", orDash(baseline.OpenError))
		}
		d.Findings = append(d.Findings, Finding{"OPEN", id, detail})
	}
	if (baseline.Stats.Successes == 0) != (current.Stats.Successes == 0) {
		d.Findings = append(d.Findings, Finding{"FAILED", id,
			fmt.Sprintf("successes %d -> %d", baseline.Stats.Successes, current.Stats.Successes)})
	}
	if baseline.Stats.Total != current.Stats.Total {
		// The denominator moved, so every rate below is over a different base.
		d.Findings = append(d.Findings, Finding{"QUERIES", id,
			fmt.Sprintf("measured queries %d -> %d", baseline.Stats.Total, current.Stats.Total)})
		d.Suppressions = append(d.Suppressions, Suppression{"denominator-mismatch", id,
			"the two runs measured a different number of queries for this target, so its counts are not on the same base"})
		return
	}

	floor := responseFloor(maxInt(baseline.Stats.Total, current.Stats.Total))
	for _, counter := range []struct {
		code          string
		before, after int
		label         string
	}{
		{"USABLE", baseline.Stats.UsableResponses, current.Stats.UsableResponses, "usable responses"},
		{"ANSWERS", baseline.Stats.Answers, current.Stats.Answers, "answers carrying a record"},
		{"TRUNCATED", baseline.Stats.Truncated, current.Stats.Truncated, "truncated responses"},
	} {
		if absInt(counter.after-counter.before) >= floor {
			d.Findings = append(d.Findings, Finding{counter.code, id,
				fmt.Sprintf("%s %d -> %d of %d (floor %d)", counter.label, counter.before, counter.after, current.Stats.Total, floor)})
		}
	}
	for _, code := range sortedRCodes(baseline.Stats.RCodeCounts, current.Stats.RCodeCounts) {
		before, after := baseline.Stats.RCodeCounts[code], current.Stats.RCodeCounts[code]
		if absInt(after-before) >= floor {
			d.Findings = append(d.Findings, Finding{"RCODE", id,
				fmt.Sprintf("%s %d -> %d of %d (floor %d)", code, before, after, current.Stats.Total, floor)})
		}
	}
	d.appendStatusFinding(id, baseline, current, floor)
	d.appendDNSSECFinding(id, baseline, current)
}

// appendStatusFinding reports a status change only when the count that decided
// it also moved beyond the floor.
//
// Status is a threshold applied to a measured count, so it flips on noise: a
// target at 198/200 usable responses is qualified and one at 197/200 is not,
// and one dropped datagram moves between them. Reporting that as
// "QUALIFIED -> INELIGIBLE" would manufacture a behaviour change out of a
// single lost packet.
func (d *Diff) appendStatusFinding(id string, baseline, current Result, floor int) {
	if baseline.Status == current.Status {
		return
	}
	// Scored contains divergent, which is a plurality vote over the targets
	// present, so a status flip attributable to it is a property of the cohort
	// rather than of this resolver.
	if baseline.Stats.Scored != current.Stats.Scored &&
		(baseline.Status == "qualified") != (current.Status == "qualified") &&
		absInt(current.Stats.Scored-baseline.Stats.Scored) < floor {
		d.Suppressions = append(d.Suppressions, Suppression{"peer-relative", id,
			fmt.Sprintf("status %s -> %s not reported: it turns on scored %d -> %d, and scored excludes divergent responses, which are decided by the other targets present",
				baseline.Status, current.Status, baseline.Stats.Scored, current.Stats.Scored)})
		return
	}
	if isQualificationFlip(baseline.Status, current.Status) &&
		absInt(current.Stats.UsableResponses-baseline.Stats.UsableResponses) < floor {
		d.Suppressions = append(d.Suppressions, Suppression{"boundary-crossing", id,
			fmt.Sprintf("status %s -> %s not reported: usable %d/%d -> %d/%d is a %d-response crossing of the 99%% bar, below the floor of %d",
				baseline.Status, current.Status,
				baseline.Stats.UsableResponses, baseline.Stats.Total,
				current.Stats.UsableResponses, current.Stats.Total,
				absInt(current.Stats.UsableResponses-baseline.Stats.UsableResponses), floor)})
		return
	}
	d.Findings = append(d.Findings, Finding{"STATUS", id,
		fmt.Sprintf("%s -> %s (usable %d/%d -> %d/%d)", baseline.Status, current.Status,
			baseline.Stats.UsableResponses, baseline.Stats.Total,
			current.Stats.UsableResponses, current.Stats.Total)})
}

// appendDNSSECFinding reports only a decided verdict changing to the other
// decided verdict. A probe that failed to complete yields "inconclusive" from a
// single lost packet, so a transition touching it is disclosed rather than
// reported as a validation change.
func (d *Diff) appendDNSSECFinding(id string, baseline, current Result) {
	before, after := verdictOf(baseline), verdictOf(current)
	if before == after {
		return
	}
	decided := func(verdict string) bool { return verdict == "validating" || verdict == "not-validating" }
	if decided(before) && decided(after) {
		d.Findings = append(d.Findings, Finding{"DNSSEC", id, fmt.Sprintf("%s -> %s", before, after)})
		return
	}
	d.Suppressions = append(d.Suppressions, Suppression{"probe-incomplete", id,
		fmt.Sprintf("DNSSEC verdict %s -> %s: a probe that does not complete reports inconclusive, which is not a validation change", orDash(before), orDash(after))})
}

func verdictOf(result Result) string {
	if result.DNSSEC == nil {
		return ""
	}
	return result.DNSSEC.Verdict
}

func isQualificationFlip(before, after string) bool {
	pair := map[string]bool{"qualified": true, "ineligible": true}
	return pair[before] && pair[after]
}

func isRedacted(id string) bool {
	const redactedPrefix = "system-redacted"
	return len(id) >= len(redactedPrefix) && id[:len(redactedPrefix)] == redactedPrefix
}

func sortedTargetIDs(before, after map[string]Result) []string {
	seen := make(map[string]bool, len(before)+len(after))
	ids := make([]string, 0, len(before)+len(after))
	for _, index := range []map[string]Result{before, after} {
		for id := range index {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func sortedRCodes(before, after map[string]int) []string {
	seen := make(map[string]bool, len(before)+len(after))
	codes := make([]string, 0, len(before)+len(after))
	for _, index := range []map[string]int{before, after} {
		for code := range index {
			if !seen[code] {
				seen[code] = true
				codes = append(codes, code)
			}
		}
	}
	sort.Strings(codes)
	return codes
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
