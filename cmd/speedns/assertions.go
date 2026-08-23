package main

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// ErrAssertionsFailed is returned after a report has been written when one or
// more user-supplied benchmark assertions do not hold.
var ErrAssertionsFailed = errors.New("assertion failed")

type assertion struct {
	raw      string
	kind     assertionKind
	metric   string
	operator string
	value    float64
	winner   string
}

type assertionKind uint8

const (
	numericAssertion assertionKind = iota
	winnerAssertion
)

var assertionOperators = []string{">=", "<=", ">", "<", "="}

func parseAssertions(values []string) ([]assertion, error) {
	assertions := make([]assertion, 0, len(values))
	for _, value := range values {
		parsed, err := parseAssertion(value)
		if err != nil {
			return nil, err
		}
		assertions = append(assertions, parsed)
	}
	return assertions, nil
}

func parseAssertion(value string) (assertion, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return assertion{}, fmt.Errorf("invalid --assert %q: expression is empty", value)
	}
	left, operator, right, ok := splitAssertion(raw)
	if !ok {
		return assertion{}, fmt.Errorf("invalid --assert %q: expected METRIC[operator]VALUE or winner=PROFILE-ID", value)
	}
	left = strings.ToLower(strings.TrimSpace(left))
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return assertion{}, fmt.Errorf("invalid --assert %q: metric and value are required", value)
	}
	if left == "winner" {
		if operator != "=" || strings.ContainsAny(right, " \t\r\n=") {
			return assertion{}, fmt.Errorf("invalid --assert %q: winner uses winner=PROFILE-ID", value)
		}
		return assertion{raw: raw, kind: winnerAssertion, winner: right}, nil
	}
	if operator == "=" && strings.HasPrefix(right, "=") {
		return assertion{}, fmt.Errorf("invalid --assert %q: malformed operator", value)
	}
	if left != "usable" && left != "success" && left != "median" && left != "p95" && left != "score" {
		return assertion{}, fmt.Errorf("invalid --assert %q: unsupported metric %q", value, left)
	}
	threshold, err := parseAssertionValue(left, right)
	if err != nil {
		return assertion{}, fmt.Errorf("invalid --assert %q: %w", value, err)
	}
	return assertion{raw: raw, kind: numericAssertion, metric: left, operator: operator, value: threshold}, nil
}

func splitAssertion(value string) (left, operator, right string, ok bool) {
	for _, candidate := range assertionOperators {
		if index := strings.Index(value, candidate); index > 0 {
			return value[:index], candidate, value[index+len(candidate):], true
		}
	}
	return "", "", "", false
}

func parseAssertionValue(metric, value string) (float64, error) {
	if metric == "usable" || metric == "success" {
		threshold, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 || threshold > 1 {
			return 0, errors.New("rate thresholds must be numbers between 0 and 1")
		}
		return threshold, nil
	}
	threshold, err := parseLatencyMilliseconds(value)
	if err != nil {
		return 0, err
	}
	if threshold < 0 || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return 0, errors.New("latency thresholds must be finite and non-negative")
	}
	return threshold, nil
}

func parseLatencyMilliseconds(value string) (float64, error) {
	if duration, err := time.ParseDuration(value); err == nil {
		return float64(duration) / float64(time.Millisecond), nil
	}
	threshold, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, errors.New("latency thresholds must be durations such as 50ms or non-negative milliseconds")
	}
	return threshold, nil
}

// validateAssertionTargets rejects a winner assertion whose ID matches none of
// the targets selected for the run. Without this check a mistyped profile or
// target ID is reported as a lost benchmark instead of the invalid input it
// is, telling the user their resolver did not win when it was never measured.
func validateAssertionTargets(assertions []assertion, targets []catalog.Target) error {
	for _, check := range assertions {
		if check.kind != winnerAssertion {
			continue
		}
		matched := false
		for _, target := range targets {
			if targetMatchesID(target, check.winner) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("invalid --assert %q: no selected resolver matches %q; use a profile id such as the ones listed by \"speedns resolvers\" or a target id", check.raw, check.winner)
		}
	}
	return nil
}

func evaluateAssertions(report benchmark.Report, assertions []assertion) error {
	if len(assertions) == 0 {
		return nil
	}
	reasons := make([]string, 0)
	winners := reportWinners(report)
	leaders := rankOneWinners(report)
	// A transport that failed outright must not be a quieter result than one
	// that merely degraded. Reported before the individual checks so the
	// structural failure leads the message.
	for _, protocol := range deadProtocols(report) {
		reasons = append(reasons, fmt.Sprintf("no %s endpoint returned a usable DNS response", protocol))
	}
	for _, check := range assertions {
		if len(winners) == 0 {
			reasons = append(reasons, fmt.Sprintf("%s has no ranked protocol winners", check.raw))
			continue
		}
		if check.kind == winnerAssertion {
			for _, protocol := range winnerProtocols(winners) {
				matched := false
				for _, winner := range winners[protocol] {
					if winnerMatches(winner, check.winner) {
						matched = true
						break
					}
				}
				if !matched {
					reasons = append(reasons, fmt.Sprintf("%s does not win %s", check.raw, protocol))
				}
			}
			continue
		}
		for _, protocol := range winnerProtocols(winners) {
			winner, ranked := leaders[protocol]
			if !ranked {
				// The protocol produced rankings -- reportWinners admitted a
				// tie-group member for it -- but no rank-one entry. That is a
				// malformed report rather than a healthy run, and skipping it
				// would leave the threshold silently unchecked, which is the
				// failure mode #106 removed.
				reasons = append(reasons, fmt.Sprintf("%s: %s produced no rank-one target to check", check.raw, protocol))
				continue
			}
			actual, ok := assertionMetricValue(winner, check.metric)
			if !ok || !assertionComparison(actual, check.operator, check.value) {
				reasons = append(reasons, fmt.Sprintf("%s: %s winner %s has %s=%s", check.raw, protocol, winner.Target.ID(), check.metric, assertionActualText(check.metric, actual)))
			}
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAssertionsFailed, strings.Join(reasons, "; "))
}

// deadProtocols returns every protocol whose non-local endpoints all returned
// no usable DNS response at all. Without this, --assert exits 0 when an entire
// selected transport is unreachable, because evaluateAssertions only iterates
// protocols that produced a ranking -- so a dead transport was never examined
// and total failure was quieter than partial degradation.
//
// The test is "no usable response", deliberately not "no ranked winner". A
// resolver that answers every query but re-dials for each one has all of its
// samples excluded from latency scoring, so it is unranked while being
// perfectly healthy; firing on a missing ranking would fail that run. This
// mirrors the allResponsesUnusable condition the report already uses to decide
// that a protocol is worth warning about, so the gate cannot contradict the
// warning printed above it.
//
// Targets with no measured queries at all are treated as alive: an interrupted
// run has not shown that the transport is dead. Resolvers on the local host are
// skipped because they are measured but never ranked, so they must not make
// their protocol required.
func deadProtocols(report benchmark.Report) []catalog.Protocol {
	alive := make(map[catalog.Protocol]bool)
	for _, result := range report.Targets {
		if result.Target.Resolver.Local {
			continue
		}
		protocol := result.Target.Protocol
		if _, measured := alive[protocol]; !measured {
			alive[protocol] = false
		}
		if result.Stats.Total == 0 || result.Stats.UsableResponses != 0 {
			alive[protocol] = true
		}
	}
	dead := make([]catalog.Protocol, 0, len(alive))
	for protocol, reachable := range alive {
		if !reachable {
			dead = append(dead, protocol)
		}
	}
	// Documented measurement order, so a CI failure lists transports the way
	// every other part of the report does.
	sort.Slice(dead, func(i, j int) bool { return catalog.CompareProtocols(dead[i], dead[j]) < 0 })
	return dead
}

// rankOneWinners returns the single rank-one target of each protocol.
//
// reportWinners deliberately admits every confidence-interval tie-group member,
// because `winner=ID` asks whether a resolver won and a tie means the run
// cannot say it did not. Numeric thresholds are a different question. Applying
// `p95<50ms` to the whole tie group makes the number of targets it must hold
// for a function of network noise -- measured against the bundled catalog it
// was 6, 3 and 10 of 10 targets at --sample 3, 10 and 25 -- so the same command
// passes or fails on identical infrastructure. That is non-determinism rather
// than strictness, and it contradicts what README and METHODOLOGY promise.
func rankOneWinners(report benchmark.Report) map[catalog.Protocol]benchmark.TargetResult {
	results := make(map[string]benchmark.TargetResult, len(report.Targets))
	for _, result := range report.Targets {
		results[result.Target.ID()] = result
	}
	leaders := make(map[catalog.Protocol]benchmark.TargetResult)
	for _, ranking := range report.Rankings {
		if ranking.Rank != 1 {
			continue
		}
		if result, ok := results[ranking.TargetID]; ok {
			leaders[ranking.Protocol] = result
		}
	}
	return leaders
}

func reportWinners(report benchmark.Report) map[catalog.Protocol][]benchmark.TargetResult {
	results := make(map[string]benchmark.TargetResult, len(report.Targets))
	for _, result := range report.Targets {
		results[result.Target.ID()] = result
	}
	winners := make(map[catalog.Protocol][]benchmark.TargetResult)
	for _, ranking := range report.Rankings {
		if ranking.Rank != 1 && !ranking.Tie {
			continue
		}
		if result, ok := results[ranking.TargetID]; ok {
			winners[ranking.Protocol] = append(winners[ranking.Protocol], result)
		}
	}
	return winners
}

func winnerProtocols(winners map[catalog.Protocol][]benchmark.TargetResult) []catalog.Protocol {
	protocols := make([]catalog.Protocol, 0, len(winners))
	for protocol := range winners {
		protocols = append(protocols, protocol)
	}
	// Protocol values have a stable string representation, and keeping the
	// diagnostic order deterministic makes CI failures easy to compare.
	sort.Slice(protocols, func(i, j int) bool { return protocols[i].String() < protocols[j].String() })
	return protocols
}

func winnerMatches(result benchmark.TargetResult, expected string) bool {
	return targetMatchesID(result.Target, expected)
}

func targetMatchesID(target catalog.Target, expected string) bool {
	return target.ID() == expected || target.Resolver.ID == expected
}

func assertionMetricValue(result benchmark.TargetResult, metric string) (float64, bool) {
	switch metric {
	case "usable":
		return result.Stats.UsableRate, true
	case "success":
		return result.Stats.SuccessRate, true
	case "median":
		return result.Stats.MedianMS, true
	case "p95":
		return result.Stats.P95MS, true
	case "score":
		return result.Stats.ScoreMS, true
	default:
		return 0, false
	}
}

func assertionComparison(actual float64, operator string, expected float64) bool {
	switch operator {
	case ">=":
		return actual >= expected
	case "<=":
		return actual <= expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	case "=":
		return actual == expected
	default:
		return false
	}
}

func assertionActualText(metric string, value float64) string {
	if metric == "usable" || metric == "success" {
		return strconv.FormatFloat(value, 'f', 3, 64)
	}
	return strconv.FormatFloat(value, 'f', 3, 64) + "ms"
}
