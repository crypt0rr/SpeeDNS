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
			for _, winner := range winners[protocol] {
				actual, ok := assertionMetricValue(winner, check.metric)
				if !ok || !assertionComparison(actual, check.operator, check.value) {
					reasons = append(reasons, fmt.Sprintf("%s: %s winner %s has %s=%s", check.raw, protocol, winner.Target.ID(), check.metric, assertionActualText(check.metric, actual)))
				}
			}
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrAssertionsFailed, strings.Join(reasons, "; "))
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
