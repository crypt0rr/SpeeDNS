package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

func TestParseAssertions(t *testing.T) {
	parsed, err := parseAssertions([]string{
		"usable>=0.99",
		"success=1",
		"p95<50ms",
		"median<=1.5s",
		"score>10",
		"winner=quad9-9999",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 6 || parsed[0].value != 0.99 || parsed[2].value != 50 || parsed[3].value != 1500 || parsed[5].kind != winnerAssertion {
		t.Fatalf("parsed assertions = %#v", parsed)
	}
	if _, err := parseAssertions([]string{"bad"}); err == nil {
		t.Fatal("parseAssertions accepted an invalid expression")
	}

	for _, expression := range []string{
		"",
		"usable>=1.1",
		"usable>=99%",
		"p95<fast",
		"p95<-1ms",
		"usable>=0.99ms",
		"p95==50ms",
		"unknown=1",
		"winner>quad9-9999",
		"winner==quad9-9999",
		"winner=",
		"winner=two words",
	} {
		if _, err := parseAssertion(expression); err == nil {
			t.Fatalf("parseAssertion(%q) unexpectedly succeeded", expression)
		}
	}
}

func TestEvaluateAssertionsAcrossProtocols(t *testing.T) {
	udpWinner := assertionTarget("quad9-9999", catalog.UDP, "9.9.9.9")
	dohWinner := assertionTarget("quad9-9999", catalog.DoH, "9.9.9.9")
	udpOther := assertionTarget("cloudflare-1111", catalog.UDP, "1.1.1.1")
	report := benchmark.Report{
		Targets: []benchmark.TargetResult{
			{Target: udpWinner, Stats: benchmark.Statistics{UsableRate: 1, SuccessRate: 1, MedianMS: 12, P95MS: 30, ScoreMS: 20}},
			{Target: dohWinner, Stats: benchmark.Statistics{UsableRate: 0.995, SuccessRate: 1, MedianMS: 14, P95MS: 40, ScoreMS: 25}},
			{Target: udpOther, Stats: benchmark.Statistics{UsableRate: 1, SuccessRate: 1, MedianMS: 20, P95MS: 60, ScoreMS: 35}},
		},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.UDP, TargetID: udpWinner.ID(), Rank: 1, Tie: true},
			{Protocol: catalog.UDP, TargetID: udpOther.ID(), Rank: 2},
			{Protocol: catalog.DoH, TargetID: dohWinner.ID(), Rank: 1},
		},
	}

	assertions, err := parseAssertions([]string{"usable>=0.99", "success=1", "median<=14ms", "p95<50ms", "score>10ms", "winner=quad9-9999"})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluateAssertions(report, assertions); err != nil {
		t.Fatalf("evaluateAssertions() = %v", err)
	}

	failed, err := parseAssertions([]string{"p95<20ms", "usable>=1", "winner=cloudflare-1111"})
	if err != nil {
		t.Fatal(err)
	}
	err = evaluateAssertions(report, failed)
	if !errors.Is(err, ErrAssertionsFailed) || !strings.Contains(err.Error(), "assertion failed") || !strings.Contains(err.Error(), "p95<20ms") || !strings.Contains(err.Error(), "usable>=1") || !strings.Contains(err.Error(), "winner=cloudflare-1111") {
		t.Fatalf("failed assertions error = %v", err)
	}
}

func TestAssertionHelpersRejectUnknownState(t *testing.T) {
	if _, ok := assertionMetricValue(benchmark.TargetResult{}, "unknown"); ok {
		t.Fatal("unknown assertion metric unexpectedly succeeded")
	}
	if assertionComparison(1, "?", 1) {
		t.Fatal("unknown assertion operator unexpectedly succeeded")
	}
	if got := assertionActualText("usable", 0.5); got != "0.500" {
		t.Fatalf("rate assertion text = %q", got)
	}
	if err := evaluateAssertions(benchmark.Report{}, []assertion{{raw: "p95<1ms", kind: numericAssertion, metric: "p95", operator: "<", value: 1}}); !errors.Is(err, ErrAssertionsFailed) || !strings.Contains(err.Error(), "no ranked protocol winners") {
		t.Fatalf("empty report assertion error = %v", err)
	}
}

func TestEvaluateAssertionsAcceptsTiedWinners(t *testing.T) {
	first := assertionTarget("first", catalog.UDP, "192.0.2.1")
	second := assertionTarget("second", catalog.UDP, "192.0.2.2")
	report := benchmark.Report{
		Targets: []benchmark.TargetResult{
			{Target: first, Stats: benchmark.Statistics{UsableRate: 1, P95MS: 10}},
			{Target: second, Stats: benchmark.Statistics{UsableRate: 1, P95MS: 10}},
		},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.UDP, TargetID: first.ID(), Rank: 1, Tie: true},
			{Protocol: catalog.UDP, TargetID: second.ID(), Rank: 2, Tie: true},
		},
	}
	assertions, err := parseAssertions([]string{"winner=second"})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluateAssertions(report, assertions); err != nil {
		t.Fatalf("tied winner assertion = %v", err)
	}
}

func TestValidateAssertionTargetsRejectsUnknownWinners(t *testing.T) {
	targets := []catalog.Target{
		assertionTarget("first", catalog.UDP, "192.0.2.1"),
		assertionTarget("second", catalog.TCP, "192.0.2.2"),
	}
	accepted, err := parseAssertions([]string{"p95<50ms", "winner=second", "winner=" + targets[0].ID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAssertionTargets(accepted, targets); err != nil {
		t.Fatalf("validateAssertionTargets() = %v", err)
	}

	rejected, err := parseAssertions([]string{"winner=secnod"})
	if err != nil {
		t.Fatal(err)
	}
	err = validateAssertionTargets(rejected, targets)
	if err == nil || !strings.Contains(err.Error(), "no selected resolver matches") || !strings.Contains(err.Error(), "secnod") {
		t.Fatalf("unknown winner error = %v", err)
	}
	if errors.Is(err, ErrAssertionsFailed) {
		t.Fatal("an unknown winner is invalid input, not a failed assertion")
	}

	// A profile that is filtered out of the run, for example by --protocol,
	// must be rejected rather than silently reported as a loser.
	if err := validateAssertionTargets(rejected, targets[:1]); err == nil {
		t.Fatal("expected unknown winner error against the reduced target set")
	}
	unselected, err := parseAssertions([]string{"winner=second"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAssertionTargets(unselected, targets[:1]); err == nil {
		t.Fatal("expected error for a profile that is not part of the run")
	}
}

func assertionTarget(id string, protocol catalog.Protocol, address string) catalog.Target {
	return catalog.Target{
		Resolver: catalog.ResolverProfile{ID: id, Name: id, Owner: "Test", Policy: "unfiltered"},
		Protocol: protocol,
		Address:  address,
		Spec:     catalog.TransportSpec{Port: 53},
	}
}
