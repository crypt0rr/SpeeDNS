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

// assertTarget builds one measured endpoint. Callers set the fields that decide
// reachability; the engine only scores a sample it also counted as usable
// (internal/benchmark/benchmark.go:978,991), so every fixture here keeps
// UsableResponses >= Scored the way a real run does.
func assertTarget(id string, protocol catalog.Protocol, local bool, stats benchmark.Statistics) benchmark.TargetResult {
	return benchmark.TargetResult{
		Target: catalog.Target{
			Resolver: catalog.ResolverProfile{ID: id, Name: id, Owner: "Owner", Policy: "unfiltered", Local: local},
			Protocol: protocol,
			Address:  "192.0.2.1",
			Spec:     catalog.TransportSpec{Port: 53},
		},
		Stats: stats,
	}
}

// TestDeadProtocolsFiresOnlyOnUnreachableTransports is the core of #106: an
// entire transport failing must not be a quieter result than one degrading.
// The cases that must NOT fire matter more than the one that must — an
// over-eager gate would fail healthy CI runs.
func TestDeadProtocolsFiresOnlyOnUnreachableTransports(t *testing.T) {
	healthy := benchmark.Statistics{Total: 6, Successes: 6, UsableResponses: 6, Scored: 6, SuccessRate: 1, UsableRate: 1}
	dead := benchmark.Statistics{Total: 6, Failures: 6, FailureRate: 1}

	// A resolver that answers every query but re-dials for each one has every
	// sample excluded from latency scoring, so it is unranked while being
	// perfectly healthy. Keying the gate on a missing ranking would fail it.
	reconnecting := benchmark.Statistics{Total: 6, Successes: 6, UsableResponses: 6, Reconnects: 6, Scored: 0, SuccessRate: 1, UsableRate: 1}

	// Responses arrive but none are usable: the transport is up, the resolver
	// is not answering usefully. Still a dead protocol for gate purposes,
	// matching the report's own allResponsesUnusable warning.
	unusable := benchmark.Statistics{Total: 6, Successes: 6, UsableResponses: 0, ResolverFailures: 6, SuccessRate: 1}

	for _, testCase := range []struct {
		name    string
		targets []benchmark.TargetResult
		want    []catalog.Protocol
	}{
		{"every endpoint dead", []benchmark.TargetResult{assertTarget("a", catalog.DoQ, false, dead)}, []catalog.Protocol{catalog.DoQ}},
		{"no usable responses", []benchmark.TargetResult{assertTarget("a", catalog.DoT, false, unusable)}, []catalog.Protocol{catalog.DoT}},
		{"healthy", []benchmark.TargetResult{assertTarget("a", catalog.UDP, false, healthy)}, nil},
		{"healthy but unranked by reconnects", []benchmark.TargetResult{assertTarget("a", catalog.DoH, false, reconnecting)}, nil},
		{"one endpoint of two survives", []benchmark.TargetResult{
			assertTarget("a", catalog.UDP, false, dead),
			assertTarget("b", catalog.UDP, false, healthy),
		}, nil},
		{"local resolvers never make a protocol required", []benchmark.TargetResult{
			assertTarget("stub", catalog.UDP, true, dead),
		}, nil},
		{"an interrupted run has proved nothing", []benchmark.TargetResult{
			assertTarget("a", catalog.TCP, false, benchmark.Statistics{}),
		}, nil},
		{"reported in documented order, not lexicographic", []benchmark.TargetResult{
			assertTarget("a", catalog.DoQ, false, dead),
			assertTarget("b", catalog.UDP, false, dead),
			assertTarget("c", catalog.DoH, false, dead),
		}, []catalog.Protocol{catalog.UDP, catalog.DoH, catalog.DoQ}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := deadProtocols(benchmark.Report{Targets: testCase.targets})
			if len(got) != len(testCase.want) {
				t.Fatalf("deadProtocols = %v, want %v", got, testCase.want)
			}
			for i := range testCase.want {
				if got[i] != testCase.want[i] {
					t.Fatalf("deadProtocols = %v, want %v", got, testCase.want)
				}
			}
		})
	}
}

// TestEvaluateAssertionsReportsDeadTransportsFirst pins the wiring: the
// structural failure leads the message, ordinary checks follow, and a run with
// no assertions is still not an error however dead the transports are.
func TestEvaluateAssertionsReportsDeadTransportsFirst(t *testing.T) {
	good := assertTarget("good", catalog.UDP, false, benchmark.Statistics{
		Total: 6, Successes: 6, UsableResponses: 6, Scored: 6, SuccessRate: 1, UsableRate: 0.5, P95MS: 90,
	})
	bad := assertTarget("bad", catalog.DoQ, false, benchmark.Statistics{Total: 6, Failures: 6, FailureRate: 1})
	report := benchmark.Report{
		Targets:  []benchmark.TargetResult{good, bad},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: good.Target.ID(), Rank: 1}},
	}

	// Without assertions the run is not a gate, so nothing is reported.
	if err := evaluateAssertions(report, nil); err != nil {
		t.Fatalf("a run with no assertions must not fail: %v", err)
	}

	checks, err := parseAssertions([]string{"usable>=0.99"})
	if err != nil {
		t.Fatal(err)
	}
	err = evaluateAssertions(report, checks)
	if err == nil || !errors.Is(err, ErrAssertionsFailed) {
		t.Fatalf("dead transport error = %v", err)
	}
	message := err.Error()
	structural := strings.Index(message, "no doq endpoint returned a usable DNS response")
	numeric := strings.Index(message, "usable>=0.99")
	if structural < 0 || numeric < 0 {
		t.Fatalf("both failures must be reported: %q", message)
	}
	if structural > numeric {
		t.Fatalf("the structural failure must lead the message: %q", message)
	}
}

// TestNumericAssertionsTargetRankOneOnly pins #107. A numeric threshold must
// apply to one deterministic target per protocol, not to the whole
// confidence-interval tie group whose size is decided by network noise.
//
// `winner=` deliberately keeps tie-group membership: it asks whether a resolver
// won, and a tie means the run cannot say it did not. The two questions differ,
// so the two assertion kinds differ.
func TestNumericAssertionsTargetRankOneOnly(t *testing.T) {
	leader := assertTarget("leader", catalog.UDP, false, benchmark.Statistics{
		Total: 30, Successes: 30, UsableResponses: 30, Scored: 30, SuccessRate: 1, UsableRate: 1, P95MS: 10,
	})
	// Statistically tied with the leader, but far slower. Under the old
	// semantics this target alone decided whether p95<50ms held.
	tied := assertTarget("tied", catalog.UDP, false, benchmark.Statistics{
		Total: 30, Successes: 30, UsableResponses: 30, Scored: 30, SuccessRate: 1, UsableRate: 1, P95MS: 900,
	})
	report := benchmark.Report{
		Targets: []benchmark.TargetResult{leader, tied},
		Rankings: []benchmark.Ranking{
			{Protocol: catalog.UDP, TargetID: leader.Target.ID(), Rank: 1},
			{Protocol: catalog.UDP, TargetID: tied.Target.ID(), Rank: 2, Tie: true},
		},
	}

	numeric, err := parseAssertions([]string{"p95<50ms"})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluateAssertions(report, numeric); err != nil {
		t.Fatalf("a numeric assertion must hold for the rank-one target only: %v", err)
	}

	// The rank-one target failing still fails, so this is not simply leniency.
	slowLeader := report
	slowLeader.Targets = []benchmark.TargetResult{
		assertTarget("leader", catalog.UDP, false, benchmark.Statistics{
			Total: 30, Successes: 30, UsableResponses: 30, Scored: 30, SuccessRate: 1, UsableRate: 1, P95MS: 900,
		}),
		tied,
	}
	if err := evaluateAssertions(slowLeader, numeric); err == nil ||
		!strings.Contains(err.Error(), "winner leader") {
		t.Fatalf("a failing rank-one target must fail the gate: %v", err)
	}

	// winner= still accepts any tie-group member, as METHODOLOGY documents.
	tieWinner, err := parseAssertions([]string{"winner=tied"})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluateAssertions(report, tieWinner); err != nil {
		t.Fatalf("winner= must still accept a tie-group member: %v", err)
	}

	// A ranking set with tie members but no rank-one entry cannot come from
	// makeRankings, but a numeric threshold must never be silently skipped, so
	// the malformed report is reported rather than passed over.
	malformed := report
	malformed.Rankings = []benchmark.Ranking{
		{Protocol: catalog.UDP, TargetID: tied.Target.ID(), Rank: 2, Tie: true},
	}
	if err := evaluateAssertions(malformed, numeric); err == nil ||
		!strings.Contains(err.Error(), "produced no rank-one target to check") {
		t.Fatalf("malformed ranking set = %v", err)
	}

	// A protocol that ranked nothing contributes no numeric reason; the dead
	// transport rule from #106 owns that case.
	unranked := benchmark.Report{Targets: []benchmark.TargetResult{leader}}
	if err := evaluateAssertions(unranked, numeric); err == nil ||
		!strings.Contains(err.Error(), "has no ranked protocol winners") {
		t.Fatalf("unranked report = %v", err)
	}
}
