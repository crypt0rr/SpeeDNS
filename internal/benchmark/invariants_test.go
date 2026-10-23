package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
)

// TestRankingsOrderFastestFirst pins the product's central claim.
//
// Nothing asserted it before. Inverting the comparator in makeRankings ranks the
// slowest resolver first and every gate still passes -- gofmt, vet, the whole
// suite, staticcheck, and the coverage gate at 100.0% -- because coverage proves
// the line ran, never that it computed the right order.
//
// Scores are hand-picked and well separated so no confidence interval can
// overlap and the expected order is unambiguous. The input order is fixed
// rather than shuffled, so a failure reproduces exactly.
func TestRankingsOrderFastestFirst(t *testing.T) {
	scored := func(address string, score float64) TargetResult {
		return TargetResult{
			Target: testTarget(catalog.UDP, address),
			Stats: Statistics{
				Total: 40, Successes: 40, UsableResponses: 40, Scored: 40,
				SuccessRate: 1, UsableRate: 1,
				MedianMS: score, P95MS: score, ScoreMS: score,
				CILowMS: score - 0.5, CIHighMS: score + 0.5,
			},
		}
	}
	// Deliberately not in score order on the way in.
	results := []TargetResult{
		scored("slow", 200),
		scored("fastest", 10),
		scored("middling", 120),
		scored("quick", 50),
	}

	rankings := makeRankings(results, DefaultTimeout)
	if len(rankings) != 4 {
		t.Fatalf("makeRankings returned %d rankings, want 4", len(rankings))
	}
	wantOrder := []struct {
		address string
		rank    int
	}{{"fastest", 1}, {"quick", 2}, {"middling", 3}, {"slow", 4}}
	for index, want := range wantOrder {
		wantID := testTarget(catalog.UDP, want.address).ID()
		got := rankings[index]
		if got.TargetID != wantID || got.Rank != want.rank {
			t.Fatalf("rankings[%d] = {TargetID:%q, Rank:%d}, want {TargetID:%q, Rank:%d}",
				index, got.TargetID, got.Rank, wantID, want.rank)
		}
	}

	// Well-separated scores must not be reported as statistically tied.
	for _, ranking := range rankings {
		if ranking.Tie {
			t.Fatalf("%s was flagged TIED against non-overlapping intervals", ranking.TargetID)
		}
	}
}

// TestRunRanksFastestFirst is the Run-level twin of the test above.
//
// A helper-level test cannot see a correct comparator fed the wrong slice --
// that is exactly how the sample_size regression passed its first test -- so
// the ordering is asserted again on a report the real pipeline produced.
func TestRunRanksFastestFirst(t *testing.T) {
	latency := map[string]float64{"aaa-slow": 90, "bbb-fast": 5}
	useTargetSeam(t, func(_ context.Context, target catalog.Target, queries []Query, opts Options) TargetResult {
		result := TargetResult{Target: target}
		for _, query := range queries {
			result.Observations = append(result.Observations, Observation{
				Name: query.Name, QType: query.QType, Success: true, Usable: true,
				RCode: dns.RcodeSuccess, ResponseClass: "answer",
				LatencyMS: latency[target.Address],
			})
		}
		result.Stats = calculateStatistics(result, opts.Timeout, opts.Seed)
		return result
	})

	options := validBenchmarkOptions()
	options.Sample = 2
	// Alphabetical order puts the slow target first, so a comparator that
	// ignores the score entirely would still fail this.
	report, err := Run(context.Background(), []catalog.Target{
		testTarget(catalog.UDP, "aaa-slow"),
		testTarget(catalog.UDP, "bbb-fast"),
	}, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Rankings) != 2 {
		t.Fatalf("report has %d rankings, want 2", len(report.Rankings))
	}
	if want := testTarget(catalog.UDP, "bbb-fast").ID(); report.Rankings[0].TargetID != want {
		t.Fatalf("rank 1 = %q, want the faster target %q", report.Rankings[0].TargetID, want)
	}
	if report.Rankings[0].Rank != 1 || report.Rankings[1].Rank != 2 {
		t.Fatalf("ranks = %d,%d, want 1,2", report.Rankings[0].Rank, report.Rankings[1].Rank)
	}
}

// TestStatisticsHoldTheirInvariants is a property test over calculateStatistics.
//
// Individual wrong values inside a valid shape are invisible to schema
// validation and to golden fixtures whose adjacent fields happen to be equal.
// These invariants must hold for every input, so they catch a swapped
// assignment or a changed denominator without anyone predicting which field
// would be swapped.
func TestStatisticsHoldTheirInvariants(t *testing.T) {
	random := rand.New(rand.NewSource(20260824))
	for iteration := 0; iteration < 400; iteration++ {
		result := TargetResult{Target: testTarget(catalog.UDP, "invariants")}
		count := 1 + random.Intn(25)
		for index := 0; index < count; index++ {
			observation := Observation{
				Name: fmt.Sprintf("q%02d.example.", index), QType: dns.TypeA,
				LatencyMS: random.Float64() * 250,
			}
			switch random.Intn(5) {
			case 0: // transport failure
				observation.Error = "dial failed"
			case 1: // usable answer
				observation.Success, observation.Usable = true, true
				observation.RCode, observation.ResponseClass = dns.RcodeSuccess, "answer"
			case 2: // resolver error, not usable
				observation.Success = true
				observation.RCode, observation.ResponseClass = dns.RcodeServerFailure, "servfail"
			case 3: // truncated
				observation.Success, observation.Truncated = true, true
			default: // usable but excluded from warm scoring
				observation.Success, observation.Usable = true, true
				observation.RCode, observation.ResponseClass = dns.RcodeSuccess, "answer"
				observation.Reconnected = true
			}
			result.Observations = append(result.Observations, observation)
		}
		stats := calculateStatistics(result, time.Second, 7)

		// The report must always be encodable: a NaN anywhere makes
		// --format json emit nothing at all.
		if _, err := json.Marshal(stats); err != nil {
			t.Fatalf("iteration %d: statistics are not JSON-encodable: %v", iteration, err)
		}
		if stats.Total != len(result.Observations) {
			t.Fatalf("iteration %d: Total %d != %d observations", iteration, stats.Total, len(result.Observations))
		}
		// Counts must nest: scored samples are a subset of usable responses,
		// which are a subset of successes, which are a subset of the total.
		// An answer is a usable response that carried a record, so it nests
		// inside usable just as scored does.
		if stats.Answers > stats.UsableResponses {
			t.Fatalf("iteration %d: answers %d exceed usable responses %d", iteration, stats.Answers, stats.UsableResponses)
		}
		if !(stats.Scored <= stats.UsableResponses && stats.UsableResponses <= stats.Successes && stats.Successes <= stats.Total) {
			t.Fatalf("iteration %d: counts do not nest: scored=%d usable=%d successes=%d total=%d",
				iteration, stats.Scored, stats.UsableResponses, stats.Successes, stats.Total)
		}
		if stats.Successes+stats.Failures != stats.Total {
			t.Fatalf("iteration %d: successes %d + failures %d != total %d",
				iteration, stats.Successes, stats.Failures, stats.Total)
		}
		// Every published rate is a proportion of the total, so each one both
		// stays in [0,1] and matches its own numerator.
		for _, rate := range []struct {
			name      string
			value     float64
			numerator int
		}{
			{"success_rate", stats.SuccessRate, stats.Successes},
			{"failure_rate", stats.FailureRate, stats.Failures},
			{"usable_rate", stats.UsableRate, stats.UsableResponses},
			{"resolver_failure_rate", stats.ResolverFailureRate, stats.ResolverFailures},
			{"answer_rate", stats.AnswerRate, stats.Answers},
		} {
			if rate.value < 0 || rate.value > 1 || math.IsNaN(rate.value) {
				t.Fatalf("iteration %d: %s = %v, want a proportion in [0,1]", iteration, rate.name, rate.value)
			}
			if want := float64(rate.numerator) / float64(stats.Total); math.Abs(rate.value-want) > 1e-12 {
				t.Fatalf("iteration %d: %s = %v, want %v (%d/%d)",
					iteration, rate.name, rate.value, want, rate.numerator, stats.Total)
			}
		}
		// Latency percentiles must be ordered, and a confidence interval must
		// not be published upside down.
		if stats.Scored > 0 {
			if !(stats.MinMS <= stats.MedianMS && stats.MedianMS <= stats.P95MS && stats.P95MS <= stats.MaxMS) {
				t.Fatalf("iteration %d: latency percentiles out of order: min=%v median=%v p95=%v max=%v",
					iteration, stats.MinMS, stats.MedianMS, stats.P95MS, stats.MaxMS)
			}
			if stats.CILowMS > stats.CIHighMS {
				t.Fatalf("iteration %d: score interval inverted: [%v, %v]", iteration, stats.CILowMS, stats.CIHighMS)
			}
		}
	}
}

// TestTieGroupsOrderByMedian pins the fix for unreproducible rank order.
//
// Ordering overlapping targets by raw score made the headline result a coin
// flip: four runs of one command at one seed produced three different orders,
// and the target with the worst median in every run took rank one twice. The
// instability lives entirely in the 0.40 x p95 term, whose interval is 66-143%
// of its estimate where the median's is 9-14%.
//
// Within a tie group the median decides; outside one the score still does.
func TestTieGroupsOrderByMedian(t *testing.T) {
	target := func(address string, median, score, low, high float64) TargetResult {
		return TargetResult{
			Target: testTarget(catalog.UDP, address),
			Stats: Statistics{
				Total: 40, Successes: 40, UsableResponses: 40, Scored: 40,
				SuccessRate: 1, UsableRate: 1,
				MedianMS: median, P95MS: score * 2, ScoreMS: score,
				CILowMS: low, CIHighMS: high,
			},
		}
	}
	// Two overlapping intervals: the worse score has the better median, which
	// is exactly the case that used to flip between runs. A third target sits
	// clear of both.
	results := []TargetResult{
		target("noisy", 22.0, 20.0, 10.0, 40.0),
		target("steady", 18.0, 25.0, 12.0, 42.0),
		target("slow", 60.0, 80.0, 70.0, 90.0),
	}

	rankings := makeRankings(results, DefaultTimeout)
	got := make([]string, 0, len(rankings))
	for _, ranking := range rankings {
		got = append(got, ranking.TargetID)
	}
	want := []string{
		testTarget(catalog.UDP, "steady").ID(), // better median inside the tie group
		testTarget(catalog.UDP, "noisy").ID(),
		testTarget(catalog.UDP, "slow").ID(), // no overlap: ranked by score
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("rank %d = %q, want %q (order: %v)", index+1, got[index], want[index], got)
		}
	}

	// Outside a tie group the score still decides, so this is not a silent
	// switch to median-based ranking.
	separate := []TargetResult{
		target("worse-score-better-median", 5.0, 90.0, 85.0, 95.0),
		target("better-score", 50.0, 10.0, 5.0, 15.0),
	}
	order := makeRankings(separate, DefaultTimeout)
	if order[0].TargetID != testTarget(catalog.UDP, "better-score").ID() {
		t.Fatalf("non-overlapping targets must rank by score, got %q first", order[0].TargetID)
	}

	// Degenerate but not impossible: equal scores with disjoint intervals.
	// The order must still be deterministic rather than depending on map
	// iteration, so it falls back to the target ID.
	identical := []TargetResult{
		target("zzz", 10.0, 30.0, 40.0, 50.0),
		target("aaa", 20.0, 30.0, 1.0, 5.0),
	}
	stable := makeRankings(identical, DefaultTimeout)
	if stable[0].TargetID != testTarget(catalog.UDP, "aaa").ID() {
		t.Fatalf("equal scores must break ties by target ID, got %q first", stable[0].TargetID)
	}
}

func TestRankingsArePermutationInvariantWithChainedOverlaps(t *testing.T) {
	target := func(address string, median, score, low, high float64) TargetResult {
		return TargetResult{
			Target: testTarget(catalog.UDP, address),
			Stats: Statistics{
				Total: 40, Successes: 40, UsableResponses: 40, Scored: 40,
				SuccessRate: 1, UsableRate: 1,
				MedianMS: median, P95MS: score * 2, ScoreMS: score,
				CILowMS: low, CIHighMS: high,
			},
		}
	}
	// A overlaps B, B overlaps C, and A does not overlap C. A pairwise
	// comparator that switches between median and score therefore has a cycle:
	// A < B, B < C, and C < A. The score-order leader is C; only C/B are in
	// its leader-anchored tie group, and B's lower median is presented first.
	base := []TargetResult{
		target("a", 10, 50, 45, 55),
		target("b", 20, 40, 25, 50),
		target("c", 30, 30, 20, 35),
	}
	wantIDs := []string{
		testTarget(catalog.UDP, "b").ID(),
		testTarget(catalog.UDP, "c").ID(),
		testTarget(catalog.UDP, "a").ID(),
	}
	wantTies := []bool{true, true, false}

	permutations := [][]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
		{1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}
	for _, permutation := range permutations {
		results := make([]TargetResult, len(base))
		for index, source := range permutation {
			results[index] = base[source]
		}
		rankings := makeRankings(results, DefaultTimeout)
		if len(rankings) != len(wantIDs) {
			t.Fatalf("permutation %v produced %d rankings, want %d", permutation, len(rankings), len(wantIDs))
		}
		for index, wantID := range wantIDs {
			if rankings[index].TargetID != wantID || rankings[index].Tie != wantTies[index] {
				t.Fatalf("permutation %v rank %d = %#v, want target %q tie %t", permutation, index+1, rankings[index], wantID, wantTies[index])
			}
		}
	}
}

// tieOrderTarget builds a 200-observation UDP target through
// calculateStatistics at the default timeout. Latencies are base plus up to
// spread of jitter from random; failures observations at random positions are
// copies of failed.
func tieOrderTarget(random *rand.Rand, seed int64, address string, base, spread float64, failures int, failed Observation) TargetResult {
	result := TargetResult{Target: testTarget(catalog.UDP, address)}
	failedAt := make(map[int]bool, failures)
	for _, index := range random.Perm(200)[:failures] {
		failedAt[index] = true
	}
	for index := 0; index < 200; index++ {
		observation := Observation{
			Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer",
			LatencyMS: base + random.Float64()*spread,
		}
		if failedAt[index] {
			observation = failed
		}
		observation.Name, observation.QType = fmt.Sprintf("q%03d.example.", index), dns.TypeA
		result.Observations = append(result.Observations, observation)
	}
	result.Stats = calculateStatistics(result, DefaultTimeout, seed)
	return result
}

// tieOrderFlaky is the target that used to take rank one: a median near
// 10.9 ms, about 1 ms better than the leader's, and two failed queries in 200.
func tieOrderFlaky(random *rand.Rand, seed int64, failed Observation) TargetResult {
	return tieOrderTarget(random, seed, "flaky", 9.9, 2.0, 2, failed)
}

// tieOrderScenario builds the shape that used to hand rank one to the less
// reliable resolver: a leader that answered all 200 queries with a median near
// 12 ms, tieOrderFlaky, and a steady target near 14.4 ms clear of both.
func tieOrderScenario(seed int64, failed Observation) []TargetResult {
	random := rand.New(rand.NewSource(seed))
	return []TargetResult{
		tieOrderTarget(random, seed, "leader", 11.0, 2.0, 0, Observation{}),
		tieOrderFlaky(random, seed, failed),
		tieOrderTarget(random, seed, "steady", 14.0, 0.8, 0, Observation{}),
	}
}

// TestTieGroupOrderPenalizesOneAndThreeFailures covers the neighbours of the
// two-failure case. One failure in 200 already joins the leader's group with
// a latency-only lower bound; three leave the target recommendation-ineligible
// (usable 0.985), yet under median-only ordering it still took rank one and
// became the target unqualified numeric --assert checks evaluate. The leader
// that lost nothing must hold rank one in both.
func TestTieGroupOrderPenalizesOneAndThreeFailures(t *testing.T) {
	for _, failures := range []int{1, 3} {
		random := rand.New(rand.NewSource(7))
		results := []TargetResult{
			tieOrderTarget(random, 7, "leader", 11.0, 2.0, 0, Observation{}),
			tieOrderTarget(random, 7, "flaky", 9.9, 2.0, failures, Observation{Error: "timeout"}),
		}
		leader, flaky := results[0].Stats, results[1].Stats
		if flaky.MedianMS >= leader.MedianMS || !confidenceIntervalsOverlap(leader, flaky) {
			t.Fatalf("%d failures: precondition: flaky median %.3f vs leader %.3f, intervals [%.3f, %.3f] and [%.3f, %.3f]",
				failures, flaky.MedianMS, leader.MedianMS, flaky.CILowMS, flaky.CIHighMS, leader.CILowMS, leader.CIHighMS)
		}
		rankings := makeRankings(results, DefaultTimeout)
		if rankings[0].TargetID != results[0].Target.ID() || !rankings[0].Tie || !rankings[1].Tie {
			t.Fatalf("%d failures: rankings = %#v, want the leader first in a two-member tie group", failures, rankings)
		}
	}
}

// firstRecommended applies report.recommendedResult's rule -- the first
// ranked, complete, recommendation-eligible target of the protocol -- which
// this package cannot call without an import cycle.
func firstRecommended(results []TargetResult, rankings []Ranking) string {
	for _, ranking := range rankings {
		for _, result := range results {
			if result.Target.ID() == ranking.TargetID && !result.Incomplete && result.Stats.Recommended {
				return ranking.TargetID
			}
		}
	}
	return ""
}

// checkTieOrderKeepsReliableLeader asserts the outcome the fix exists for,
// after checking that the inputs really are the shape that used to invert: the
// failing target has the better median, is recommendation-eligible, and joined
// the leader's tie group.
func checkTieOrderKeepsReliableLeader(t *testing.T, label string, results []TargetResult) {
	t.Helper()
	leader, flaky := results[0], results[1]
	if flaky.Stats.MedianMS >= leader.Stats.MedianMS || flaky.Stats.ScoringFailureRate == 0 || !flaky.Stats.Recommended {
		t.Fatalf("%s: precondition: flaky median %.3f vs leader %.3f, scoring failure rate %v, recommended %t",
			label, flaky.Stats.MedianMS, leader.Stats.MedianMS, flaky.Stats.ScoringFailureRate, flaky.Stats.Recommended)
	}
	if !confidenceIntervalsOverlap(leader.Stats, flaky.Stats) {
		t.Fatalf("%s: precondition: flaky interval [%.3f, %.3f] does not overlap the leader's [%.3f, %.3f]",
			label, flaky.Stats.CILowMS, flaky.Stats.CIHighMS, leader.Stats.CILowMS, leader.Stats.CIHighMS)
	}

	rankings := makeRankings(results, DefaultTimeout)
	// Membership is unchanged. The steady target's interval lies inside the
	// failing target's wide one but clear of the leader's, so it stays outside
	// the leader's group and below both members, although its score is better
	// than the failing target's.
	wantIDs := []string{leader.Target.ID(), flaky.Target.ID(), results[2].Target.ID()}
	wantTies := []bool{true, true, false}
	if len(rankings) != len(wantIDs) {
		t.Fatalf("%s: %d rankings, want %d", label, len(rankings), len(wantIDs))
	}
	for index, wantID := range wantIDs {
		if rankings[index].TargetID != wantID || rankings[index].Tie != wantTies[index] {
			t.Fatalf("%s: rank %d = %#v, want target %q tie %t", label, index+1, rankings[index], wantID, wantTies[index])
		}
	}
	if got := firstRecommended(results, rankings); got != leader.Target.ID() {
		t.Fatalf("%s: recommendation = %q, want the leader that lost no query", label, got)
	}
}

// TestTieGroupOrderPenalizesScoringFailures pins the fix for the tie group
// recommending the less reliable resolver.
//
// With k <= 3 scoring failures in 200 queries roughly e^-k of the bootstrap
// resamples contain no failure, so the interval's lower bound falls to the
// latency-only score and the target joins the leader's tie group. Ordering
// that group by median alone then discarded the failure penalty: a target
// that lost 2 of 200 queries, with a 1 ms better median, took rank one and
// RECOMMENDED from one that lost none, for every seed tried.
func TestTieGroupOrderPenalizesScoringFailures(t *testing.T) {
	results := tieOrderScenario(7, Observation{Error: "timeout"})
	checkTieOrderKeepsReliableLeader(t, "seed 7", results)

	// The order is still a property of the targets, not of the input slice.
	permutations := [][]int{{0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, permutation := range permutations {
		permuted := make([]TargetResult, len(results))
		for index, source := range permutation {
			permuted[index] = results[source]
		}
		rankings := makeRankings(permuted, DefaultTimeout)
		for index, result := range results {
			if rankings[index].TargetID != result.Target.ID() {
				t.Fatalf("permutation %v changed the order: %#v", permutation, rankings)
			}
		}
	}

	// Fifty seeds resample the failing target's latencies, failure positions
	// and bootstrap. Each must reproduce the old inversion's preconditions and
	// keep the leader first. The leader and the steady target stay fixed: the
	// failing target's interval is what decides whether it joins the group, and
	// every calculateStatistics call costs a full 1000-replicate bootstrap.
	for seed := int64(1); seed <= 50; seed++ {
		flaky := tieOrderFlaky(rand.New(rand.NewSource(seed)), seed, Observation{Error: "timeout"})
		checkTieOrderKeepsReliableLeader(t, fmt.Sprintf("seed %d", seed), []TargetResult{results[0], flaky, results[2]})
	}
}

// TestTieGroupOrderCountsResolverErrorsAsFailures pins that the tie order
// uses ScoringFailureRate rather than FailureRate. A fast SERVFAIL is a
// transport success, so FailureRate stays zero; keying on it would let a
// resolver that rejects queries quickly escape the penalty the score applies.
func TestTieGroupOrderCountsResolverErrorsAsFailures(t *testing.T) {
	servfail := Observation{Success: true, RCode: dns.RcodeServerFailure, ResponseClass: "servfail", LatencyMS: 1}
	results := tieOrderScenario(7, servfail)
	if flaky := results[1].Stats; flaky.FailureRate != 0 || flaky.ResolverFailures != 2 {
		t.Fatalf("precondition: SERVFAILs must be transport successes and resolver failures: %#v", flaky)
	}
	checkTieOrderKeepsReliableLeader(t, "servfail", results)
}

// TestTieGroupOrderBreaksKeyTiesByMedianThenID pins the order's tie-breakers.
// A 5 ms median with 0.3% failures at a 1 s timeout pays exactly the 3 ms it
// gained over a 10 ms median, so the key alone cannot order the two; the
// median decides, and equal medians fall back to the target ID.
func TestTieGroupOrderBreaksKeyTiesByMedianThenID(t *testing.T) {
	target := func(address string, median, failureRate float64) TargetResult {
		return TargetResult{
			Target: testTarget(catalog.UDP, address),
			Stats: Statistics{
				Scored: 40, MedianMS: median, ScoringFailureRate: failureRate,
				ScoreMS: 10, CILowMS: 4, CIHighMS: 20,
			},
		}
	}
	// The IDs sort opposite to the medians, so an ID fallback cannot pass.
	steady, flaky := target("a-steady", 10, 0), target("b-flaky", 5, 0.003)
	if tieOrderKey(steady.Stats, 1000) != tieOrderKey(flaky.Stats, 1000) {
		t.Fatalf("precondition: keys %v and %v must be equal", tieOrderKey(steady.Stats, 1000), tieOrderKey(flaky.Stats, 1000))
	}
	rankings := makeRankings([]TargetResult{steady, flaky}, time.Second)
	if rankings[0].TargetID != flaky.Target.ID() || !rankings[0].Tie || !rankings[1].Tie {
		t.Fatalf("equal keys must be ordered by median: %#v", rankings)
	}

	twins := makeRankings([]TargetResult{target("zzz", 5, 0.003), target("aaa", 5, 0.003)}, time.Second)
	if twins[0].TargetID != testTarget(catalog.UDP, "aaa").ID() {
		t.Fatalf("equal keys and medians must be ordered by target ID: %#v", twins)
	}
}

// TestRunOrdersTieGroupWithTheRunTimeout pins that Run prices the tie order's
// failure penalty at its own --timeout, as calculateStatistics prices the
// score's. Two lost queries in 200 cost 20 ms at the default 2 s timeout but
// only 1 ms at 100 ms, which is less than the 1.2 ms the failing target gains
// on 0.60 x median, so the same observations rank differently. Ordering by
// median alone, or at any fixed timeout, gets one of the two runs wrong.
func TestRunOrdersTieGroupWithTheRunTimeout(t *testing.T) {
	useTargetSeam(t, func(_ context.Context, target catalog.Target, queries []Query, opts Options) TargetResult {
		result := TargetResult{Target: target}
		for index, query := range queries {
			observation := Observation{Name: query.Name, QType: query.QType, Error: "timeout"}
			if target.Address != "flaky" || index >= 2 {
				base := 11.0
				if target.Address == "flaky" {
					base = 9.0
				}
				observation = Observation{
					Name: query.Name, QType: query.QType, Success: true, Usable: true,
					RCode: dns.RcodeSuccess, ResponseClass: "answer",
					LatencyMS: base + 2*float64(index%20)/19,
				}
			}
			result.Observations = append(result.Observations, observation)
		}
		return result
	})
	options := validBenchmarkOptions()
	options.Domains = make([]string, 100)
	for index := range options.Domains {
		options.Domains[index] = fmt.Sprintf("d%03d.example.", index)
	}
	options.Sample = len(options.Domains)
	for _, tc := range []struct {
		timeout time.Duration
		first   string
	}{
		{timeout: DefaultTimeout, first: "leader"},
		{timeout: 100 * time.Millisecond, first: "flaky"},
	} {
		options.Timeout = tc.timeout
		report, err := Run(context.Background(), []catalog.Target{
			testTarget(catalog.UDP, "flaky"),
			testTarget(catalog.UDP, "leader"),
		}, options)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Rankings) != 2 || !report.Rankings[0].Tie || !report.Rankings[1].Tie {
			t.Fatalf("timeout %v: precondition: both targets must share the tie group: %#v", tc.timeout, report.Rankings)
		}
		if want := testTarget(catalog.UDP, tc.first).ID(); report.Rankings[0].TargetID != want {
			t.Fatalf("timeout %v: rank 1 = %q, want %q", tc.timeout, report.Rankings[0].TargetID, want)
		}
	}
}
