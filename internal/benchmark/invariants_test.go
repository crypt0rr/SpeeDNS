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

	rankings := makeRankings(results)
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
