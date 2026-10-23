package benchmark

import (
	"math"
	"sort"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
)

// The scoring engine is documented in METHODOLOGY.md as
//
//	score_ms = 0.60 x median_ms + 0.40 x p95_ms
//	           + scoring_failure_rate x timeout_ms
//
// These constants restate that contract so a reader can see the weights and
// the percentiles that the tests below assert, and so a silent change to
// either one fails here instead of only moving a ranking.
const (
	scoreMedianWeight  = 0.60
	scoreP95Weight     = 0.40
	scoreMedianQuant   = 0.50
	scoreP95Quant      = 0.95
	bootstrapLowQuant  = 0.025
	bootstrapHighQuant = 0.975
)

// scoringEpsilon is used only where the arithmetic is genuinely inexact in
// binary floating point, that is where percentile() interpolates with a
// weight such as 0.85 or 0.8 that has no exact double representation. Every
// other assertion in this file compares exact float64 values.
const scoringEpsilon = 1e-9

func nearlyEqual(got, want float64) bool {
	return math.Abs(got-want) <= scoringEpsilon
}

// scoredObservation is a usable, non-divergent, non-reconnect sample, which
// is what the latency percentiles are computed from.
func scoredObservation(latencyMS float64) Observation {
	return Observation{
		Success:       true,
		Usable:        true,
		RCode:         dns.RcodeSuccess,
		ResponseClass: "answer",
		Latency:       time.Duration(latencyMS * float64(time.Millisecond)),
		LatencyMS:     latencyMS,
	}
}

// timedOutObservation is a transport failure, so it is a scoring failure and
// contributes to the failure penalty.
func timedOutObservation() Observation {
	return Observation{Success: false, Error: "timeout"}
}

func scoringTarget(id string) catalog.Target {
	return catalog.Target{
		Resolver: catalog.ResolverProfile{ID: id, Name: "Scoring", Owner: "Scoring", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "192.0.2.1",
		Spec:     catalog.TransportSpec{Port: 53},
	}
}

// rampLatencies returns count latencies of 10, 20, 30 and so on. With 21
// samples the median lands exactly on index 10 (110) and the p95 lands
// exactly on index 19 (200), so the score arithmetic stays exact and the p5
// (20), p95 (200) and p99 (208) values are all distinct.
func rampLatencies(count int) []float64 {
	values := make([]float64, count)
	for index := range values {
		values[index] = float64(10 * (index + 1))
	}
	return values
}

func TestPercentileInterpolatesKnownVectors(t *testing.T) {
	tests := []struct {
		name   string
		sorted []float64
		p      float64
		want   float64
		exact  bool
	}{
		{name: "empty", sorted: nil, p: scoreMedianQuant, want: 0, exact: true},
		{name: "single sample median", sorted: []float64{42}, p: scoreMedianQuant, want: 42, exact: true},
		{name: "single sample p95", sorted: []float64{42}, p: scoreP95Quant, want: 42, exact: true},
		{name: "single sample low quantile", sorted: []float64{42}, p: bootstrapLowQuant, want: 42, exact: true},
		{name: "two sample median", sorted: []float64{10, 20}, p: scoreMedianQuant, want: 15, exact: true},
		// position = 0.95 * 1, so the result is 10 + 10*0.95 with an
		// interpolation weight that is not exactly representable.
		{name: "two sample p95", sorted: []float64{10, 20}, p: scoreP95Quant, want: 19.5, exact: false},
		{name: "two sample bootstrap low", sorted: []float64{10, 20}, p: bootstrapLowQuant, want: 10.25, exact: false},
		{name: "two sample bootstrap high", sorted: []float64{10, 20}, p: bootstrapHighQuant, want: 19.75, exact: false},
		// position = 0.50 * 3 = 1.5, exactly halfway between 20 and 30.
		{name: "four sample median interpolates", sorted: []float64{10, 20, 30, 40}, p: scoreMedianQuant, want: 25, exact: true},
		// position = 0.95 * 3 = 2.85, so 30 + 10*0.85.
		{name: "four sample p95 interpolates", sorted: []float64{10, 20, 30, 40}, p: scoreP95Quant, want: 38.5, exact: false},
		{name: "five sample median lands on an index", sorted: []float64{1, 2, 3, 4, 5}, p: scoreMedianQuant, want: 3, exact: true},
		// position = 0.95 * 4 = 3.8, so 4 + 1*0.8.
		{name: "five sample p95 interpolates", sorted: []float64{1, 2, 3, 4, 5}, p: scoreP95Quant, want: 4.8, exact: false},
		{name: "twenty one sample median lands on index ten", sorted: rampLatencies(21), p: scoreMedianQuant, want: 110, exact: true},
		{name: "twenty one sample p95 lands on index nineteen", sorted: rampLatencies(21), p: scoreP95Quant, want: 200, exact: true},
		{name: "twenty one sample p5 lands on index one", sorted: rampLatencies(21), p: 0.05, want: 20, exact: true},
		{name: "twenty one sample p99 interpolates above p95", sorted: rampLatencies(21), p: 0.99, want: 208, exact: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := percentile(test.sorted, test.p)
			if test.exact {
				if got != test.want {
					t.Fatalf("percentile(%v, %v) = %v, want exactly %v", test.sorted, test.p, got, test.want)
				}
				return
			}
			if !nearlyEqual(got, test.want) {
				t.Fatalf("percentile(%v, %v) = %v, want %v within %v", test.sorted, test.p, got, test.want, scoringEpsilon)
			}
		})
	}
}

func TestCalculateStatisticsPinsLatencyDistribution(t *testing.T) {
	observations := make([]Observation, 0, 21)
	for _, latency := range rampLatencies(21) {
		observations = append(observations, scoredObservation(latency))
	}
	stats := calculateStatistics(TargetResult{Target: scoringTarget("distribution"), Observations: observations}, 2*time.Second, 7)

	if stats.Total != 21 || stats.Scored != 21 || stats.UsableResponses != 21 {
		t.Fatalf("counts = total %d scored %d usable %d, want 21/21/21", stats.Total, stats.Scored, stats.UsableResponses)
	}
	if stats.MedianMS != 110 {
		t.Fatalf("MedianMS = %v, want exactly 110 (the 50th percentile, not the 5th)", stats.MedianMS)
	}
	if stats.P95MS != 200 {
		t.Fatalf("P95MS = %v, want exactly 200 (the 95th percentile, not the 99th)", stats.P95MS)
	}
	if stats.MinMS != 10 {
		t.Fatalf("MinMS = %v, want exactly 10", stats.MinMS)
	}
	if stats.MaxMS != 210 {
		t.Fatalf("MaxMS = %v, want exactly 210", stats.MaxMS)
	}
	// Deviations from the median are 100, 90, ..., 10, 0, 10, ..., 100, so
	// their median is 50.
	if stats.MADMS != 50 {
		t.Fatalf("MADMS = %v, want exactly 50", stats.MADMS)
	}
	if stats.ScoringFailureRate != 0 {
		t.Fatalf("ScoringFailureRate = %v, want exactly 0", stats.ScoringFailureRate)
	}
	// 0.60*110 + 0.40*200 = 66 + 80, with no failure penalty.
	if want := scoreMedianWeight*110 + scoreP95Weight*200; stats.ScoreMS != want {
		t.Fatalf("ScoreMS = %v, want exactly %v", stats.ScoreMS, want)
	}
	if stats.ScoreMS != 146 {
		t.Fatalf("ScoreMS = %v, want exactly 146 (0.60*110 + 0.40*200)", stats.ScoreMS)
	}
}

func TestCalculateStatisticsPinsFailurePenalty(t *testing.T) {
	const (
		timeout   = 2 * time.Second
		timeoutMS = 2000.0
	)
	// 21 scored latencies plus 7 failures gives a scoring failure rate of
	// exactly 0.25 over the 28 scoring outcomes.
	observations := make([]Observation, 0, 28)
	for _, latency := range rampLatencies(21) {
		observations = append(observations, scoredObservation(latency))
	}
	for index := 0; index < 7; index++ {
		observations = append(observations, timedOutObservation())
	}
	stats := calculateStatistics(TargetResult{Target: scoringTarget("penalty"), Observations: observations}, timeout, 7)

	if stats.Scored != 21 || stats.Failures != 7 || stats.Total != 28 {
		t.Fatalf("counts = scored %d failures %d total %d, want 21/7/28", stats.Scored, stats.Failures, stats.Total)
	}
	if stats.ScoringFailureRate != 0.25 {
		t.Fatalf("ScoringFailureRate = %v, want exactly 0.25", stats.ScoringFailureRate)
	}
	if stats.MedianMS != 110 || stats.P95MS != 200 {
		t.Fatalf("median/p95 = %v/%v, want exactly 110/200", stats.MedianMS, stats.P95MS)
	}
	// 0.60*110 + 0.40*200 + 0.25*2000 = 66 + 80 + 500. Each product is
	// rounded, as compositeScore rounds it, so the exact comparison below
	// holds on arm64, where a product could otherwise be fused into the sum.
	want := float64(scoreMedianWeight*stats.MedianMS) + float64(scoreP95Weight*stats.P95MS) + float64(stats.ScoringFailureRate*timeoutMS)
	if stats.ScoreMS != want {
		t.Fatalf("ScoreMS = %v, want exactly %v", stats.ScoreMS, want)
	}
	if stats.ScoreMS != 646 {
		t.Fatalf("ScoreMS = %v, want exactly 646 (0.60*110 + 0.40*200 + 0.25*2000)", stats.ScoreMS)
	}
	// The penalty is the only difference from the unpenalised case, so a
	// change to the weights cannot absorb it.
	if stats.ScoreMS-146 != 500 {
		t.Fatalf("failure penalty = %v, want exactly 500", stats.ScoreMS-146)
	}
}

func TestScoreFromLatenciesUsesDocumentedWeights(t *testing.T) {
	latencies := rampLatencies(21)
	// A swap of the two weights would give 0.60*200 + 0.40*110 = 164.
	if got, want := scoreFromLatencies(latencies, 0, 2000), scoreMedianWeight*110+scoreP95Weight*200; got != want {
		t.Fatalf("scoreFromLatencies without failures = %v, want exactly %v", got, want)
	}
	if got := scoreFromLatencies(latencies, 0.25, 2000); got != 646 {
		t.Fatalf("scoreFromLatencies with a 0.25 failure rate = %v, want exactly 646", got)
	}
	// The weights must sum to one, so a flat latency vector scores as that
	// latency.
	flat := []float64{25, 25, 25, 25, 25}
	if got := scoreFromLatencies(flat, 0, 2000); got != 25 {
		t.Fatalf("flat latency score = %v, want exactly 25", got)
	}
}

func TestBootstrapCIIsDeterministicAndPinsQuantiles(t *testing.T) {
	const (
		timeout   = 2 * time.Second
		timeoutMS = 2000.0
	)
	samples := []scoreSample{
		{latencyMS: 10, success: true},
		{latencyMS: 20, success: true},
		{latencyMS: 30, success: true},
		{latencyMS: 40, success: true},
		{success: false},
	}
	seed := bootstrapSeed(42, "scoring@192.0.2.1/udp")

	low, high := bootstrapCI(samples, timeout, seed)
	repeatLow, repeatHigh := bootstrapCI(samples, timeout, seed)
	if low != repeatLow || high != repeatHigh {
		t.Fatalf("bootstrap is not deterministic: %v/%v then %v/%v", low, high, repeatLow, repeatHigh)
	}

	// Pinned bounds for this exact sample vector and seed: the 0.025 and
	// 0.975 quantiles of the 1000 bootstrap replicates. Widening the
	// interval to 80% or narrowing it changes these numbers. Their bits,
	// taken on amd64, are pinned too: METHODOLOGY promises the same bounds
	// bit for bit on arm64, and the tolerance alone would accept a bound one
	// rounding away (the upper one is already an ulp below 1223.68).
	const (
		wantLow      = 20.4
		wantHigh     = 1223.68
		wantLowBits  = 0x4034666666666666
		wantHighBits = 0x40931eb851eb851e
	)
	if !nearlyEqual(low, wantLow) || !nearlyEqual(high, wantHigh) {
		t.Fatalf("bootstrap interval = %v/%v, want %v/%v", low, high, wantLow, wantHigh)
	}
	if math.Float64bits(low) != wantLowBits || math.Float64bits(high) != wantHighBits {
		t.Fatalf("bootstrap interval bits = %#016x/%#016x, want %#016x/%#016x as computed on amd64",
			math.Float64bits(low), math.Float64bits(high), uint64(wantLowBits), uint64(wantHighBits))
	}

	score := scoreFromSamples(samples, timeoutMS)
	if score < low || score > high {
		t.Fatalf("bootstrap interval %v/%v does not bracket the score %v", low, high, score)
	}

	// A different per-target seed for the same samples must move the
	// interval, which is what makes the target-identity seed meaningful.
	otherLow, otherHigh := bootstrapCI(samples, timeout, bootstrapSeed(42, "other@192.0.2.2/udp"))
	if otherLow == low && otherHigh == high {
		t.Fatalf("distinct target seeds produced an identical interval: %v/%v", low, high)
	}

	// Fewer than two samples degenerates to the point estimate.
	pointLow, pointHigh := bootstrapCI([]scoreSample{{latencyMS: 12, success: true}}, timeout, seed)
	if pointLow != 12 || pointHigh != 12 {
		t.Fatalf("single-sample interval = %v/%v, want exactly 12/12", pointLow, pointHigh)
	}
}

// TestStatisticsArePinnedBitForBit pins the exact bits, taken on amd64, of the
// statistics a report carries for two targets and for one paired effect.
// METHODOLOGY promises that the same observations and seed give bit-identical
// medians, p95 values, scores and interval bounds on amd64 and arm64, and the
// ubuntu (amd64) and macOS (arm64) CI jobs both run this test, so this is
// where the promise is enforced. A tolerance could not enforce it: a multiply
// fused into the following add or subtract rounds once instead of twice and
// moves a result by an ulp or two.
//
// The first target is the pinned vector of
// TestBootstrapCIIsDeterministicAndPinsQuantiles. Its bootstrap quantiles fall
// between equal or nearly equal replicate scores, so only a fused composite
// score moves its pins. The second target and the paired deltas are chosen so
// that the p95 and the interval bounds interpolate between distinct values
// with inexact weights, where a fused percentile position or interpolation
// moves a pin as well.
func TestStatisticsArePinnedBitForBit(t *testing.T) {
	const seed = 42
	timeout := 2 * time.Second
	pinned := calculateStatistics(TargetResult{Target: scoringTarget("scoring"), Observations: []Observation{
		scoredObservation(10), scoredObservation(20), scoredObservation(30), scoredObservation(40), timedOutObservation(),
	}}, timeout, seed)

	// 25 scored latencies in a fixed, unsorted order, with a timeout after
	// the 7th and the 18th, so the failure rate is 2/27.
	latencies := []float64{
		14.66, 11.37, 22.9, 12.91, 98.6, 15.87, 12.08, 31.2, 13.4, 17.45, 61.4, 16.3, 18.1,
		19.76, 140.3, 21.33, 24.18, 26.5, 45.1, 28.07, 15.02, 34.95, 39.6, 52.8, 77.25,
	}
	observations := make([]Observation, 0, len(latencies)+2)
	for index, latency := range latencies {
		observations = append(observations, scoredObservation(latency))
		if index == 6 || index == 17 {
			observations = append(observations, timedOutObservation())
		}
	}
	varied := calculateStatistics(TargetResult{Target: scoringTarget("scoring"), Observations: observations}, timeout, seed)

	// The deltas are sorted before the median and the bootstrap, as
	// calculatePairedEffects sorts them. Seed 9 places the upper bound between
	// two distinct replicate medians.
	deltas := []float64{
		-38.4, -21.7, -12.95, -7.3, -3.85, -1.2, 0.45, 2.1, 3.6, 5.25, 7.9, 11.4,
		16.05, 24.3, 37.8, 58.2, -2.6, 1.35, 4.4, 9.15, -5.5, 13.6, 19.95,
	}
	sort.Float64s(deltas)
	pairedLow, pairedHigh := bootstrapPairedCI(deltas, 9)

	for _, pin := range []struct {
		name string
		got  float64
		bits uint64
	}{
		{"pinned vector median", pinned.MedianMS, 0x4039000000000000},
		{"pinned vector p95", pinned.P95MS, 0x4043400000000000},
		{"pinned vector MAD", pinned.MADMS, 0x4024000000000000},
		{"pinned vector score", pinned.ScoreMS, 0x407ae66666666666},
		{"pinned vector CI low", pinned.CILowMS, 0x4034666666666666},
		{"pinned vector CI high", pinned.CIHighMS, 0x40931eb851eb851e},
		{"varied vector median", varied.MedianMS, 0x4036e66666666666},
		// Of all the pins, only this one moves when the interpolation is
		// fused, so a change to the vector must keep a p95 that does.
		{"varied vector p95", varied.P95MS, 0x4057951eb851eb80},
		{"varied vector MAD", varied.MADMS, 0x402099999999999a},
		{"varied vector score", varied.ScoreMS, 0x4068f3d840eddf14},
		{"varied vector CI low", varied.CILowMS, 0x4043627d566cf41f},
		{"varied vector CI high", varied.CIHighMS, 0x407a7f360c59432f},
		{"paired median delta", percentile(deltas, 0.5), 0x400ccccccccccccd},
		{"paired CI low", pairedLow, 0xbff3333333333333},
		{"paired CI high", pairedHigh, 0x402269999999997d},
	} {
		if bits := math.Float64bits(pin.got); bits != pin.bits {
			t.Errorf("%s = %v (bits %#016x), want %v (bits %#016x) as computed on amd64",
				pin.name, pin.got, bits, math.Float64frombits(pin.bits), pin.bits)
		}
	}
}

func TestRecommendedThresholdIsPinnedToMinimumRecommendedSamples(t *testing.T) {
	if MinimumRecommendedSamples != 20 {
		t.Fatalf("MinimumRecommendedSamples = %d, want 20 as documented in METHODOLOGY.md", MinimumRecommendedSamples)
	}
	if MinimumRecommendedSuccessRate != 0.99 {
		t.Fatalf("MinimumRecommendedSuccessRate = %v, want 0.99 as documented in METHODOLOGY.md", MinimumRecommendedSuccessRate)
	}

	scoredStats := func(count int) Statistics {
		observations := make([]Observation, 0, count)
		for index := 0; index < count; index++ {
			observations = append(observations, scoredObservation(float64(10*(index+1))))
		}
		return calculateStatistics(TargetResult{Target: scoringTarget("recommended"), Observations: observations}, 2*time.Second, 7)
	}

	below := scoredStats(MinimumRecommendedSamples - 1)
	if below.Scored != MinimumRecommendedSamples-1 || below.UsableRate != 1 {
		t.Fatalf("below-threshold stats = scored %d usable rate %v", below.Scored, below.UsableRate)
	}
	if below.Recommended {
		t.Fatalf("%d scored samples with a 100%% usable rate must not be recommended", below.Scored)
	}

	at := scoredStats(MinimumRecommendedSamples)
	if at.Scored != MinimumRecommendedSamples || at.UsableRate != 1 {
		t.Fatalf("at-threshold stats = scored %d usable rate %v", at.Scored, at.UsableRate)
	}
	if !at.Recommended {
		t.Fatalf("%d scored samples with a 100%% usable rate must be recommended", at.Scored)
	}
}
