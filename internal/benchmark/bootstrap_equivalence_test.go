package benchmark

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// The legacy functions below are the bootstrap as it was before it counted
// ranks: every replicate copied its draws into a slice and sorted it. They are
// kept verbatim -- percentile and the score formula included, so nothing they
// compute goes through the helpers they are checked against -- as the
// reference the rank-count bootstrap must reproduce bit for bit, and as the
// baseline its benchmarks are measured against. Nothing else calls them. The
// one change is the float64 conversions that round each product: they spell
// out the unfused arithmetic every amd64 build performed, so the comparison is
// also exact on arm64, where the compiler may otherwise fuse a multiply-add
// differently in the inlined reference and in the code under test.

func legacyPercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	position := float64(p * float64(len(sorted)-1))
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	weight := position - float64(lower)
	return sorted[lower] + float64((sorted[upper]-sorted[lower])*weight)
}

func legacyScoreFromLatencies(latencies []float64, failureRate, timeoutMS float64) float64 {
	return float64(0.60*legacyPercentile(latencies, 0.50)) + float64(0.40*legacyPercentile(latencies, 0.95)) + float64(failureRate*timeoutMS)
}

func legacyScoreFromSamples(samples []scoreSample, timeoutMS float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	latencies := make([]float64, 0, len(samples))
	failures := 0
	for _, sample := range samples {
		if sample.success {
			latencies = append(latencies, sample.latencyMS)
		} else {
			failures++
		}
	}
	failureRate := float64(failures) / float64(len(samples))
	sort.Float64s(latencies)
	return legacyScoreFromLatencies(latencies, failureRate, timeoutMS)
}

func legacyBootstrapCI(samples []scoreSample, timeout time.Duration, seed int64) (float64, float64) {
	if len(samples) < 2 {
		score := legacyScoreFromSamples(samples, durationMS(timeout))
		return score, score
	}
	rng := rand.New(rand.NewSource(seed))
	scores := make([]float64, BootstrapIterations)
	resample := make([]scoreSample, len(samples))
	for iteration := range scores {
		for index := range resample {
			resample[index] = samples[rng.Intn(len(samples))]
		}
		scores[iteration] = legacyScoreFromSamples(resample, durationMS(timeout))
	}
	sort.Float64s(scores)
	return legacyPercentile(scores, 0.025), legacyPercentile(scores, 0.975)
}

func legacyBootstrapPairedCI(deltas []float64, seed int64) (float64, float64) {
	if len(deltas) == 0 {
		return 0, 0
	}
	rng := rand.New(rand.NewSource(seed))
	scores := make([]float64, BootstrapIterations)
	resample := make([]float64, len(deltas))
	for iteration := range scores {
		for index := range resample {
			resample[index] = deltas[rng.Intn(len(deltas))]
		}
		sort.Float64s(resample)
		scores[iteration] = legacyPercentile(resample, 0.5)
	}
	sort.Float64s(scores)
	return legacyPercentile(scores, 0.025), legacyPercentile(scores, 0.975)
}

// sameBits compares two intervals exactly. Equality within a tolerance would
// accept a different rounding, and a CI bound decides tie membership.
func sameBits(gotLow, gotHigh, wantLow, wantHigh float64) bool {
	return math.Float64bits(gotLow) == math.Float64bits(wantLow) && math.Float64bits(gotHigh) == math.Float64bits(wantHigh)
}

// TestRankCountBootstrapMatchesSortedResampling is the proof that counting
// ranks changed no interval. Each trial draws a fresh sample vector -- sizes
// from empty to a --full run's 2,000, failure shares from none to all,
// integer-valued latencies whose many ties make every rank-order decision
// visible, negative paired deltas -- and a fresh seed, and requires both
// bootstraps to agree bit for bit with the sorting implementation.
func TestRankCountBootstrapMatchesSortedResampling(t *testing.T) {
	rng := rand.New(rand.NewSource(20261023))
	for trial := 0; trial < 100; trial++ {
		size := rng.Intn(48)
		switch {
		case trial == 8:
			size = 2000
		case trial%20 == 0:
			size = 200 + rng.Intn(200)
		}
		failureShare := []float64{0, 0.05, 0.5, 0.95, 1}[trial%5]
		tied := trial%3 == 0
		samples := make([]scoreSample, size)
		deltas := make([]float64, size)
		for index := range samples {
			latency := rng.ExpFloat64() * 25
			delta := rng.NormFloat64() * 4
			if tied {
				latency, delta = math.Round(latency), math.Round(delta)+0.5
			}
			deltas[index] = delta
			if rng.Float64() >= failureShare {
				samples[index] = scoreSample{latencyMS: latency, success: true}
			}
		}
		seed := rng.Int63()
		timeout := time.Duration(1+rng.Intn(4)) * 500 * time.Millisecond

		gotLow, gotHigh := bootstrapCI(samples, timeout, seed)
		wantLow, wantHigh := legacyBootstrapCI(samples, timeout, seed)
		if !sameBits(gotLow, gotHigh, wantLow, wantHigh) {
			t.Fatalf("trial %d (%d samples): score interval %v/%v, sorted resampling gives %v/%v", trial, size, gotLow, gotHigh, wantLow, wantHigh)
		}
		gotLow, gotHigh = bootstrapPairedCI(deltas, seed)
		wantLow, wantHigh = legacyBootstrapPairedCI(deltas, seed)
		if !sameBits(gotLow, gotHigh, wantLow, wantHigh) {
			t.Fatalf("trial %d (%d deltas): paired interval %v/%v, sorted resampling gives %v/%v", trial, size, gotLow, gotHigh, wantLow, wantHigh)
		}
	}
}

// TestRankValuesOrdersLikeSortFloat64s pins the ordering rankValues relies on,
// including the NaN placement sort.Float64s uses, and that every input value
// lands on a position holding that same value.
func TestRankValuesOrdersLikeSortFloat64s(t *testing.T) {
	values := []float64{3, math.NaN(), -1, 3, 0, math.Inf(1), -2.5, 3}
	sorted, ranks := rankValues(values)
	want := append([]float64(nil), values...)
	sort.Float64s(want)
	for index := range want {
		if math.Float64bits(sorted[index]) != math.Float64bits(want[index]) && !(math.IsNaN(sorted[index]) && math.IsNaN(want[index])) {
			t.Fatalf("rankValues order = %v, sort.Float64s gives %v", sorted, want)
		}
	}
	seen := make(map[int]bool, len(ranks))
	for index, rank := range ranks {
		if seen[rank] {
			t.Fatalf("rank %d assigned twice: %v", rank, ranks)
		}
		seen[rank] = true
		if math.Float64bits(sorted[rank]) != math.Float64bits(values[index]) {
			t.Fatalf("value %v ranked at %d, which holds %v", values[index], rank, sorted[rank])
		}
	}
}

// benchmarkScoreSamples builds a deterministic sample vector shaped like a
// real target: mostly successes with long-tailed latencies and a few
// failures. 200 is the default run's 100 names x A,AAAA; 2,000 is --full.
func benchmarkScoreSamples(size int) ([]scoreSample, []float64) {
	rng := rand.New(rand.NewSource(int64(size)))
	samples := make([]scoreSample, size)
	deltas := make([]float64, size)
	for index := range samples {
		deltas[index] = rng.NormFloat64() * 4
		if rng.Intn(50) != 0 {
			samples[index] = scoreSample{latencyMS: 5 + rng.ExpFloat64()*20, success: true}
		}
	}
	return samples, deltas
}

// BenchmarkBootstrapCI compares the rank-count bootstrap with sorting every
// resample. Run with: go test -run '^$' -bench Bootstrap ./internal/benchmark
func BenchmarkBootstrapCI(b *testing.B) {
	for _, size := range []int{200, 2000} {
		samples, _ := benchmarkScoreSamples(size)
		b.Run(fmt.Sprintf("rank-counts/samples=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				bootstrapCI(samples, 2*time.Second, 42)
			}
		})
		b.Run(fmt.Sprintf("sorted-resample/samples=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				legacyBootstrapCI(samples, 2*time.Second, 42)
			}
		})
	}
}

// BenchmarkBootstrapPairedCI is the same comparison for the paired-effect
// median, which runs once for every non-reference target.
func BenchmarkBootstrapPairedCI(b *testing.B) {
	for _, size := range []int{200, 2000} {
		_, deltas := benchmarkScoreSamples(size)
		b.Run(fmt.Sprintf("rank-counts/deltas=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				bootstrapPairedCI(deltas, 42)
			}
		})
		b.Run(fmt.Sprintf("sorted-resample/deltas=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				legacyBootstrapPairedCI(deltas, 42)
			}
		})
	}
}
