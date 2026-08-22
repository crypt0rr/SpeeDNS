package benchmark

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
)

func TestBuildQueriesIsDeterministic(t *testing.T) {
	opts := Options{Domains: []string{"a.example", "b.example", "c.example"}, QueryTypes: []uint16{1, 28}, Sample: 2, Seed: 42}
	first, err := buildQueries(opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildQueries(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 4 {
		t.Fatalf("query count = %d, want 4", len(first))
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("query order changed at %d: %#v != %#v", index, first[index], second[index])
		}
	}
}

func TestStatisticsAndRanking(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "test", Name: "Test", Owner: "Test", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "127.0.0.1",
	}
	observations := make([]Observation, 0, 20)
	for index := 0; index < 20; index++ {
		observations = append(observations, Observation{Success: true, LatencyMS: float64(index + 1), ResponseClass: "answer"})
	}
	result := TargetResult{Target: target, Observations: observations}
	stats := calculateStatistics(result, 2*time.Second, 1)
	if stats.Scored != 20 || !stats.Recommended {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if stats.MedianMS <= 0 || stats.P95MS < stats.MedianMS || stats.ScoreMS <= 0 {
		t.Fatalf("invalid latency stats: %#v", stats)
	}
}

func TestRunWarnsWhenSampleIsClamped(t *testing.T) {
	oldTarget := runTargetFunc
	t.Cleanup(func() { runTargetFunc = oldTarget })
	runTargetFunc = func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target, Observations: []Observation{{
			Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 1,
		}}}
	}

	opts := validBenchmarkOptions()
	opts.Domains = []string{"Example.COM.", "example.com", "example.org"}
	opts.QueryTypes = []uint16{dns.TypeA}
	opts.Sample = 99
	report, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "sample-warning")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if report.SampleSize != 2 || report.Queries != 2 {
		t.Fatalf("effective sample = %d domains/%d queries, want 2/2", report.SampleSize, report.Queries)
	}
	if !containsWarning(report.Warnings, "requested sample of 99 domains") || !containsWarning(report.Warnings, "using all 2 domains") {
		t.Fatalf("sample clamp warnings = %#v", report.Warnings)
	}

	opts.Sample = 2
	report, err = Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "sample-fits")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if containsWarning(report.Warnings, "requested sample") {
		t.Fatalf("unexpected warning for fitting sample: %#v", report.Warnings)
	}

	opts.Full = true
	opts.Sample = 99
	report, err = Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "sample-full")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if containsWarning(report.Warnings, "requested sample") {
		t.Fatalf("unexpected warning for full sample: %#v", report.Warnings)
	}

	runTargetFunc = func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target}
	}
	opts.Full = false
	opts.Sample = 99
	report, err = Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "sample-no-result")}, opts)
	if err == nil || !strings.Contains(err.Error(), "no comparable") {
		t.Fatalf("no-comparable sample run error = %v", err)
	}
	if !containsWarning(report.Warnings, "requested sample of 99 domains") {
		t.Fatalf("no-comparable report lost sample warning: %#v", report.Warnings)
	}
}

func containsWarning(warnings []string, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, fragment) {
			return true
		}
	}
	return false
}

func TestDivergentResponsesAreExcluded(t *testing.T) {
	results := []TargetResult{
		{Observations: []Observation{{Name: "example.com", QType: 1, Success: true, LatencyMS: 5, ResponseClass: "answer"}}},
		{Observations: []Observation{{Name: "example.com", QType: 1, Success: true, LatencyMS: 2, ResponseClass: "nxdomain"}}},
	}
	markDivergence(results)
	for _, result := range results {
		if !result.Observations[0].Divergent {
			t.Fatal("expected response-class divergence to be marked")
		}
	}
}

func TestPercentileAndMAD(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5}
	if got := percentile(values, .5); got != 3 {
		t.Fatalf("median = %v, want 3", got)
	}
	if got := mad(values, 3); got != 1 {
		t.Fatalf("MAD = %v, want 1", got)
	}
}

func TestResolverErrorsAreNotScored(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "test", Name: "Test", Owner: "Test", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "127.0.0.1",
	}
	result := TargetResult{Target: target, Observations: []Observation{
		{Name: "answer.example", Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 20},
		{Name: "servfail.example", Success: true, RCode: dns.RcodeServerFailure, ResponseClass: "rcode-2", LatencyMS: 1},
		{Name: "refused.example", Success: true, RCode: dns.RcodeRefused, ResponseClass: "rcode-5", LatencyMS: 1},
	}}
	stats := calculateStatistics(result, 2*time.Second, 1)
	if stats.Successes != 3 || stats.Failures != 0 {
		t.Fatalf("transport statistics = %#v", stats)
	}
	if stats.UsableResponses != 1 || stats.ResolverFailures != 2 || stats.Scored != 1 {
		t.Fatalf("semantic statistics = %#v", stats)
	}
	if stats.RCodeCounts["SERVFAIL"] != 1 || stats.RCodeCounts["REFUSED"] != 1 {
		t.Fatalf("rcode counts = %#v", stats.RCodeCounts)
	}
	if observationUsable(Observation{Success: true, ResponseClass: "unexpected"}) {
		t.Fatal("unknown response classes should not be usable")
	}
	if formatRCodeCounts(nil) != "" {
		t.Fatal("empty RCODE counts should format as empty")
	}
	if stats.ScoreMS <= 1000 {
		t.Fatalf("resolver-error penalty missing from score: %#v", stats)
	}

	result.Stats = stats
	rankings := makeRankings([]TargetResult{result, {Target: target, Stats: Statistics{Scored: 0, ScoreMS: 0}}})
	if len(rankings) != 1 {
		t.Fatalf("resolver-error target should not be ranked: %#v", rankings)
	}
}

func TestRecommendationRequiresUsableResponses(t *testing.T) {
	target := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "test", Name: "Test", Owner: "Test", Policy: "unfiltered"},
		Protocol: catalog.UDP,
		Address:  "127.0.0.1",
	}
	observations := make([]Observation, 0, 21)
	for index := 0; index < 20; index++ {
		observations = append(observations, Observation{
			Name: "answer.example", Success: true, Usable: true, RCode: dns.RcodeSuccess,
			ResponseClass: "answer", LatencyMS: float64(index + 1),
		})
	}
	observations = append(observations, Observation{
		Name: "servfail.example", Success: true, RCode: dns.RcodeServerFailure,
		ResponseClass: "rcode-2", LatencyMS: 1,
	})
	stats := calculateStatistics(TargetResult{Target: target, Observations: observations}, 2*time.Second, 1)
	if stats.SuccessRate != 1 || stats.UsableRate >= MinimumRecommendedSuccessRate || stats.Scored != 20 || stats.Recommended {
		t.Fatalf("recommendation ignored unusable response: %#v", stats)
	}

	warnings := collectWarnings([]TargetResult{{
		Target: target,
		Stats:  Statistics{Total: 2, Scored: 1, ResolverFailures: 1, RCodeCounts: map[string]int{"SERVFAIL": 1}},
	}})
	if len(warnings) != 2 || !strings.Contains(strings.Join(warnings, "\n"), "SERVFAIL:1") {
		t.Fatalf("resolver-error warnings = %#v", warnings)
	}
}

func TestPairedEffectsAreDeterministicAndPolicyLocal(t *testing.T) {
	observation := func(name string, latency float64) Observation {
		return Observation{Name: name, QType: dns.TypeA, Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: latency}
	}
	reference := testTarget(catalog.UDP, "reference")
	slower := testTarget(catalog.UDP, "slower")
	noise := testTarget(catalog.UDP, "noise")
	protective := testTarget(catalog.UDP, "protective")
	protective.Resolver.Policy = " Protective "
	missing := testTarget(catalog.UDP, "missing")
	unscored := testTarget(catalog.UDP, "unscored")
	incomplete := testTarget(catalog.UDP, "incomplete")
	emptyReference := testTarget(catalog.TCP, "empty-reference")

	referenceResult := TargetResult{
		Target: reference,
		Stats:  Statistics{Scored: 2, ScoreMS: 1},
		Observations: []Observation{
			observation("A.Example.", 10), observation("b.example", 20),
			observation("a.example", 99),
			{Success: false, Name: "failed.example", QType: dns.TypeA},
			{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: math.NaN()},
			{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: math.Inf(1)},
			{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: -1},
		},
	}
	slowerResult := TargetResult{
		Target: slower, Stats: Statistics{Scored: 2, ScoreMS: 2},
		Observations: []Observation{observation("a.example", 12), observation("B.EXAMPLE.", 25),
			{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: 50, Divergent: true},
			{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: 50, Reconnected: true}},
	}
	noiseResult := TargetResult{
		Target: noise, Stats: Statistics{Scored: 2, ScoreMS: 3},
		Observations: []Observation{observation("a.example", 9), observation("b.example", 21)},
	}
	protectiveResult := TargetResult{
		Target: protective, Stats: Statistics{Scored: 1, ScoreMS: 4},
		Observations: []Observation{observation("a.example", 30)},
	}
	missingResult := TargetResult{
		Target: missing, Stats: Statistics{Scored: 1, ScoreMS: 5},
		Observations: []Observation{observation("other.example", 40)},
	}
	results := []TargetResult{
		referenceResult, slowerResult, noiseResult, protectiveResult, missingResult,
		{Target: unscored}, {Target: incomplete, Incomplete: true, Stats: Statistics{Scored: 1, ScoreMS: 0.5}},
		{Target: emptyReference, Stats: Statistics{Scored: 1, ScoreMS: 6}},
	}
	rankings := []Ranking{
		{Protocol: catalog.UDP, TargetID: reference.ID(), Rank: 1},
		{Protocol: catalog.UDP, TargetID: slower.ID(), Rank: 2},
		{Protocol: catalog.UDP, TargetID: noise.ID(), Rank: 3},
		{Protocol: catalog.UDP, TargetID: protective.ID(), Rank: 4},
	}
	first := calculatePairedEffects(results, rankings, 42)
	second := calculatePairedEffects(results, rankings, 42)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("paired effects are not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	find := func(id string) PairedEffect {
		for _, effect := range first {
			if effect.TargetID == id {
				return effect
			}
		}
		t.Fatalf("missing paired effect for %s: %#v", id, first)
		return PairedEffect{}
	}
	refEffect := find(reference.ID())
	if !refEffect.Reference || refEffect.ReferenceTargetID != reference.ID() || refEffect.Samples != 2 || refEffect.Reason != "" {
		t.Fatalf("reference effect = %#v", refEffect)
	}
	slowEffect := find(slower.ID())
	if slowEffect.Samples != 2 || slowEffect.MedianDeltaMS != 3.5 || slowEffect.Indistinguishable {
		t.Fatalf("slower effect = %#v", slowEffect)
	}
	noiseEffect := find(noise.ID())
	if noiseEffect.Samples != 2 || !noiseEffect.Indistinguishable || noiseEffect.CILowMS > 0 || noiseEffect.CIHighMS < 0 {
		t.Fatalf("noise effect = %#v", noiseEffect)
	}
	protectiveEffect := find(protective.ID())
	if !protectiveEffect.Reference || protectiveEffect.Policy != "protective" || protectiveEffect.Samples != 1 {
		t.Fatalf("policy-local effect = %#v", protectiveEffect)
	}
	missingEffect := find(missing.ID())
	if missingEffect.Samples != 0 || missingEffect.Reason != "no shared scored samples" {
		t.Fatalf("missing-pair effect = %#v", missingEffect)
	}
	if len(first) != 6 {
		t.Fatalf("paired effect count = %d, want 6", len(first))
	}
	emptyEffect := find(emptyReference.ID())
	if !emptyEffect.Reference || emptyEffect.Samples != 0 || emptyEffect.Reason != "no scored samples" {
		t.Fatalf("empty reference effect = %#v", emptyEffect)
	}

	fallbackA := testTarget(catalog.TCP, "fallback-a")
	fallbackB := testTarget(catalog.TCP, "fallback-b")
	fallback := calculatePairedEffects([]TargetResult{
		{Target: fallbackB, Stats: Statistics{Scored: 1, ScoreMS: 2}, Observations: []Observation{observation("a.example", 2)}},
		{Target: fallbackA, Stats: Statistics{Scored: 1, ScoreMS: 1}, Observations: []Observation{observation("a.example", 1)}},
	}, nil, 42)
	if len(fallback) != 2 || fallback[0].ReferenceTargetID != fallbackA.ID() {
		t.Fatalf("unranked fallback reference = %#v", fallback)
	}
	equalFallback := calculatePairedEffects([]TargetResult{
		{Target: fallbackB, Stats: Statistics{Scored: 1, ScoreMS: 1}, Observations: []Observation{observation("a.example", 2)}},
		{Target: fallbackA, Stats: Statistics{Scored: 1, ScoreMS: 1}, Observations: []Observation{observation("a.example", 1)}},
	}, nil, 42)
	if len(equalFallback) != 2 || equalFallback[0].ReferenceTargetID != fallbackA.ID() {
		t.Fatalf("equal unranked fallback reference = %#v", equalFallback)
	}

	if low, high := bootstrapPairedCI(nil, 1); low != 0 || high != 0 {
		t.Fatalf("empty paired interval = %v/%v", low, high)
	}
	if low, high := bootstrapPairedCI([]float64{2}, 1); low != 2 || high != 2 {
		t.Fatalf("single paired interval = %v/%v", low, high)
	}
	if low, high := bootstrapPairedCI([]float64{1, 3}, 1); low > high {
		t.Fatalf("paired interval inverted = %v/%v", low, high)
	}
	if pairedBootstrapSeed(1, catalog.UDP, "unfiltered", "a", "b") == pairedBootstrapSeed(1, catalog.UDP, "unfiltered", "a", "c") {
		t.Fatal("paired bootstrap seed ignored target identity")
	}
}
