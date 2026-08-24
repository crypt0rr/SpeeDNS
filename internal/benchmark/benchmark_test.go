package benchmark

import (
	"context"
	"fmt"
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
		observations = append(observations, Observation{Success: true, Latency: time.Duration(index+1) * time.Millisecond, LatencyMS: float64(index + 1), ResponseClass: "answer"})
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
	useTargetSeam(t, func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target, Observations: []Observation{{
			Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 1,
		}}}
	})

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

func containsWarning(warnings []Warning, fragment string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning.String(), fragment) {
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
	if len(warnings) != 2 || !strings.Contains(warningText(warnings), "SERVFAIL:1") {
		t.Fatalf("resolver-error warnings = %#v", warnings)
	}
}

func TestPairedEffectsAreDeterministicAndProtocolScoped(t *testing.T) {
	observation := func(name string, latency float64) Observation {
		return Observation{Name: name, QType: dns.TypeA, Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: latency}
	}
	series := func(count int, latency func(index int) float64) []Observation {
		observations := make([]Observation, 0, count)
		for index := 0; index < count; index++ {
			observations = append(observations, observation(fmt.Sprintf("q%02d.Example.", index), latency(index)))
		}
		return observations
	}
	reference := testTarget(catalog.UDP, "reference")
	slower := testTarget(catalog.UDP, "slower")
	noise := testTarget(catalog.UDP, "noise")
	few := testTarget(catalog.UDP, "few")
	protective := testTarget(catalog.UDP, "protective")
	protective.Resolver.Policy = " Protective "
	missing := testTarget(catalog.UDP, "missing")
	unscored := testTarget(catalog.UDP, "unscored")
	incomplete := testTarget(catalog.UDP, "incomplete")
	emptyReference := testTarget(catalog.TCP, "empty-reference")

	referenceResult := TargetResult{
		Target: reference,
		Stats:  Statistics{Scored: MinimumRecommendedSamples, ScoreMS: 1},
		Observations: append(series(MinimumRecommendedSamples, func(int) float64 { return 10 }),
			observation("q00.example", 99),
			Observation{Success: false, Name: "failed.example", QType: dns.TypeA},
			Observation{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: math.NaN()},
			Observation{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: math.Inf(1)},
			Observation{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: -1},
		),
	}
	slowerResult := TargetResult{
		Target: slower, Stats: Statistics{Scored: MinimumRecommendedSamples, ScoreMS: 2},
		Observations: append(series(MinimumRecommendedSamples, func(int) float64 { return 13.5 }),
			Observation{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: 50, Divergent: true},
			Observation{Success: true, Usable: true, ResponseClass: "answer", LatencyMS: 50, Reconnected: true}),
	}
	noiseResult := TargetResult{
		Target: noise, Stats: Statistics{Scored: MinimumRecommendedSamples, ScoreMS: 3},
		Observations: series(MinimumRecommendedSamples, func(index int) float64 {
			if index%2 == 0 {
				return 9
			}
			return 11
		}),
	}
	fewResult := TargetResult{
		Target:       few,
		Stats:        Statistics{Scored: MinimumRecommendedSamples - 1, ScoreMS: 3.5},
		Observations: series(MinimumRecommendedSamples-1, func(int) float64 { return 93.42 }),
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
		referenceResult, slowerResult, noiseResult, fewResult, protectiveResult, missingResult,
		{Target: unscored}, {Target: incomplete, Incomplete: true, Stats: Statistics{Scored: 1, ScoreMS: 0.5}},
		{Target: emptyReference, Stats: Statistics{Scored: 1, ScoreMS: 6}},
	}
	rankings := []Ranking{
		{Protocol: catalog.UDP, TargetID: reference.ID(), Rank: 1},
		{Protocol: catalog.UDP, TargetID: slower.ID(), Rank: 2},
		{Protocol: catalog.UDP, TargetID: noise.ID(), Rank: 3},
		{Protocol: catalog.UDP, TargetID: few.ID(), Rank: 4},
		{Protocol: catalog.UDP, TargetID: protective.ID(), Rank: 5},
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
	if !refEffect.Reference || refEffect.ReferenceTargetID != reference.ID() || refEffect.Samples != MinimumRecommendedSamples || refEffect.Reason != "" {
		t.Fatalf("reference effect = %#v", refEffect)
	}
	slowEffect := find(slower.ID())
	if slowEffect.Samples != MinimumRecommendedSamples || slowEffect.MedianDeltaMS != 3.5 || slowEffect.Indistinguishable || slowEffect.Reason != "" {
		t.Fatalf("slower effect = %#v", slowEffect)
	}
	noiseEffect := find(noise.ID())
	if noiseEffect.Samples != MinimumRecommendedSamples || !noiseEffect.Indistinguishable || noiseEffect.CILowMS > 0 || noiseEffect.CIHighMS < 0 {
		t.Fatalf("noise effect = %#v", noiseEffect)
	}
	fewEffect := find(few.ID())
	const wantReason = "insufficient paired samples"
	if fewEffect.Samples != MinimumRecommendedSamples-1 || fewEffect.Reason != wantReason {
		t.Fatalf("below-minimum effect = %#v", fewEffect)
	}
	if fewEffect.MedianDeltaMS != 0 || fewEffect.CILowMS != 0 || fewEffect.CIHighMS != 0 || fewEffect.Indistinguishable {
		t.Fatalf("below-minimum effect reported a difference: %#v", fewEffect)
	}
	// A resolver alone in its policy string used to be its own reference,
	// producing a self-comparison that told the reader nothing. It is now
	// compared against the protocol's rank-one target like every other member,
	// and its policy string survives as a label on the row.
	protectiveEffect := find(protective.ID())
	if protectiveEffect.Reference || protectiveEffect.Policy != "protective" {
		t.Fatalf("single-policy target must not be its own reference: %#v", protectiveEffect)
	}
	if protectiveEffect.ReferenceTargetID != reference.ID() {
		t.Fatalf("single-policy target compared against %q, want the protocol winner", protectiveEffect.ReferenceTargetID)
	}
	missingEffect := find(missing.ID())
	if missingEffect.Samples != 0 || missingEffect.Reason != "no shared scored samples" {
		t.Fatalf("missing-pair effect = %#v", missingEffect)
	}
	if len(first) != 7 {
		t.Fatalf("paired effect count = %d, want 7", len(first))
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
	if low, high := bootstrapPairedCI([]float64{1, 3}, 1); low > high {
		t.Fatalf("paired interval inverted = %v/%v", low, high)
	}
	if pairedBootstrapSeed(1, catalog.UDP, "a", "b") == pairedBootstrapSeed(1, catalog.UDP, "a", "c") {
		t.Fatal("paired bootstrap seed ignored target identity")
	}
	if pairedBootstrapSeed(1, catalog.UDP, "a", "b") == pairedBootstrapSeed(1, catalog.TCP, "a", "b") {
		t.Fatal("paired bootstrap seed ignored protocol")
	}
}

// slowBookkeepingSession delays the reconnect lookup that measure() performs
// after a query returns, which is the work the warm-latency timer must not
// charge to the resolver.
type slowBookkeepingSession struct {
	*fakeSession
	delay time.Duration
}

func (s *slowBookkeepingSession) LastQueryReconnected() bool {
	time.Sleep(s.delay)
	return false
}

func TestMeasureTimesOnlyTheExchange(t *testing.T) {
	const bookkeeping = 200 * time.Millisecond
	runner := &targetRunner{
		target:  testTarget(catalog.UDP, "192.0.2.1"),
		opts:    Options{Timeout: time.Second, QueryTypes: []uint16{dns.TypeA}},
		session: &slowBookkeepingSession{fakeSession: &fakeSession{}, delay: bookkeeping},
		ready:   true,
	}
	if !runner.measure(context.Background(), Query{Name: "example.com", QType: dns.TypeA}) {
		t.Fatal("measure did not record an observation")
	}
	observation := runner.result.Observations[0]
	if !observation.Success {
		t.Fatalf("measured observation = %#v", observation)
	}
	if observation.Latency >= bookkeeping {
		t.Fatalf("warm latency %v included %v of post-query bookkeeping", observation.Latency, bookkeeping)
	}
	if observation.LatencyMS != durationMS(observation.Latency) {
		t.Fatalf("latency milliseconds %v do not match %v", observation.LatencyMS, observation.Latency)
	}
}

// TestLocalResolverIsMeasuredButNeverRankedOrRecommended pins the
// non-comparability rule for a resolver running on the local host. A loopback
// stub answers from its own cache, so its latency excludes the upstream
// resolution it forwards to and must never win a ranking or carry a
// recommendation, however fast it looks.
func TestLocalResolverIsMeasuredButNeverRankedOrRecommended(t *testing.T) {
	observations := func(latency float64) []Observation {
		samples := make([]Observation, 0, MinimumRecommendedSamples)
		for index := 0; index < MinimumRecommendedSamples; index++ {
			samples = append(samples, Observation{
				Name: fmt.Sprintf("name%d.example", index), QType: dns.TypeA,
				Success: true, Usable: true, RCode: dns.RcodeSuccess,
				ResponseClass: "answer", LatencyMS: latency,
			})
		}
		return samples
	}

	stub := testTarget(catalog.UDP, "127.0.0.53")
	stub.Resolver.ID = "system-stub-127-0-0-53"
	stub.Resolver.Name = "System DNS stub"
	stub.Resolver.Policy = "local forwarding (upstream unknown)"
	stub.Resolver.Local = true
	network := testTarget(catalog.UDP, "192.0.2.53")

	stubResult := TargetResult{Target: stub, Observations: observations(0.2)}
	networkResult := TargetResult{Target: network, Observations: observations(12)}
	stubResult.Stats = calculateStatistics(stubResult, 2*time.Second, 7)
	networkResult.Stats = calculateStatistics(networkResult, 2*time.Second, 7)

	if stubResult.Stats.Scored != MinimumRecommendedSamples || stubResult.Stats.MedianMS != 0.2 {
		t.Fatalf("local stub measurement dropped: %#v", stubResult.Stats)
	}
	if stubResult.Stats.ScoreMS >= networkResult.Stats.ScoreMS {
		t.Fatalf("fixture must make the local stub look fastest: %v vs %v", stubResult.Stats.ScoreMS, networkResult.Stats.ScoreMS)
	}
	if stubResult.Stats.Recommended {
		t.Fatalf("local stub was marked recommendation-eligible: %#v", stubResult.Stats)
	}
	if !networkResult.Stats.Recommended {
		t.Fatalf("network resolver lost its recommendation: %#v", networkResult.Stats)
	}

	rankings := makeRankings([]TargetResult{stubResult, networkResult})
	if len(rankings) != 1 || rankings[0].TargetID != network.ID() || rankings[0].Rank != 1 {
		t.Fatalf("rankings admitted the local stub: %#v", rankings)
	}

	warnings := collectWarnings([]TargetResult{stubResult, networkResult})
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v", warnings)
	}
	for _, expected := range []string{"System DNS stub 127.0.0.53/udp", "cache-hit latency", "upstream resolution cost", "not comparable"} {
		if !strings.Contains(warnings[0].String(), expected) {
			t.Fatalf("non-comparability warning missing %q: %q", expected, warnings[0].String())
		}
	}
	if strings.Contains(warnings[0].String(), "recommendation-eligible yet") {
		t.Fatalf("local stub reported as a quality problem: %q", warnings[0])
	}

	// The classification, not the address, decides: the same loopback target
	// without the flag stays a normal ranked, recommendable resolver.
	unflagged := stubResult
	unflagged.Target.Resolver.Local = false
	unflagged.Stats = calculateStatistics(unflagged, 2*time.Second, 7)
	if !unflagged.Stats.Recommended {
		t.Fatalf("unflagged target lost its recommendation: %#v", unflagged.Stats)
	}
	if unflaggedRankings := makeRankings([]TargetResult{unflagged}); len(unflaggedRankings) != 1 {
		t.Fatalf("unflagged target was excluded from ranking: %#v", unflaggedRankings)
	}
}

// TestRunMeasuresProtocolsInDocumentedOrder pins the protocol execution order
// to METHODOLOGY.md. catalog.Protocol is a string type, so sorting the group
// keys by value ordered the groups lexicographically as doh, doq, dot, tcp,
// udp instead.
func TestRunMeasuresProtocolsInDocumentedOrder(t *testing.T) {
	// A target-level fake only takes effect under the legacy scheduler, which
	// since the scheduler became an explicit choice must be selected
	// deliberately rather than inferred from the seam being replaced.
	useTargetSeam(t, func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target, Observations: []Observation{{Success: true, LatencyMS: 3, ResponseClass: "answer"}}}
	})
	var measured []catalog.Protocol
	opts := validBenchmarkOptions()
	opts.OnProgress = func(progress Progress) {
		if progress.Phase == ProgressPreparing {
			measured = append(measured, progress.Protocol)
		}
	}
	// Supplied in the lexicographic order the defect produced so the assertion
	// fails if the input order leaks through.
	targets := []catalog.Target{
		testTarget(catalog.DoH, "doh"), testTarget(catalog.DoQ, "doq"), testTarget(catalog.DoT, "dot"),
		testTarget(catalog.TCP, "tcp"), testTarget(catalog.UDP, "udp"),
	}
	if _, err := Run(context.Background(), targets, opts); err != nil {
		t.Fatal(err)
	}
	want := []catalog.Protocol{catalog.UDP, catalog.TCP, catalog.DoH, catalog.DoT, catalog.DoQ}
	if !reflect.DeepEqual(measured, want) {
		t.Fatalf("measured protocol order = %#v, want %#v", measured, want)
	}
	if !reflect.DeepEqual(want, catalog.AllProtocols) {
		t.Fatalf("documented order = %#v, want catalog.AllProtocols %#v", want, catalog.AllProtocols)
	}
}
