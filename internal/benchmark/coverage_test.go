package benchmark

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/catalog"
	"github.com/crypt0rr/dns-speedtest/internal/transport"
	"github.com/miekg/dns"
)

type fakeOpen struct {
	session transport.Session
	err     error
}

type fakeFactory struct {
	opens []fakeOpen
	mu    sync.Mutex
	count int
}

func (f *fakeFactory) Open(context.Context) (transport.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.count
	f.count++
	if index >= len(f.opens) {
		return nil, errors.New("unexpected factory open")
	}
	return f.opens[index].session, f.opens[index].err
}

type fakeSession struct {
	query    func(context.Context, string, uint16) (*dns.Msg, error)
	closeErr error
	closes   int
}

func (s *fakeSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if s.query == nil {
		return replyFor(name, qtype), nil
	}
	return s.query(ctx, name, qtype)
}

func (s *fakeSession) Close() error {
	s.closes++
	return s.closeErr
}

func replyFor(name string, qtype uint16) *dns.Msg {
	return &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: 0, Response: true},
		Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}},
	}
}

func testTarget(protocol catalog.Protocol, address string) catalog.Target {
	return catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "resolver-" + address, Name: "Resolver", Owner: "Owner", Policy: "unfiltered"},
		Protocol: protocol,
		Address:  address,
		Spec:     catalog.TransportSpec{Port: 53},
	}
}

func validBenchmarkOptions() Options {
	return Options{
		Domains:     []string{"Example.COM.", "example.org"},
		QueryTypes:  []uint16{dns.TypeA, dns.TypeAAAA},
		Sample:      1,
		Seed:        7,
		Timeout:     time.Second,
		Concurrency: 1,
	}
}

func TestRunValidationAndQueryConstruction(t *testing.T) {
	base := validBenchmarkOptions()
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"empty domains", Options{QueryTypes: base.QueryTypes, Sample: 1, Timeout: time.Second, Concurrency: 1}, "domain corpus is empty"},
		{"empty types", Options{Domains: base.Domains, Sample: 1, Timeout: time.Second, Concurrency: 1}, "at least one DNS query type"},
		{"invalid sample", Options{Domains: base.Domains, QueryTypes: base.QueryTypes, Timeout: time.Second, Concurrency: 1}, "sample size must be positive"},
		{"invalid timeout", Options{Domains: base.Domains, QueryTypes: base.QueryTypes, Sample: 1, Concurrency: 1}, "timeout must be positive"},
		{"invalid concurrency", Options{Domains: base.Domains, QueryTypes: base.QueryTypes, Sample: 1, Timeout: time.Second}, "concurrency must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "one")}, tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run error = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := Run(context.Background(), nil, base); err == nil || !strings.Contains(err.Error(), "no supported") {
		t.Fatalf("empty target error = %v", err)
	}
	if _, err := buildQueries(Options{Domains: []string{" ", "# ignored"}, QueryTypes: base.QueryTypes, Sample: 1, Seed: 1}); err == nil {
		t.Fatal("expected an empty normalized corpus error")
	}
	if _, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "build-error")}, Options{Domains: []string{"# ignored"}, QueryTypes: base.QueryTypes, Sample: 1, Timeout: time.Second, Concurrency: 1}); err == nil || !strings.Contains(err.Error(), "no valid names") {
		t.Fatalf("Run build error = %v", err)
	}

	full := base
	full.Full = true
	full.Sample = 0
	queries, err := buildQueries(full)
	if err != nil || len(queries) != 4 {
		t.Fatalf("full query construction = %d, %v; want 4, nil", len(queries), err)
	}
	large := base
	large.Sample = 99
	queries, err = buildQueries(large)
	if err != nil || len(queries) != 4 {
		t.Fatalf("oversized sample construction = %d, %v; want 4, nil", len(queries), err)
	}
	if got := normalizeDomains([]string{" A.Example. ", "a.example", "", " # comment", "B.example"}); len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("normalized domains = %#v", got)
	}
}

func TestRunAndProtocolScheduling(t *testing.T) {
	oldTarget := runTargetFunc
	t.Cleanup(func() { runTargetFunc = oldTarget })
	var progress []Progress
	runTargetFunc = func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target, Observations: []Observation{{Success: true, LatencyMS: 2, ResponseClass: "answer"}}}
	}
	opts := validBenchmarkOptions()
	opts.OnProgress = func(p Progress) { progress = append(progress, p) }
	targets := []catalog.Target{testTarget(catalog.TCP, "two"), testTarget(catalog.UDP, "one")}
	report, err := Run(context.Background(), targets, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Targets) != 2 || len(report.Rankings) != 2 || len(progress) != 2 {
		t.Fatalf("report targets/rankings/progress = %d/%d/%d", len(report.Targets), len(report.Rankings), len(progress))
	}
	if _, ok := report.ResultFor(report.Targets[0].Target.ID()); !ok {
		t.Fatal("ResultFor did not find an existing result")
	}
	if _, ok := report.ResultFor("missing"); ok {
		t.Fatal("ResultFor found a missing result")
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	runTargetFunc = func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		once.Do(func() { close(started) })
		<-release
		return TargetResult{Target: target}
	}
	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan []TargetResult, 1)
	var cancelledProgress []Progress
	go func() {
		resultCh <- runProtocol(ctx, targets, []Query{{Name: "x", QType: dns.TypeA}}, Options{
			Concurrency: 1,
			OnProgress: func(progress Progress) {
				cancelledProgress = append(cancelledProgress, progress)
			},
		})
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	cancel()
	close(release)
	if got := <-resultCh; len(got) != 1 || got[0].Target.ID() != targets[0].ID() {
		t.Fatalf("cancelled scheduler results = %#v, want only dispatched target %#v", got, targets[0])
	}
	if len(cancelledProgress) != 1 || cancelledProgress[0].Completed != 1 || cancelledProgress[0].Total != len(targets) {
		t.Fatalf("cancelled scheduler progress = %#v, want one completed dispatched target", cancelledProgress)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	runTargetFunc = func(ctx context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		cancel()
		return TargetResult{Target: target, Observations: []Observation{{Success: true, LatencyMS: 1}}}
	}
	cancelledTargets := []catalog.Target{testTarget(catalog.TCP, "cancel-first"), testTarget(catalog.UDP, "not-dispatched")}
	cancelledReport, err := Run(ctx, cancelledTargets, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Run error = %v, want context canceled", err)
	}
	if len(cancelledReport.Targets) != 1 || cancelledReport.Targets[0].Target.ID() == "@/" || cancelledReport.Targets[0].Target.ID() != cancelledTargets[0].ID() {
		t.Fatalf("cancelled Run targets = %#v, want only the first dispatched target", cancelledReport.Targets)
	}

	runTargetFunc = func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target}
	}
	if _, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "none")}, opts); err == nil || !strings.Contains(err.Error(), "no comparable") {
		t.Fatalf("unscored Run error = %v", err)
	}
}

func TestRunNoComparableReportsRetainUnavailableTargets(t *testing.T) {
	oldTarget := runTargetFunc
	t.Cleanup(func() { runTargetFunc = oldTarget })
	runTargetFunc = func(_ context.Context, target catalog.Target, queries []Query, _ Options) TargetResult {
		return TargetResult{
			Target: target, OpenError: "connection refused",
			Observations: failedObservations(queries, errors.New("connection refused")),
		}
	}
	opts := validBenchmarkOptions()
	opts.Domains = []string{"example.com"}
	opts.QueryTypes = []uint16{dns.TypeA}
	targets := []catalog.Target{testTarget(catalog.UDP, "unavailable-a"), testTarget(catalog.UDP, "unavailable-b")}
	report, err := Run(context.Background(), targets, opts)
	if !errors.Is(err, ErrNoComparableResults) {
		t.Fatalf("Run error = %v, want no-comparable error", err)
	}
	if report.FinishedAt.IsZero() || len(report.Targets) != len(targets) || len(report.Rankings) != 0 {
		t.Fatalf("unavailable report metadata/results = %#v", report)
	}
	joined := strings.Join(report.Warnings, "\n")
	if !strings.Contains(joined, "connection refused") || !strings.Contains(joined, "failed queries") {
		t.Fatalf("unavailable report warnings = %#v", report.Warnings)
	}
}

func TestRunNoComparableReportsRetainUnusableResolverResponses(t *testing.T) {
	oldTarget := runTargetFunc
	t.Cleanup(func() { runTargetFunc = oldTarget })
	runTargetFunc = func(_ context.Context, target catalog.Target, queries []Query, _ Options) TargetResult {
		observations := make([]Observation, 0, len(queries))
		for _, query := range queries {
			observations = append(observations, Observation{
				Name: query.Name, QType: query.QType, Success: true, Usable: false,
				RCode: dns.RcodeServerFailure, ResponseClass: "rcode-2", LatencyMS: 1,
			})
		}
		return TargetResult{Target: target, Observations: observations}
	}
	opts := validBenchmarkOptions()
	opts.Domains = []string{"example.com"}
	opts.QueryTypes = []uint16{dns.TypeA}
	targets := []catalog.Target{testTarget(catalog.UDP, "servfail-a"), testTarget(catalog.UDP, "servfail-b")}
	report, err := Run(context.Background(), targets, opts)
	if !errors.Is(err, ErrNoComparableResults) {
		t.Fatalf("Run error = %v, want no-comparable error", err)
	}
	if report.FinishedAt.IsZero() || len(report.Targets) != len(targets) || len(report.Rankings) != 0 {
		t.Fatalf("unusable-response report metadata/results = %#v", report)
	}
	joined := strings.Join(report.Warnings, "\n")
	if !strings.Contains(joined, "unusable DNS responses") || !strings.Contains(joined, "SERVFAIL:1") {
		t.Fatalf("unusable-response report warnings = %#v", report.Warnings)
	}
}

func TestRunProtocolCancellationBeforeDispatch(t *testing.T) {
	oldTarget := runTargetFunc
	t.Cleanup(func() { runTargetFunc = oldTarget })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := runProtocol(ctx, []catalog.Target{testTarget(catalog.UDP, "one")}, nil, Options{Concurrency: 5})
	if len(results) != 0 {
		t.Fatalf("pre-cancelled scheduler results = %#v", results)
	}
}

func TestRunTargetWithScriptedTransport(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	coldError := errors.New("cold query failed")
	warmError := errors.New("warm query failed")
	cold := []*fakeSession{
		{query: func(context.Context, string, uint16) (*dns.Msg, error) {
			return replyFor("example.com", dns.TypeA), nil
		}},
		{query: func(context.Context, string, uint16) (*dns.Msg, error) { return nil, coldError }},
		{query: func(context.Context, string, uint16) (*dns.Msg, error) {
			return replyFor("example.com", dns.TypeA), nil
		}},
	}
	warm := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		switch name {
		case "example.org":
			return nil, warmError
		case "truncated.example":
			message := replyFor(name, qtype)
			message.Truncated = true
			return message, nil
		case "error.example":
			return nil, errors.New("measured query failed")
		default:
			return replyFor(name, qtype), nil
		}
	}}
	factory := &fakeFactory{opens: []fakeOpen{{session: cold[0]}, {session: cold[1]}, {session: cold[2]}, {session: warm}}}
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) { return factory, nil }
	result := runTarget(context.Background(), testTarget(catalog.UDP, "scripted"), []Query{
		{Name: "ok.example", QType: dns.TypeA}, {Name: "truncated.example", QType: dns.TypeAAAA}, {Name: "error.example", QType: dns.TypeA},
	}, Options{QueryTypes: []uint16{dns.TypeA, dns.TypeAAAA}, Timeout: time.Second})
	if len(result.Cold) != 3 || !result.Cold[0].Success || result.Cold[1].Error != coldError.Error() || len(result.Observations) != 3 {
		t.Fatalf("scripted cold/observations = %#v/%#v", result.Cold, result.Observations)
	}
	if !result.Observations[0].Success || !result.Observations[0].Usable || result.Observations[0].RCode != dns.RcodeSuccess || !result.Observations[1].Truncated || result.Observations[1].Error == "" || result.Observations[2].Error == "" {
		t.Fatalf("scripted observations = %#v", result.Observations)
	}
	if warm.closes != 1 || cold[0].closes != 1 || cold[1].closes != 1 || cold[2].closes != 1 {
		t.Fatalf("session close counts = %d/%d/%d/%d", warm.closes, cold[0].closes, cold[1].closes, cold[2].closes)
	}

	nilSession := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		if name == "nil.example" {
			return nil, nil
		}
		return replyFor(name, qtype), nil
	}}
	nilFactory := &fakeFactory{opens: []fakeOpen{{session: &fakeSession{}}, {session: &fakeSession{}}, {session: &fakeSession{}}, {session: nilSession}}}
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) { return nilFactory, nil }
	nilResult := runTarget(context.Background(), testTarget(catalog.UDP, "nil-response"), []Query{{Name: "nil.example", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(nilResult.Observations) != 1 || nilResult.Observations[0].Success || nilResult.Observations[0].Error != "empty DNS response" {
		t.Fatalf("nil response observation = %#v", nilResult.Observations)
	}
}

func TestRunTargetFactoryAndOpenErrors(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) {
		return nil, errors.New("factory creation failed")
	}
	result := runTarget(context.Background(), testTarget(catalog.UDP, "factory"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if result.OpenError != "factory creation failed" || len(result.Observations) != 1 {
		t.Fatalf("factory error result = %#v", result)
	}

	first := &fakeSession{}
	second := &fakeSession{}
	third := &fakeSession{}
	factory := &fakeFactory{opens: []fakeOpen{{err: errors.New("cold open 1")}, {err: errors.New("cold open 2")}, {err: errors.New("cold open 3")}, {session: &fakeSession{}}}}
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) { return factory, nil }
	result = runTarget(context.Background(), testTarget(catalog.UDP, "cold-open"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(result.Cold) != 3 || result.Cold[0].Error == "" || result.OpenError != "" {
		t.Fatalf("cold open result = %#v", result)
	}

	factory = &fakeFactory{opens: []fakeOpen{{session: first}, {session: second}, {session: third}, {err: errors.New("warm open failed")}}}
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) { return factory, nil }
	result = runTarget(context.Background(), testTarget(catalog.UDP, "warm-open"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if result.OpenError != "warm open failed" || len(result.Observations) != 1 || result.Observations[0].Error != "warm open failed" {
		t.Fatalf("warm open result = %#v", result)
	}
}

func TestRunTargetStopsWhenContextCancelsDuringWarmup(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	ctx, cancel := context.WithCancel(context.Background())
	warm := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		if name == "example.com" {
			cancel()
		}
		return replyFor(name, qtype), nil
	}}
	factory := &fakeFactory{opens: []fakeOpen{{session: &fakeSession{}}, {session: &fakeSession{}}, {session: &fakeSession{}}, {session: warm}}}
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) { return factory, nil }
	result := runTarget(ctx, testTarget(catalog.UDP, "cancel-warmup"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if result.OpenError != context.Canceled.Error() || result.Observations[0].Error != context.Canceled.Error() {
		t.Fatalf("cancelled warmup result = %#v", result)
	}

	ctx, cancel = context.WithCancel(context.Background())
	warm = &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		if name == "example.net" {
			cancel()
		}
		return replyFor(name, qtype), nil
	}}
	factory = &fakeFactory{opens: []fakeOpen{{session: &fakeSession{}}, {session: &fakeSession{}}, {session: &fakeSession{}}, {session: warm}}}
	newFactory = func(catalog.Target, time.Duration) (transport.Factory, error) { return factory, nil }
	result = runTarget(ctx, testTarget(catalog.UDP, "cancel-query"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if result.OpenError != "" || result.Observations[0].Error != context.Canceled.Error() {
		t.Fatalf("cancelled measured query result = %#v", result)
	}
}

func TestStatisticsRankingAndWarnings(t *testing.T) {
	target := testTarget(catalog.UDP, "stats")
	result := TargetResult{Target: target, Observations: []Observation{
		{Success: true, LatencyMS: 4, ResponseClass: "answer", Divergent: true},
		{Success: false, Error: "timeout"},
		{Success: true, Truncated: true, LatencyMS: 9},
	}, Cold: []ColdObservation{{Success: true, LatencyMS: 6}, {Success: false}, {Success: true, LatencyMS: 8}}}
	stats := calculateStatistics(result, 2*time.Second, 11)
	if stats.Total != 3 || stats.Successes != 2 || stats.Failures != 1 || stats.Divergent != 1 || stats.Truncated != 1 || stats.Scored != 0 || stats.ColdMedianMS != 7 {
		t.Fatalf("mixed statistics = %#v", stats)
	}
	empty := calculateStatistics(TargetResult{}, time.Second, 1)
	if empty.Total != 0 || empty.SuccessRate != 0 || empty.Recommended {
		t.Fatalf("empty statistics = %#v", empty)
	}

	first := TargetResult{Target: testTarget(catalog.UDP, "fast"), Stats: Statistics{Scored: 2, ScoreMS: 1, CILowMS: 0, CIHighMS: 1}}
	second := TargetResult{Target: testTarget(catalog.UDP, "slow"), Stats: Statistics{Scored: 2, ScoreMS: 2, CILowMS: 0.5, CIHighMS: 3}}
	other := TargetResult{Target: testTarget(catalog.TCP, "other"), Stats: Statistics{Scored: 2, ScoreMS: 5, CILowMS: 5, CIHighMS: 5}}
	rankings := makeRankings([]TargetResult{second, other, first})
	if len(rankings) != 3 || rankings[0].Protocol != catalog.TCP || rankings[0].Rank != 1 || !rankings[2].Tie {
		t.Fatalf("rankings = %#v", rankings)
	}
	if len(makeRankings(nil)) != 0 || len(makeRankings([]TargetResult{{Target: target}})) != 0 {
		t.Fatal("unscored results should not be ranked")
	}

	warningResult := TargetResult{Target: target, OpenError: "open failed", Stats: Statistics{Total: 4, Failures: 1, Divergent: 1, Truncated: 1, Scored: 1, Recommended: false}}
	warnings := collectWarnings([]TargetResult{warningResult})
	if len(warnings) != 5 {
		t.Fatalf("warnings = %#v", warnings)
	}
	if got := failedObservations([]Query{{Name: "x", QType: dns.TypeA}}, errors.New("failed")); got[0].Error != "failed" {
		t.Fatalf("failed observation = %#v", got)
	}
}

func TestDivergenceAndStatisticsHelpers(t *testing.T) {
	results := []TargetResult{
		{Observations: []Observation{{Name: "EXAMPLE.COM", QType: dns.TypeA, Success: true, ResponseClass: "answer"}, {Name: "skip", QType: dns.TypeA, Success: false}}},
		{Observations: []Observation{{Name: "example.com", QType: dns.TypeA, Success: true, ResponseClass: "nxdomain"}}},
	}
	markDivergence(results)
	if !results[0].Observations[0].Divergent || !results[1].Observations[0].Divergent {
		t.Fatal("expected normalized divergent query keys")
	}
	if queryKey("Example.COM", dns.TypeA) != "example.com/1" {
		t.Fatal("unexpected query key")
	}

	if got := percentile(nil, .5); got != 0 {
		t.Fatalf("empty percentile = %v", got)
	}
	if got := percentile([]float64{3}, .5); got != 3 {
		t.Fatalf("single percentile = %v", got)
	}
	if got := percentile([]float64{1, 3, 7, 9}, .25); got != 2.5 {
		t.Fatalf("interpolated percentile = %v", got)
	}
	if low, high := bootstrapCI(nil, .25, 2*time.Second, 1); low != 500 || high != 500 {
		t.Fatalf("empty bootstrap CI = %v/%v", low, high)
	}
	if low, high := bootstrapCI([]float64{10}, .5, 2*time.Second, 1); low != high || low != 1010 {
		t.Fatalf("single bootstrap CI = %v/%v", low, high)
	}
	if got := QueryTypeName(dns.TypeAAAA); got != "AAAA" {
		t.Fatalf("known query type = %q", got)
	}
	if got := QueryTypeName(65000); got != "TYPE65000" {
		t.Fatalf("unknown query type = %q", got)
	}
	if got := sessionDialAddress(&fakeSession{}); got != "" {
		t.Fatalf("session without dial metadata = %q", got)
	}
	if got := sessionDialAddress(&reportedSession{address: "192.0.2.1:853"}); got != "192.0.2.1:853" {
		t.Fatalf("reported session dial metadata = %q", got)
	}
}

type reportedSession struct {
	fakeSession
	address string
}

func (s *reportedSession) DialAddress() string { return s.address }
