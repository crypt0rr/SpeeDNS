package benchmark

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/domains"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
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

type scriptedFactory struct {
	open  func(int, context.Context) (transport.Session, error)
	count int
}

func (f *scriptedFactory) Open(ctx context.Context) (transport.Session, error) {
	index := f.count
	f.count++
	return f.open(index, ctx)
}

type fakeSession struct {
	query       func(context.Context, string, uint16) (*dns.Msg, error)
	closeErr    error
	closeDelay  time.Duration
	reconnected bool
	closes      int
}

func (s *fakeSession) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if s.query == nil {
		return replyFor(name, qtype), nil
	}
	return s.query(ctx, name, qtype)
}

func (s *fakeSession) Close() error {
	if s.closeDelay > 0 {
		time.Sleep(s.closeDelay)
	}
	s.closes++
	return s.closeErr
}

func (s *fakeSession) LastQueryReconnected() bool { return s.reconnected }

type minimalSession struct{}

func (minimalSession) Query(context.Context, string, uint16) (*dns.Msg, error) {
	return replyFor("example.com", dns.TypeA), nil
}

func (minimalSession) Close() error { return nil }

type cancelDialSession struct {
	*fakeSession
	cancel context.CancelFunc
}

func (s *cancelDialSession) DialAddress() string {
	s.cancel()
	return ""
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

// useTargetSeam selects the legacy target-level scheduler and installs seam as
// its runTargetFunc hook. Selecting the scheduler explicitly keeps a
// whole-target fake from silently deciding which scheduler is measured.
func useTargetSeam(t *testing.T, seam func(context.Context, catalog.Target, []Query, Options) TargetResult) {
	t.Helper()
	oldScheduler := runProtocol
	oldTarget := runTargetFunc
	t.Cleanup(func() {
		runProtocol = oldScheduler
		runTargetFunc = oldTarget
	})
	runProtocol = runProtocolLegacy
	runTargetFunc = seam
}

// useFairScheduler selects the scheduler the binary ships, so a test asserts
// production behaviour rather than the legacy target-level path.
func useFairScheduler(t *testing.T) {
	t.Helper()
	oldScheduler := runProtocol
	t.Cleanup(func() { runProtocol = oldScheduler })
	runProtocol = runProtocolFair
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
	if _, err := buildQueries(Options{Domains: []string{"bad..name"}, QueryTypes: base.QueryTypes, Sample: 1}); err == nil || !strings.Contains(err.Error(), "empty labels") {
		t.Fatalf("strict query construction error = %v", err)
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
	got, normalizeErr := domains.Normalize([]string{" A.Example. ", "a.example", "", " # comment", "B.example"})
	if normalizeErr != nil || len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("normalized domains = %#v/%v", got, normalizeErr)
	}
}

func TestRunAndProtocolScheduling(t *testing.T) {
	var progress []Progress
	useTargetSeam(t, func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target, Observations: []Observation{{Success: true, LatencyMS: 2, ResponseClass: "answer"}}}
	})
	opts := validBenchmarkOptions()
	opts.OnProgress = func(p Progress) { progress = append(progress, p) }
	targets := []catalog.Target{testTarget(catalog.TCP, "two"), testTarget(catalog.UDP, "one")}
	report, err := Run(context.Background(), targets, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Targets) != 2 || len(report.Rankings) != 2 || len(progress) != 6 {
		t.Fatalf("report targets/rankings/progress = %d/%d/%d", len(report.Targets), len(report.Rankings), len(progress))
	}
	wantPhases := []ProgressPhase{
		ProgressPreparing, ProgressMeasuring, ProgressComplete,
		ProgressPreparing, ProgressMeasuring, ProgressComplete,
	}
	for index, want := range wantPhases {
		if progress[index].Phase != want {
			t.Fatalf("progress[%d] phase = %q, want %q", index, progress[index].Phase, want)
		}
	}
	if progress[0].Protocol != catalog.UDP || progress[3].Protocol != catalog.TCP {
		t.Fatalf("progress protocol order = %#v/%#v, want udp then tcp", progress[0].Protocol, progress[3].Protocol)
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
	if len(cancelledProgress) != 3 {
		t.Fatalf("cancelled scheduler progress = %#v, want preparation, measuring, and complete events", cancelledProgress)
	}
	lastProgress := cancelledProgress[len(cancelledProgress)-1]
	if lastProgress.Phase != ProgressComplete || lastProgress.TargetsCompleted != 1 || lastProgress.TargetsTotal != len(targets) {
		t.Fatalf("cancelled scheduler final progress = %#v, want one completed dispatched target", lastProgress)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	runTargetFunc = func(ctx context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		cancel()
		return TargetResult{Target: target, Observations: []Observation{{Success: true, LatencyMS: 1}}}
	}
	cancelledTargets := []catalog.Target{testTarget(catalog.UDP, "cancel-first"), testTarget(catalog.TCP, "not-dispatched")}
	cancelledReport, err := Run(ctx, cancelledTargets, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Run error = %v, want context canceled", err)
	}
	if len(cancelledReport.Targets) != 1 || len(cancelledReport.Rankings) != 0 || !cancelledReport.Targets[0].Incomplete || cancelledReport.Targets[0].Target.ID() == "@/" || cancelledReport.Targets[0].Target.ID() != cancelledTargets[0].ID() {
		t.Fatalf("cancelled Run targets = %#v, want only the first dispatched target", cancelledReport.Targets)
	}

	runTargetFunc = func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target}
	}
	if _, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "none")}, opts); err == nil || !strings.Contains(err.Error(), "no comparable") {
		t.Fatalf("unscored Run error = %v", err)
	}
}

func TestFairProgressEventsCoverPreparationAndFailedExchanges(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)
	var opens int
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		opens++
		failedSession := func() transport.Session {
			return &fakeSession{query: func(context.Context, string, uint16) (*dns.Msg, error) {
				return nil, errors.New("fixture exchange failed")
			}}
		}
		return &fakeFactory{opens: []fakeOpen{
			{session: failedSession()},
			{session: failedSession()},
			{session: failedSession()},
			{session: failedSession()},
		}}, nil
	}
	queries := []Query{{Name: "a.example", QType: dns.TypeA}, {Name: "b.example", QType: dns.TypeA}}
	var events []Progress
	result := runProtocol(context.Background(), []catalog.Target{testTarget(catalog.UDP, "fixture")}, queries, Options{
		QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 1,
		OnProgress: func(progress Progress) { events = append(events, progress) },
	})
	if opens != 1 || len(result) != 1 || len(result[0].Observations) != len(queries) {
		t.Fatalf("fair progress fixture opens/results = %d/%d observations %d", opens, len(result), len(result[0].Observations))
	}
	if len(events) != 6 {
		t.Fatalf("fair progress events = %#v, want initial/preparation, measuring rounds, and complete", events)
	}
	if events[0].Phase != ProgressPreparing || events[0].TargetsCompleted != 0 || events[0].TargetsTotal != 1 {
		t.Fatalf("initial preparation event = %#v", events[0])
	}
	if events[1].Phase != ProgressPreparing || events[1].TargetsCompleted != 1 || events[1].TargetsTotal != 1 {
		t.Fatalf("completed preparation event = %#v", events[1])
	}
	if events[2].Phase != ProgressMeasuring || events[2].ExchangesCompleted != 0 || events[2].ExchangesTotal != 2 {
		t.Fatalf("initial measuring event = %#v", events[2])
	}
	if events[4].ExchangesCompleted != 2 || events[4].ExchangesTotal != 2 {
		t.Fatalf("failed exchanges were not counted as completed work = %#v", events[4])
	}
	last := events[len(events)-1]
	if last.Phase != ProgressComplete || last.ExchangesCompleted != 2 || last.ExchangesTotal != 2 {
		t.Fatalf("complete event = %#v", last)
	}
}

func TestFairProgressEventsReportOpenFailures(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return nil, errors.New("fixture open failed")
	}
	var events []Progress
	result := runProtocol(context.Background(), []catalog.Target{testTarget(catalog.DoQ, "fixture")}, []Query{{Name: "a.example", QType: dns.TypeA}}, Options{
		QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 1,
		OnProgress: func(progress Progress) { events = append(events, progress) },
	})
	if len(result) != 1 || result[0].OpenError == "" || len(result[0].Observations) != 1 {
		t.Fatalf("open failure result = %#v", result)
	}
	if len(events) != 4 {
		t.Fatalf("open failure progress = %#v, want preparation, measuring, and complete events", events)
	}
	if events[0].Phase != ProgressPreparing || events[0].TargetsCompleted != 0 {
		t.Fatalf("open failure initial event = %#v", events[0])
	}
	if events[1].Phase != ProgressPreparing || events[1].TargetsCompleted != 1 {
		t.Fatalf("open failure preparation event = %#v", events[1])
	}
	if events[2].Phase != ProgressMeasuring || events[2].ExchangesTotal != 0 {
		t.Fatalf("open failure measuring event = %#v", events[2])
	}
	if events[3].Phase != ProgressComplete || events[3].TargetsCompleted != 1 {
		t.Fatalf("open failure complete event = %#v", events[3])
	}
}

func TestFairProtocolSchedulingIsOrderIndependent(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	targets := []catalog.Target{
		testTarget(catalog.UDP, "one"),
		testTarget(catalog.UDP, "two"),
		testTarget(catalog.UDP, "three"),
	}
	opts := validBenchmarkOptions()
	opts.Domains = []string{"one.example", "two.example", "three.example"}
	opts.QueryTypes = []uint16{dns.TypeA}
	opts.Sample = 3
	opts.Concurrency = 2
	opts.OnProgress = func(Progress) {}

	type event struct {
		target string
		round  int
		seq    int
	}
	run := func(order []catalog.Target) (Report, []event, int) {
		var mu sync.Mutex
		events := make([]event, 0, len(order)*opts.Sample)
		active := 0
		maxActive := 0
		sequence := 0
		factories := make(map[string]transport.Factory, len(order))
		for _, target := range order {
			target := target
			delay := map[string]time.Duration{"one": 5 * time.Millisecond, "two": 30 * time.Millisecond, "three": 60 * time.Millisecond}[target.Address]
			measured := 0
			session := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
				if strings.HasSuffix(name, ".example") {
					mu.Lock()
					round := measured
					measured++
					active++
					if active > maxActive {
						maxActive = active
					}
					sequence++
					events = append(events, event{target: target.Address, round: round, seq: sequence})
					mu.Unlock()
					time.Sleep(delay)
					mu.Lock()
					active--
					mu.Unlock()
				}
				return replyFor(name, qtype), nil
			}}
			factories[target.Address] = &fakeFactory{opens: []fakeOpen{
				{session: &fakeSession{}},
				{session: &fakeSession{}},
				{session: &fakeSession{}},
				{session: session},
			}}
		}
		newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
			return factories[target.Address], nil
		}
		report, err := Run(context.Background(), order, opts)
		if err != nil {
			t.Fatalf("fair run failed: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		return report, append([]event(nil), events...), maxActive
	}

	first, firstEvents, firstMax := run(targets)
	reversed := append([]catalog.Target(nil), targets...)
	sort.Slice(reversed, func(i, j int) bool { return reversed[i].Address > reversed[j].Address })
	second, secondEvents, secondMax := run(reversed)
	if firstMax > opts.Concurrency || secondMax > opts.Concurrency {
		t.Fatalf("measured concurrency exceeded limit: %d/%d > %d", firstMax, secondMax, opts.Concurrency)
	}
	if len(firstEvents) != opts.Sample*len(targets) || len(secondEvents) != len(firstEvents) {
		t.Fatalf("measured event counts = %d/%d", len(firstEvents), len(secondEvents))
	}
	for _, events := range [][]event{firstEvents, secondEvents} {
		for round := 1; round < opts.Sample; round++ {
			previousLast := 0
			currentFirst := 0
			for _, item := range events {
				if item.round == round-1 && item.seq > previousLast {
					previousLast = item.seq
				}
				if item.round == round && (currentFirst == 0 || item.seq < currentFirst) {
					currentFirst = item.seq
				}
			}
			if previousLast == 0 || currentFirst <= previousLast {
				t.Fatalf("round %d was not fully completed before the next round: %#v", round, events)
			}
		}
	}
	normalizeRankings := func(rankings []Ranking) []Ranking {
		normalized := append([]Ranking(nil), rankings...)
		for index := range normalized {
			normalized[index].Tie = false
		}
		return normalized
	}
	if !reflect.DeepEqual(normalizeRankings(first.Rankings), normalizeRankings(second.Rankings)) {
		t.Fatalf("ranking order changed with target input order: %#v != %#v", first.Rankings, second.Rankings)
	}
	sequenceFor := func(events []event) map[string][]int {
		got := make(map[string][]int)
		for _, item := range events {
			got[item.target] = append(got[item.target], item.round)
		}
		return got
	}
	if !reflect.DeepEqual(sequenceFor(firstEvents), sequenceFor(secondEvents)) {
		t.Fatalf("per-target query rounds changed with target input order: %#v != %#v", firstEvents, secondEvents)
	}
}

func TestFairSchedulerCancellationAndHelperEdges(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)
	target := testTarget(catalog.UDP, "edge")
	query := Query{Name: "edge.example", QType: dns.TypeA}
	opts := Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 1}
	if got := runProtocolLegacy(context.Background(), nil, nil, opts); got != nil {
		t.Fatalf("empty legacy protocol results = %#v", got)
	}
	if got := runProtocolFair(context.Background(), nil, nil, opts); got != nil {
		t.Fatalf("empty fair protocol results = %#v", got)
	}

	// The legacy scheduler clamps its worker pool to the target count.
	useTargetSeam(t, func(_ context.Context, target catalog.Target, _ []Query, _ Options) TargetResult {
		return TargetResult{Target: target, Observations: []Observation{{Success: true, LatencyMS: 1, ResponseClass: "answer"}}}
	})
	runProtocol(context.Background(), []catalog.Target{target}, []Query{query}, Options{Concurrency: 5})
	useFairScheduler(t)

	runQueryRound(context.Background(), nil, query, 1)
	readyRunner := &targetRunner{
		target:  target,
		opts:    opts,
		ready:   true,
		session: minimalSession{},
		result:  TargetResult{Target: target},
	}
	cancelledRoundCtx, cancelRound := context.WithCancel(context.Background())
	cancelRound()
	runQueryRound(cancelledRoundCtx, []*targetRunner{readyRunner}, query, 1)
	readyRunner.finished = false
	readyRunner.ready = true
	runQueryRound(context.Background(), []*targetRunner{readyRunner}, query, 0)
	runQueryRound(context.Background(), []*targetRunner{readyRunner}, query, 5)
	if readyRunner.measure(context.Background(), query) == false {
		t.Fatal("ready runner did not measure a query")
	}
	readyRunner.finished = true
	if readyRunner.measure(context.Background(), query) {
		t.Fatal("finished runner measured a query")
	}
	readyRunner.finished = false
	readyRunner.ready = false
	if readyRunner.measure(context.Background(), query) {
		t.Fatal("unready runner measured a query")
	}
	readyRunner.close()
	readyRunner.close()

	ctx, cancel := context.WithCancel(context.Background())
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
			if index == 0 {
				cancel()
			}
			return minimalSession{}, nil
		}}, nil
	}
	results := runProtocol(ctx, []catalog.Target{target}, []Query{query}, opts)
	if len(results) != 1 || !results[0].Incomplete {
		t.Fatalf("fair prepare cancellation results = %#v", results)
	}

	ctx, cancel = context.WithCancel(context.Background())
	started := make(chan struct{})
	var startedOnce sync.Once
	release := make(chan struct{})
	blocking := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		if strings.HasSuffix(name, ".example") {
			startedOnce.Do(func() { close(started) })
			<-release
		}
		return replyFor(name, qtype), nil
	}}
	newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
		session := &fakeSession{}
		if target.Address == "one" {
			session = blocking
		}
		return &fakeFactory{opens: []fakeOpen{
			{session: &fakeSession{}},
			{session: &fakeSession{}},
			{session: &fakeSession{}},
			{session: session},
		}}, nil
	}
	resultCh := make(chan []TargetResult, 1)
	go func() {
		resultCh <- runProtocol(ctx, []catalog.Target{testTarget(catalog.UDP, "one"), testTarget(catalog.UDP, "two")}, []Query{query}, opts)
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)
	close(release)
	results = <-resultCh
	if len(results) != 2 || !results[0].Incomplete || !results[1].Incomplete {
		t.Fatalf("fair measured cancellation results = %#v", results)
	}
}

func TestRunNoComparableReportsRetainUnavailableTargets(t *testing.T) {
	useTargetSeam(t, func(_ context.Context, target catalog.Target, queries []Query, _ Options) TargetResult {
		return TargetResult{
			Target: target, OpenError: "connection refused",
			Observations: failedObservations(queries, errors.New("connection refused")),
		}
	})
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
	joined := warningText(report.Warnings)
	if !strings.Contains(joined, "connection refused") || !strings.Contains(joined, "failed queries") {
		t.Fatalf("unavailable report warnings = %#v", report.Warnings)
	}
}

func TestRunNoComparableReportsRetainUnusableResolverResponses(t *testing.T) {
	useTargetSeam(t, func(_ context.Context, target catalog.Target, queries []Query, _ Options) TargetResult {
		observations := make([]Observation, 0, len(queries))
		for _, query := range queries {
			observations = append(observations, Observation{
				Name: query.Name, QType: query.QType, Success: true, Usable: false,
				RCode: dns.RcodeServerFailure, ResponseClass: "rcode-2", LatencyMS: 1,
			})
		}
		return TargetResult{Target: target, Observations: observations}
	})
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
	joined := warningText(report.Warnings)
	if !strings.Contains(joined, "unusable DNS responses") || !strings.Contains(joined, "SERVFAIL:1") {
		t.Fatalf("unusable-response report warnings = %#v", report.Warnings)
	}
}

func TestRunProtocolCancellationBeforeDispatch(t *testing.T) {
	useFairScheduler(t)
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
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
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
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return nilFactory, nil
	}
	nilResult := runTarget(context.Background(), testTarget(catalog.UDP, "nil-response"), []Query{{Name: "nil.example", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(nilResult.Observations) != 1 || nilResult.Observations[0].Success || nilResult.Observations[0].Error != "empty DNS response" {
		t.Fatalf("nil response observation = %#v", nilResult.Observations)
	}
}

func TestRunTargetFactoryAndOpenErrors(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
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
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
	result = runTarget(context.Background(), testTarget(catalog.UDP, "cold-open"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(result.Cold) != 3 || result.Cold[0].Error == "" || result.OpenError != "" {
		t.Fatalf("cold open result = %#v", result)
	}

	factory = &fakeFactory{opens: []fakeOpen{{session: first}, {session: second}, {session: third}, {err: errors.New("warm open failed")}}}
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
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
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
	result := runTarget(ctx, testTarget(catalog.UDP, "cancel-warmup"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if !result.Incomplete || result.OpenError != context.Canceled.Error() || len(result.Observations) != 0 {
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
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
	result = runTarget(ctx, testTarget(catalog.UDP, "cancel-query"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if !result.Incomplete || result.OpenError != context.Canceled.Error() || len(result.Observations) != 0 {
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
	if len(rankings) != 3 || rankings[0].Protocol != catalog.TCP || rankings[0].Rank != 1 || !rankings[1].Tie || !rankings[2].Tie {
		t.Fatalf("rankings = %#v", rankings)
	}
	if len(makeRankings(nil)) != 0 || len(makeRankings([]TargetResult{{Target: target}})) != 0 {
		t.Fatal("unscored results should not be ranked")
	}
	equalA := TargetResult{Target: testTarget(catalog.UDP, "equal-a"), Stats: Statistics{Scored: 1, ScoreMS: 5}}
	equalB := TargetResult{Target: testTarget(catalog.UDP, "equal-b"), Stats: Statistics{Scored: 1, ScoreMS: 5}}
	equalRankings := makeRankings([]TargetResult{equalB, equalA})
	if len(equalRankings) != 2 || equalRankings[0].TargetID != equalA.Target.ID() || !equalRankings[0].Tie || !equalRankings[1].Tie {
		t.Fatalf("equal-score rankings = %#v", equalRankings)
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

func TestDivergentUnusableResponsesRemainScoringFailures(t *testing.T) {
	badTarget := testTarget(catalog.UDP, "fast-errors")
	goodTarget := testTarget(catalog.UDP, "steady")
	badObservations := make([]Observation, 0, 20)
	goodObservations := make([]Observation, 0, 20)
	for index := 0; index < 12; index++ {
		badObservations = append(badObservations, Observation{Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 1})
		goodObservations = append(goodObservations, Observation{Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 10})
	}
	for index := 0; index < 8; index++ {
		badObservations = append(badObservations, Observation{Success: true, RCode: dns.RcodeServerFailure, ResponseClass: "rcode-2", Divergent: true, LatencyMS: 1})
		goodObservations = append(goodObservations, Observation{Success: true, Usable: true, RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: 10})
	}
	bad := calculateStatistics(TargetResult{Target: badTarget, Observations: badObservations}, 2*time.Second, 42)
	good := calculateStatistics(TargetResult{Target: goodTarget, Observations: goodObservations}, 2*time.Second, 42)
	if bad.ResolverFailures != 8 || bad.Divergent != 8 || bad.ScoringFailureRate != .4 {
		t.Fatalf("divergent unusable metrics = %#v", bad)
	}
	if bad.ScoreMS <= good.ScoreMS {
		t.Fatalf("fast resolver errors outranked usable peer: bad=%#v good=%#v", bad, good)
	}
}

func TestBootstrapUsesCompleteOutcomesAndTargetIdentity(t *testing.T) {
	samples := []scoreSample{{latencyMS: 10, success: true}, {latencyMS: 20, success: true}, {success: false}}
	low, high := bootstrapCI(samples, 2*time.Second, bootstrapSeed(42, "one@192.0.2.1/udp"))
	if high <= low {
		t.Fatalf("bootstrap interval omitted outcome uncertainty: %v/%v", low, high)
	}
	if bootstrapSeed(42, "one@192.0.2.1/udp") == bootstrapSeed(42, "two@192.0.2.2/udp") {
		t.Fatal("distinct target identities reused a bootstrap seed")
	}
	// An all-failure replicate scores the timeout penalty itself, which is
	// exactly scoreFromLatencies with no latency term and a failure rate of 1.
	if got := scoreFromSamples([]scoreSample{{success: false}}, 2000); got != 2000 {
		t.Fatalf("all-failure bootstrap score = %v, want 2000", got)
	}
}

func TestIncompleteTargetsAreExcludedFromRankings(t *testing.T) {
	target := testTarget(catalog.UDP, "partial")
	result := TargetResult{Target: target, Incomplete: true, Stats: Statistics{Scored: 20, ScoreMS: 1}}
	if rankings := makeRankings([]TargetResult{result}); len(rankings) != 0 {
		t.Fatalf("incomplete target was ranked: %#v", rankings)
	}
	if warnings := collectWarnings([]TargetResult{result}); len(warnings) != 1 || !strings.Contains(warnings[0].String(), "excluded from ranking") {
		t.Fatalf("incomplete target warnings = %#v", warnings)
	}
}

func TestColdLatencyExcludesSessionTeardown(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	factory := &fakeFactory{opens: []fakeOpen{
		{session: &fakeSession{closeDelay: 100 * time.Millisecond}},
		{session: &fakeSession{closeDelay: 100 * time.Millisecond}},
		{session: &fakeSession{closeDelay: 100 * time.Millisecond}},
		{session: &fakeSession{}},
	}}
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
	result := runTarget(context.Background(), testTarget(catalog.UDP, "cold-timing"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(result.Cold) != 3 || result.Cold[0].Latency >= 80*time.Millisecond {
		t.Fatalf("cold latency included teardown: %#v", result.Cold)
	}
}

func TestRunTargetRecordsReconnectDiagnostics(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	warm := &fakeSession{reconnected: true}
	factory := &fakeFactory{opens: []fakeOpen{{session: &fakeSession{}}, {session: &fakeSession{}}, {session: &fakeSession{}}, {session: warm}}}
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
	result := runTarget(context.Background(), testTarget(catalog.TCP, "reconnect-metric"), []Query{{Name: "x", QType: dns.TypeA}}, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(result.Observations) != 1 || !result.Observations[0].Reconnected {
		t.Fatalf("reconnect observation = %#v", result.Observations)
	}
	stats := calculateStatistics(result, time.Second, 42)
	if stats.Reconnects != 1 || stats.Scored != 0 {
		t.Fatalf("reconnect statistics = %#v", stats)
	}
}

// TestRunTargetExcludesDoHReconnectFromWarmScoring covers the DoH session
// shape: the flag is reported per query, so only the query that paid for a
// fresh HTTPS connection is excluded from warm-latency scoring.
func TestRunTargetExcludesDoHReconnectFromWarmScoring(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	warm := &fakeSession{}
	warm.query = func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		warm.reconnected = name == "dropped.example"
		return replyFor(name, qtype), nil
	}
	factory := &fakeFactory{opens: []fakeOpen{{session: &fakeSession{}}, {session: &fakeSession{}}, {session: &fakeSession{}}, {session: warm}}}
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return factory, nil
	}
	queries := []Query{{Name: "kept.example", QType: dns.TypeA}, {Name: "dropped.example", QType: dns.TypeA}}
	result := runTarget(context.Background(), testTarget(catalog.DoH, "doh-reconnect"), queries, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(result.Observations) != 2 || result.Observations[0].Reconnected || !result.Observations[1].Reconnected {
		t.Fatalf("DoH reconnect observations = %#v", result.Observations)
	}
	stats := calculateStatistics(result, time.Second, 42)
	if stats.Reconnects != 1 || stats.Scored != 1 {
		t.Fatalf("DoH reconnect statistics = %#v", stats)
	}
}

func TestRunTargetCancellationBranchesDoNotCreateSamples(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	target := testTarget(catalog.UDP, "cancel-branches")
	queries := []Query{{Name: "x", QType: dns.TypeA}}
	options := Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second}

	t.Run("factory creation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return nil, errors.New("factory failed")
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Observations) != 0 {
			t.Fatalf("factory cancellation result = %#v", result)
		}
	})

	t.Run("before cold probe", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) { return minimalSession{}, nil }}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Cold) != 0 {
			t.Fatalf("pre-cold cancellation result = %#v", result)
		}
	})

	t.Run("cold open", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
				if index == 0 {
					cancel()
					return nil, errors.New("cold open canceled")
				}
				return minimalSession{}, nil
			}}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Cold) != 1 || len(result.Observations) != 0 {
			t.Fatalf("cold-open cancellation result = %#v", result)
		}
	})

	t.Run("cold query", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
				return &fakeSession{query: func(context.Context, string, uint16) (*dns.Msg, error) {
					cancel()
					return replyFor("example.com", dns.TypeA), nil
				}}, nil
			}}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Cold) != 1 || len(result.Observations) != 0 {
			t.Fatalf("cold-query cancellation result = %#v", result)
		}
	})

	t.Run("warm open", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
				if index < 3 {
					return minimalSession{}, nil
				}
				cancel()
				return nil, errors.New("warm open canceled")
			}}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || result.OpenError != context.Canceled.Error() || len(result.Observations) != 0 {
			t.Fatalf("warm-open cancellation result = %#v", result)
		}
	})

	t.Run("before warmup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
				if index < 3 {
					return minimalSession{}, nil
				}
				cancel()
				return minimalSession{}, nil
			}}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Observations) != 0 {
			t.Fatalf("pre-warmup cancellation result = %#v", result)
		}
	})

	t.Run("before measured query", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
				if index < 3 {
					return minimalSession{}, nil
				}
				return &cancelDialSession{fakeSession: &fakeSession{}, cancel: cancel}, nil
			}}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Observations) != 0 {
			t.Fatalf("pre-measured cancellation result = %#v", result)
		}
	})

	t.Run("during measured query", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
			return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
				if index < 3 {
					return minimalSession{}, nil
				}
				return &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
					if name == "x" {
						cancel()
					}
					return replyFor(name, qtype), nil
				}}, nil
			}}, nil
		}
		result := runTarget(ctx, target, queries, options)
		if !result.Incomplete || len(result.Observations) != 0 {
			t.Fatalf("measured cancellation result = %#v", result)
		}
	})
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
	if low, high := bootstrapCI(nil, 2*time.Second, 1); low != 0 || high != 0 {
		t.Fatalf("empty bootstrap CI = %v/%v", low, high)
	}
	if low, high := bootstrapCI([]scoreSample{{latencyMS: 10, success: true}}, 2*time.Second, 1); low != high || low != 10 {
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
	if sessionQueryReconnected(minimalSession{}) {
		t.Fatal("session without reconnect metadata reported a reconnect")
	}
	if !confidenceIntervalsOverlap(Statistics{ScoreMS: 1.5}, Statistics{ScoreMS: 1.5}) {
		t.Fatal("equal fallback score intervals should overlap")
	}
	if confidenceIntervalsOverlap(Statistics{ScoreMS: 1}, Statistics{ScoreMS: 3}) {
		t.Fatal("separated fallback score intervals should not overlap")
	}
	if confidenceIntervalsOverlap(Statistics{CILowMS: 1, CIHighMS: 2}, Statistics{CILowMS: 3, CIHighMS: 4}) {
		t.Fatal("separated confidence intervals should not overlap")
	}
}

func TestPolicyAwareDivergenceBaselines(t *testing.T) {
	observation := func(class string, rcode int) Observation {
		return Observation{
			Name: "Example.COM.", QType: dns.TypeA, Success: true,
			Usable: class == "answer" || class == "nxdomain", RCode: rcode,
			ResponseClass: class, LatencyMS: 5,
		}
	}
	makeResult := func(address, policy, class string, rcode int) TargetResult {
		target := testTarget(catalog.UDP, address)
		target.Resolver.Policy = policy
		return TargetResult{Target: target, Observations: []Observation{observation(class, rcode)}}
	}

	t.Run("unanimous classes do not diverge", func(t *testing.T) {
		results := []TargetResult{
			makeResult("unanimous-a", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("unanimous-b", "unfiltered", "answer", dns.RcodeSuccess),
		}
		if details := markDivergence(results); len(details) != 0 {
			t.Fatalf("unanimous divergence details = %#v", details)
		}
		for _, result := range results {
			if result.Observations[0].Divergent {
				t.Fatal("unanimous response was marked divergent")
			}
		}
	})

	t.Run("plurality excludes only the outlier", func(t *testing.T) {
		results := []TargetResult{
			makeResult("plurality-a", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("plurality-b", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("plurality-c", "unfiltered", "nxdomain", dns.RcodeNameError),
		}
		details := markDivergence(results)
		if len(details) != 1 || details[0].Baseline != "answer" || details[0].Ambiguous || len(details[0].Excluded) != 1 {
			t.Fatalf("plurality details = %#v", details)
		}
		if details[0].Excluded[0].TargetID != results[2].Target.ID() || details[0].Excluded[0].ResponseClass != "nxdomain" || details[0].Excluded[0].Treatment != "latency-excluded" {
			t.Fatalf("plurality exclusion = %#v", details[0].Excluded)
		}
		if results[0].Observations[0].Divergent || results[1].Observations[0].Divergent || !results[2].Observations[0].Divergent {
			t.Fatalf("plurality divergence flags = %#v", results)
		}
		for _, result := range results {
			if result.Observations[0].DivergenceBaseline != "answer" {
				t.Fatalf("plurality baseline = %#v", result.Observations[0])
			}
		}
	})

	t.Run("equal classes are ambiguous", func(t *testing.T) {
		results := []TargetResult{
			makeResult("tie-a", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("tie-b", "unfiltered", "nxdomain", dns.RcodeNameError),
		}
		details := markDivergence(results)
		if len(details) != 1 || !details[0].Ambiguous || details[0].Baseline != "" || len(details[0].Excluded) != 2 {
			t.Fatalf("ambiguous details = %#v", details)
		}
		for _, result := range results {
			if !result.Observations[0].Divergent || result.Observations[0].DivergenceBaseline != "ambiguous" {
				t.Fatalf("ambiguous observation = %#v", result.Observations[0])
			}
		}
	})

	t.Run("declared policies are not compared", func(t *testing.T) {
		results := []TargetResult{
			makeResult("policy-a", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("policy-b", "protective", "nxdomain", dns.RcodeNameError),
		}
		if details := markDivergence(results); len(details) != 0 {
			t.Fatalf("policy divergence details = %#v", details)
		}
		for _, result := range results {
			if result.Observations[0].Divergent {
				t.Fatal("different declared policies were compared")
			}
		}
	})

	t.Run("unusable outlier remains a scoring failure", func(t *testing.T) {
		results := []TargetResult{
			makeResult("rcode-a", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("rcode-b", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("rcode-c", "unfiltered", "rcode-2", dns.RcodeServerFailure),
		}
		details := markDivergence(results)
		stats := calculateStatistics(results[2], 2*time.Second, 42)
		if len(details) != 1 || details[0].Excluded[0].Treatment != "failure-penalized" || !results[2].Observations[0].Divergent || stats.ResolverFailures != 1 || stats.ScoringFailureRate != 1 {
			t.Fatalf("unusable divergent response = %#v / %#v", results[2].Observations[0], stats)
		}
	})

	t.Run("sorts query types deterministically", func(t *testing.T) {
		results := []TargetResult{
			makeResult("qtype-a", "unfiltered", "answer", dns.RcodeSuccess),
			makeResult("qtype-b", "unfiltered", "nxdomain", dns.RcodeNameError),
		}
		results[0].Observations = append(results[0].Observations, observation("answer", dns.RcodeSuccess))
		results[1].Observations = append(results[1].Observations, observation("nxdomain", dns.RcodeNameError))
		results[0].Observations[1].QType = dns.TypeAAAA
		results[1].Observations[1].QType = dns.TypeAAAA
		details := markDivergence(results)
		if len(details) != 2 || details[0].QType != dns.TypeA || details[1].QType != dns.TypeAAAA {
			t.Fatalf("query-type divergence details = %#v", details)
		}
	})
}

type reportedSession struct {
	fakeSession
	address string
}

func (s *reportedSession) DialAddress() string { return s.address }

// warningText renders warnings for substring assertions in tests that only care
// about the message content.
func warningText(warnings []Warning) string {
	lines := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		lines = append(lines, warning.String())
	}
	return strings.Join(lines, "\n")
}

func TestBootstrapUpperBoundStaysInsideScoreRange(t *testing.T) {
	timeout := 2 * time.Second
	timeoutMS := durationMS(timeout)
	// One success and four scoring failures. Roughly a third of the bootstrap
	// replicates draw no success at all, so an out-of-range all-failure
	// sentinel would surface directly in the reported upper bound.
	samples := []scoreSample{
		{latencyMS: 10, success: true},
		{success: false},
		{success: false},
		{success: false},
		{success: false},
	}
	seed := bootstrapSeed(42, "failing@192.0.2.9/udp")
	low, high := bootstrapCI(samples, timeout, seed)
	// The score function cannot exceed the worst observed latency plus the
	// full timeout penalty, so no replicate of it may either.
	maxScore := 10 + timeoutMS
	if low < 0 || high > maxScore {
		t.Fatalf("bootstrap interval [%v, %v] left the score range [0, %v]", low, high, maxScore)
	}
	if high != timeoutMS {
		t.Fatalf("all-failure replicates scored %v, want the timeout penalty %v", high, timeoutMS)
	}
	repeatLow, repeatHigh := bootstrapCI(samples, timeout, seed)
	if repeatLow != low || repeatHigh != high {
		t.Fatalf("seeded bootstrap bounds changed between runs: %v/%v != %v/%v", repeatLow, repeatHigh, low, high)
	}
}

func TestPrepareTargetsEdges(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })

	// An unset concurrency still prepares one target at a time.
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return nil, errors.New("fixture open failed")
	}
	runners, dispatched := prepareTargets(context.Background(), []catalog.Target{testTarget(catalog.UDP, "solo")}, nil, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second})
	if len(runners) != 1 || !dispatched[0] || runners[0].result.OpenError == "" {
		t.Fatalf("unbounded-concurrency preparation = %#v/%#v", runners, dispatched)
	}

	// A worker count larger than the target group is clamped before the warm
	// phase starts. This also exercises the successful two-phase path for a
	// single target.
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return &fakeFactory{opens: []fakeOpen{
			{session: &fakeSession{}},
			{session: &fakeSession{}},
			{session: &fakeSession{}},
			{session: &fakeSession{}},
		}}, nil
	}
	runners, dispatched = prepareTargets(context.Background(), []catalog.Target{testTarget(catalog.UDP, "clamped")}, nil, Options{
		QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 2,
	})
	if len(runners) != 1 || !dispatched[0] || !runners[0].ready {
		t.Fatalf("clamped-concurrency preparation = %#v/%#v", runners, dispatched)
	}

	// Cancelling while the only worker is still opening a session stops
	// dispatching, so later targets never get a runner at all.
	released := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
			once.Do(func() { close(started) })
			<-released
			return nil, errors.New("preparation interrupted")
		}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := []catalog.Target{testTarget(catalog.UDP, "blocked-first"), testTarget(catalog.UDP, "never-dispatched")}
	go func() {
		<-started
		cancel()
		time.Sleep(10 * time.Millisecond)
		close(released)
	}()
	runners, dispatched = prepareTargets(ctx, blocked, nil, Options{QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 1})
	if !dispatched[0] || dispatched[1] || runners[1] != nil {
		t.Fatalf("cancelled preparation dispatched too much: %#v/%#v", runners, dispatched)
	}
}

func TestPrepareTargetsAbortsCompletedColdRunnersAfterCancellation(t *testing.T) {
	restore := newFactory
	t.Cleanup(func() { newFactory = restore })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fastColdDone := make(chan struct{})
	var fastColdQueries atomic.Int32
	var fastColdOnce sync.Once
	fastColdSession := func() transport.Session {
		return &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			if fastColdQueries.Add(1) == 3 {
				fastColdOnce.Do(func() { close(fastColdDone) })
			}
			return replyFor(name, qtype), nil
		}}
	}
	newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
		if target.Address == "fast" {
			return &fakeFactory{opens: []fakeOpen{
				{session: fastColdSession()},
				{session: fastColdSession()},
				{session: fastColdSession()},
				{session: &fakeSession{}},
			}}, nil
		}
		return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
			if index == 0 {
				<-fastColdDone
				// Give the fast worker time to return from prepareCold before
				// cancellation makes the post-phase cleanup abort it.
				time.Sleep(25 * time.Millisecond)
				cancel()
			}
			return minimalSession{}, nil
		}}, nil
	}

	targets := []catalog.Target{testTarget(catalog.TCP, "fast"), testTarget(catalog.TCP, "slow")}
	runners, dispatched := prepareTargets(ctx, targets, nil, Options{
		QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 2,
	})
	if !dispatched[0] || !dispatched[1] || runners[0] == nil || runners[1] == nil {
		t.Fatalf("cancellation preparation dispatch = %#v/%#v", runners, dispatched)
	}
	if !runners[0].finished || !runners[0].result.Incomplete {
		t.Fatalf("completed cold runner was not aborted after cancellation: %#v", runners[0].result)
	}
}

func TestPreparationIsConcurrentBoundedAndDeterministic(t *testing.T) {
	oldTarget := runTargetFunc
	oldFactory := newFactory
	t.Cleanup(func() {
		runTargetFunc = oldTarget
		newFactory = oldFactory
	})
	runTargetFunc = runTarget

	targets := []catalog.Target{
		testTarget(catalog.UDP, "one"),
		testTarget(catalog.UDP, "two"),
		testTarget(catalog.UDP, "three"),
		testTarget(catalog.UDP, "four"),
	}
	opts := validBenchmarkOptions()
	opts.Domains = []string{"a.example", "b.example"}
	opts.QueryTypes = []uint16{dns.TypeA}
	opts.Sample = 2
	opts.Concurrency = 2
	opts.Seed = 99

	run := func() (Report, int) {
		var mu sync.Mutex
		active := 0
		maxActive := 0
		// Cold probes and warm-ups use warmupNames; the measured matrix uses
		// ".example" names. Counting only the former measures how many targets
		// are being prepared at the same instant.
		preparationSession := func() *fakeSession {
			return &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
				if !strings.HasSuffix(name, ".example") {
					mu.Lock()
					active++
					if active > maxActive {
						maxActive = active
					}
					mu.Unlock()
					time.Sleep(5 * time.Millisecond)
					mu.Lock()
					active--
					mu.Unlock()
				}
				return replyFor(name, qtype), nil
			}}
		}
		factories := make(map[string]transport.Factory, len(targets))
		for _, target := range targets {
			factories[target.Address] = &fakeFactory{opens: []fakeOpen{
				{session: preparationSession()},
				{session: preparationSession()},
				{session: preparationSession()},
				{session: preparationSession()},
			}}
		}
		newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
			return factories[target.Address], nil
		}
		report, err := Run(context.Background(), targets, opts)
		if err != nil {
			t.Fatalf("prepared run failed: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		return report, maxActive
	}

	shape := func(report Report) []string {
		lines := make([]string, 0, len(report.Targets))
		for _, result := range report.Targets {
			parts := []string{result.Target.ID()}
			for _, observation := range result.Observations {
				parts = append(parts, observation.Name+"/"+QueryTypeName(observation.QType))
			}
			lines = append(lines, strings.Join(parts, " "))
		}
		return lines
	}

	first, firstMax := run()
	second, secondMax := run()
	if firstMax > opts.Concurrency || secondMax > opts.Concurrency {
		t.Fatalf("preparation concurrency exceeded limit: %d/%d > %d", firstMax, secondMax, opts.Concurrency)
	}
	if firstMax < 2 || secondMax < 2 {
		t.Fatalf("preparation stayed sequential: %d/%d, want up to %d targets prepared at once", firstMax, secondMax, opts.Concurrency)
	}
	if len(first.Targets) != len(targets) {
		t.Fatalf("prepared results = %d, want %d", len(first.Targets), len(targets))
	}
	if !reflect.DeepEqual(shape(first), shape(second)) {
		t.Fatalf("seeded run was not deterministic: %#v != %#v", shape(first), shape(second))
	}
}

// agingWarmSession models a stream session that reconnects when it has been
// idle for too long. The real TCP and DoT transports expose the same
// diagnostic after a stale connection is recovered. Keeping the fixture at
// the benchmark seam makes this a deterministic scheduler regression test.
type agingWarmSession struct {
	opened      time.Time
	idleLimit   time.Duration
	reconnected bool
}

func (s *agingWarmSession) Query(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	s.reconnected = time.Since(s.opened) > s.idleLimit
	return replyFor(name, qtype), nil
}

func (s *agingWarmSession) Close() error { return nil }

func (s *agingWarmSession) LastQueryReconnected() bool { return s.reconnected }

type agingFactory struct {
	slow  bool
	opens atomic.Int32
}

func (f *agingFactory) Open(ctx context.Context) (transport.Session, error) {
	index := f.opens.Add(1) - 1
	if f.slow && index == 0 {
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if index == 3 {
		return &agingWarmSession{opened: time.Now(), idleLimit: 50 * time.Millisecond}, nil
	}
	return &fakeSession{}, nil
}

func TestPreparationBarrierPreventsWarmSessionAging(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	fastFactory := &agingFactory{}
	slowFactory := &agingFactory{slow: true}
	newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
		if target.Address == "slow" {
			return slowFactory, nil
		}
		return fastFactory, nil
	}

	targets := []catalog.Target{
		testTarget(catalog.TCP, "fast"),
		testTarget(catalog.TCP, "slow"),
	}
	options := Options{
		Domains:     []string{"measured.example"},
		QueryTypes:  []uint16{dns.TypeA},
		Sample:      1,
		Seed:        42,
		Timeout:     time.Second,
		Concurrency: 2,
	}

	report, err := Run(context.Background(), targets, options)
	if err != nil {
		t.Fatalf("barrier benchmark failed: %v", err)
	}
	fast, ok := report.ResultFor(targets[0].ID())
	if !ok {
		t.Fatal("fast target result missing")
	}
	if fast.Stats.Reconnects != 0 || len(fast.Observations) != 1 || fast.Observations[0].Reconnected {
		t.Fatalf("fast target warm session aged before measurement: stats=%#v observations=%#v", fast.Stats, fast.Observations)
	}
}

// TestPrepareTargetsStopsDispatchingWhenCancelledMidSend covers the dispatch
// loop's ctx.Done() arm deterministically.
//
// That arm was previously reached only by luck. The loop guards with
// `if ctx.Err() != nil { break }` before the select, so a context already
// cancelled takes the guard, and when the send is ready Go picks between the
// two ready select cases pseudo-randomly. Coverage of the arm therefore
// depended on goroutine scheduling -- it held on Linux and failed on macOS,
// where the guard won the race.
//
// Making it deterministic needs the send to be unable to proceed at the moment
// of cancellation. One worker, an unbuffered job channel, and a worker that
// blocks inside prepare guarantee exactly that: the worker takes target 0 and
// parks, so the dispatcher blocks sending target 1 and the only case that can
// ever become ready is ctx.Done().
func TestPrepareTargetsStopsDispatchingWhenCancelledMidSend(t *testing.T) {
	restore := newFactory
	t.Cleanup(func() { newFactory = restore })

	preparing := make(chan struct{})
	release := make(chan struct{})
	var opened atomic.Int32
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
			if opened.Add(1) == 1 {
				close(preparing)
				<-release
			}
			return minimalSession{}, nil
		}}, nil
	}

	targets := []catalog.Target{
		{Resolver: catalog.ResolverProfile{ID: "a", Policy: "unfiltered"}, Protocol: catalog.UDP, Address: "192.0.2.1", Spec: catalog.TransportSpec{Port: 53}},
		{Resolver: catalog.ResolverProfile{ID: "b", Policy: "unfiltered"}, Protocol: catalog.UDP, Address: "192.0.2.2", Spec: catalog.TransportSpec{Port: 53}},
		{Resolver: catalog.ResolverProfile{ID: "c", Policy: "unfiltered"}, Protocol: catalog.UDP, Address: "192.0.2.3", Spec: catalog.TransportSpec{Port: 53}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []bool, 1)
	go func() {
		_, dispatched := prepareTargets(ctx, targets, []Query{{Name: "example.com.", QType: 1}}, Options{Concurrency: 1, QueryTypes: []uint16{1}, Timeout: time.Second})
		done <- dispatched
	}()

	// The single worker is now parked inside prepare for target 0, so the
	// dispatcher is blocked sending target 1 and no receive can complete.
	<-preparing

	// Cancelling here would be too early: the dispatcher may still be at the
	// ctx.Err() guard that precedes the select, in which case the guard breaks
	// the loop and the select arm is never evaluated -- which is how coverage
	// of this arm came to depend on the host's scheduler. Waiting until the
	// dispatcher has been blocked on the send for a while puts it provably
	// inside the select, so ctx.Done() is the only case that can ever fire.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// The worker stays parked until the dispatcher has acted on the
	// cancellation. Releasing it first would make a receive ready again and
	// reintroduce the two-ready-cases coin flip.
	for attempt := 0; attempt < 1000; attempt++ {
		runtime.Gosched()
	}
	close(release)

	dispatched := <-done
	if !dispatched[0] {
		t.Fatal("the target taken by the worker must be reported as dispatched")
	}
	if dispatched[2] {
		t.Fatal("dispatching must stop at cancellation, not run to completion")
	}
}

// TestCacheMissQueriesAskEachGeneratedNameOnce is the heart of the #108 fix.
// A resolver that answers speedns-<nonce>-0001.example.com/A with NXDOMAIN
// caches that negative answer for the whole name, so asking the same name for
// AAAA measures the cache rather than a miss. Under the default --type A,AAAA
// that made half of every cache-miss run a warm read.
//
// Queries per target are unchanged, which is what keeps the reserved-zone
// traffic budget intact: the corpus doubled and the per-name question count
// halved.
func TestCacheMissQueriesAskEachGeneratedNameOnce(t *testing.T) {
	names := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("speedns-test-%04d.example.com", i))
	}
	options := Options{Domains: names, QueryTypes: []uint16{1, 28}, Sample: 20, Seed: 7, CacheMiss: true}

	queries, err := buildQueries(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 20 {
		t.Fatalf("cache-miss produced %d queries for 20 names", len(queries))
	}
	perName := make(map[string]int, len(queries))
	perType := make(map[uint16]int, 2)
	for _, query := range queries {
		perName[query.Name]++
		perType[query.QType]++
	}
	for name, count := range perName {
		if count != 1 {
			t.Fatalf("%s was asked %d times; every later question is a warm read", name, count)
		}
	}
	// Types still rotate across the corpus, so a multi-type selection is
	// represented -- just never twice for one name.
	if perType[1] != 10 || perType[28] != 10 {
		t.Fatalf("query types did not rotate evenly: A=%d AAAA=%d", perType[1], perType[28])
	}

	// A warm-cache run keeps the cross-product: repeating a name there is the
	// point, because it measures a cache hit.
	options.CacheMiss = false
	warm, err := buildQueries(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(warm) != 40 {
		t.Fatalf("warm-cache produced %d queries, want the 20x2 cross-product", len(warm))
	}
}

// TestPairedLatencyDeltasRequireAMatchingResponseClass covers the guard that
// replaces the policy grouping key.
//
// Grouping paired effects by policy was meant to stop a filtering resolver
// being compared against an unfiltered one. It did that by refusing most
// comparisons entirely, including all the safe ones. The real hazard is
// narrower and per-observation: a resolver that sinkholes a name answers from
// its own blocklist in microseconds while the reference performs a real
// recursion, so that pair measures the filtering policy, not the speed.
// Requiring both observations to share a response class removes exactly those
// pairs and leaves every other comparison intact.
func TestPairedLatencyDeltasRequireAMatchingResponseClass(t *testing.T) {
	sample := func(name string, class string, latency float64) Observation {
		return Observation{
			Name: name, QType: dns.TypeA, Success: true, Usable: true,
			RCode: dns.RcodeSuccess, ResponseClass: class, LatencyMS: latency,
		}
	}
	reference := TargetResult{
		Target: testTarget(catalog.UDP, "reference"),
		Observations: []Observation{
			sample("real.example.", "answer", 20),
			sample("blocked.example.", "answer", 22),
			sample("absent.example.", "nodata", 18),
		},
	}
	// A filtering resolver: it answers "blocked" from its blocklist, which is
	// both a different class and far faster than a real recursion.
	filtering := TargetResult{
		Target: testTarget(catalog.UDP, "filtering"),
		Observations: []Observation{
			sample("real.example.", "answer", 25),
			sample("blocked.example.", "nxdomain", 1),
			sample("absent.example.", "nodata", 19),
		},
	}

	deltas := pairedLatencyDeltas(filtering, reference)
	if len(deltas) != 2 {
		t.Fatalf("deltas = %v, want the two same-class pairs only", deltas)
	}
	for _, delta := range deltas {
		if delta < 0 {
			t.Fatalf("a sinkholed pair leaked into the deltas: %v", deltas)
		}
	}

	// With the guard removed the blocklist hit would contribute -21 ms and
	// make the filtering resolver look dramatically faster than it is.
	sum := 0.0
	for _, delta := range deltas {
		sum += delta
	}
	if sum != 6 {
		t.Fatalf("delta sum = %v, want 5 + 1 from the two comparable pairs", sum)
	}
}

// TestPairedEffectsSkipLocalResolvers pins an exclusion that protocol-only
// grouping made necessary. A resolver on the local host is measured but never
// ranked, and its cache-hit latency hides the upstream resolution it forwards.
// Under the old policy grouping a loopback stub landed in its own policy group
// and compared only against itself; grouping by protocol would otherwise pair
// it against the protocol winner and present that comparison as meaningful.
func TestPairedEffectsSkipLocalResolvers(t *testing.T) {
	sample := func(name string, latency float64) Observation {
		return Observation{
			Name: name, QType: dns.TypeA, Success: true, Usable: true,
			RCode: dns.RcodeSuccess, ResponseClass: "answer", LatencyMS: latency,
		}
	}
	observations := make([]Observation, 0, MinimumRecommendedSamples)
	for index := 0; index < MinimumRecommendedSamples; index++ {
		observations = append(observations, sample(fmt.Sprintf("q%02d.example.", index), 20))
	}

	remote := testTarget(catalog.UDP, "remote")
	stub := testTarget(catalog.UDP, "stub")
	stub.Resolver.Local = true

	effects := calculatePairedEffects([]TargetResult{
		{Target: remote, Stats: Statistics{Scored: MinimumRecommendedSamples, ScoreMS: 2}, Observations: observations},
		{Target: stub, Stats: Statistics{Scored: MinimumRecommendedSamples, ScoreMS: 1}, Observations: observations},
	}, []Ranking{{Protocol: catalog.UDP, TargetID: remote.ID(), Rank: 1}}, 42)

	for _, effect := range effects {
		if effect.TargetID == stub.ID() || effect.ReferenceTargetID == stub.ID() {
			t.Fatalf("a local resolver reached the paired effects: %#v", effect)
		}
	}
	if len(effects) != 1 || effects[0].TargetID != remote.ID() {
		t.Fatalf("paired effects = %#v, want only the remote target", effects)
	}
}

// TestSampleSizeCountsNamesInBothCorpusShapes pins the number the report
// publishes as run.sample_size.
//
// It used to be derived as len(queries)/len(QueryTypes), which assumes the warm
// cross-product. Cache-miss mode asks each generated name one question, so that
// divisor halved the reported sample size under the default --type A,AAAA and
// rounded down for odd corpora -- a wrong number in the versioned JSON
// contract, contradicting the corpus the run actually measured.
func TestSampleSizeCountsNamesInBothCorpusShapes(t *testing.T) {
	// An odd corpus, so an off-by-rounding is visible rather than absorbed.
	names := make([]string, 0, 7)
	for index := 0; index < 7; index++ {
		names = append(names, fmt.Sprintf("speedns-test-%04d.example.com", index))
	}

	cacheMiss, err := buildQueries(Options{Domains: names, QueryTypes: []uint16{1, 28}, Sample: 7, Seed: 3, CacheMiss: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := distinctQueryNames(cacheMiss); got != 7 {
		t.Fatalf("cache-miss sample size = %d, want 7 names", got)
	}
	if len(cacheMiss) != 7 {
		t.Fatalf("cache-miss produced %d queries for 7 names", len(cacheMiss))
	}

	warm, err := buildQueries(Options{Domains: names, QueryTypes: []uint16{1, 28}, Sample: 7, Seed: 3})
	if err != nil {
		t.Fatal(err)
	}
	if got := distinctQueryNames(warm); got != 7 {
		t.Fatalf("warm sample size = %d, want 7 names", got)
	}
	if len(warm) != 14 {
		t.Fatalf("warm produced %d queries, want the 7x2 cross-product", len(warm))
	}

	// Through Run, because the published number is assigned there and a
	// helper-level test cannot see a wrong formula at the assignment site.
	restore := newFactory
	t.Cleanup(func() { newFactory = restore })
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
			return minimalSession{}, nil
		}}, nil
	}
	for _, testCase := range []struct {
		name      string
		cacheMiss bool
		want      int
	}{
		{"cache-miss corpus", true, 7},
		{"warm corpus", false, 7},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := validBenchmarkOptions()
			options.Domains = names
			options.QueryTypes = []uint16{1, 28}
			options.Sample = 7
			options.CacheMiss = testCase.cacheMiss
			report, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "one")}, options)
			if err != nil {
				t.Fatal(err)
			}
			if report.SampleSize != testCase.want {
				t.Fatalf("report.SampleSize = %d, want %d names", report.SampleSize, testCase.want)
			}
		})
	}
}
