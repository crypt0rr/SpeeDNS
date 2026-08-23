package benchmark

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/domains"
	"github.com/crypt0rr/SpeeDNS/internal/safetext"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/miekg/dns"
)

const (
	DefaultSample                 = 100
	DefaultTimeout                = 2 * time.Second
	DefaultConcurrency            = 4
	BootstrapIterations           = 1000
	MinimumRecommendedSamples     = 20
	MinimumRecommendedSuccessRate = 0.99
	CorpusWarmCache               = "warm-cache"
	CorpusCacheMiss               = "cache-miss"
)

// ErrNoComparableResults means the benchmark completed, but no target had a
// comparable set of DNS observations to rank.
var ErrNoComparableResults = errors.New("no comparable DNS results were produced")

var warmupNames = []string{"example.com", "example.org", "example.net"}

// newFactory is kept as a small dependency seam so the scheduler and
// statistics engine can be tested without contacting a real resolver.
var newFactory = transport.NewFactory

// protocolScheduler measures one protocol group of targets and returns their
// results.
type protocolScheduler func(ctx context.Context, targets []catalog.Target, queries []Query, opts Options) []TargetResult

// runProtocol is the scheduler every protocol group is measured with. It is a
// variable purely so a test can select runProtocolLegacy deliberately; the
// production choice is never inferred from the state of a test hook.
var runProtocol protocolScheduler = runProtocolFair

// runTargetFunc is the target-level seam used by runProtocolLegacy. Replacing
// it has no effect unless runProtocolLegacy is also selected explicitly.
var runTargetFunc = runTarget

type Options struct {
	Domains     []string
	QueryTypes  []uint16
	Sample      int
	Full        bool
	Seed        int64
	Timeout     time.Duration
	Concurrency int
	Protocols   []catalog.Protocol
	OnProgress  func(Progress)
}

// ProgressPhase identifies the kind of work represented by a progress event.
// Preparation includes connection setup, cold probes, and warm-up queries;
// measuring includes only the scored query exchanges.
type ProgressPhase string

const (
	ProgressPreparing ProgressPhase = "preparing"
	ProgressMeasuring ProgressPhase = "measuring"
	ProgressComplete  ProgressPhase = "complete"
)

type Progress struct {
	Protocol           catalog.Protocol
	Phase              ProgressPhase
	TargetsCompleted   int
	TargetsTotal       int
	ExchangesCompleted int
	ExchangesTotal     int
}

type Query struct {
	Name  string
	QType uint16
}

type Observation struct {
	Name               string        `json:"name"`
	QType              uint16        `json:"qtype"`
	Latency            time.Duration `json:"-"`
	LatencyMS          float64       `json:"latency_ms,omitempty"`
	Success            bool          `json:"success"`
	Usable             bool          `json:"usable"`
	RCode              int           `json:"rcode,omitempty"`
	Truncated          bool          `json:"truncated,omitempty"`
	ResponseClass      string        `json:"response_class,omitempty"`
	Divergent          bool          `json:"divergent,omitempty"`
	DivergenceBaseline string        `json:"divergence_baseline,omitempty"`
	Reconnected        bool          `json:"reconnected,omitempty"`
	Error              string        `json:"error,omitempty"`
}

type ColdObservation struct {
	Name      string        `json:"name"`
	QType     uint16        `json:"qtype"`
	Latency   time.Duration `json:"-"`
	LatencyMS float64       `json:"latency_ms,omitempty"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}

type Statistics struct {
	Total               int            `json:"total"`
	Successes           int            `json:"successes"`
	Failures            int            `json:"failures"`
	UsableResponses     int            `json:"usable_responses"`
	ResolverFailures    int            `json:"resolver_failures"`
	Scored              int            `json:"scored"`
	Divergent           int            `json:"divergent"`
	Truncated           int            `json:"truncated"`
	Reconnects          int            `json:"reconnects"`
	SuccessRate         float64        `json:"success_rate"`
	FailureRate         float64        `json:"failure_rate"`
	UsableRate          float64        `json:"usable_rate"`
	ResolverFailureRate float64        `json:"resolver_failure_rate"`
	ScoringFailureRate  float64        `json:"scoring_failure_rate"`
	RCodeCounts         map[string]int `json:"rcode_counts,omitempty"`
	MedianMS            float64        `json:"median_ms"`
	P95MS               float64        `json:"p95_ms"`
	MinMS               float64        `json:"min_ms"`
	MaxMS               float64        `json:"max_ms"`
	MADMS               float64        `json:"mad_ms"`
	ColdMedianMS        float64        `json:"cold_median_ms"`
	ScoreMS             float64        `json:"score_ms"`
	CILowMS             float64        `json:"ci_low_ms"`
	CIHighMS            float64        `json:"ci_high_ms"`
	Recommended         bool           `json:"recommended"`
	Tie                 bool           `json:"tie"`
}

type TargetResult struct {
	Target       catalog.Target    `json:"-"`
	Observations []Observation     `json:"samples,omitempty"`
	Cold         []ColdObservation `json:"cold,omitempty"`
	Stats        Statistics        `json:"stats"`
	OpenError    string            `json:"open_error,omitempty"`
	Incomplete   bool              `json:"incomplete,omitempty"`
	DialAddress  string            `json:"-"`
}

type Ranking struct {
	Protocol catalog.Protocol `json:"protocol"`
	TargetID string           `json:"target_id"`
	Rank     int              `json:"rank"`
	Tie      bool             `json:"tie"`
}

type Report struct {
	StartedAt     time.Time          `json:"started_at"`
	FinishedAt    time.Time          `json:"finished_at"`
	Seed          int64              `json:"seed"`
	Provenance    *RunProvenance     `json:"provenance,omitempty"`
	CorpusMode    string             `json:"corpus_mode,omitempty"`
	CorpusZone    string             `json:"corpus_zone,omitempty"`
	CorpusNonce   string             `json:"corpus_nonce,omitempty"`
	SampleSize    int                `json:"sample_size"`
	Queries       int                `json:"queries_per_target"`
	QueryTypes    []uint16           `json:"query_types"`
	Targets       []TargetResult     `json:"results"`
	Rankings      []Ranking          `json:"rankings"`
	PairedEffects []PairedEffect     `json:"paired_effects,omitempty"`
	Divergence    []DivergenceDetail `json:"divergence,omitempty"`
	Warnings      []string           `json:"warnings,omitempty"`
}

// RunProvenance records the local build, platform, corpus, and effective
// benchmark settings needed to compare a report with another run. It is
// populated by the CLI because the benchmark package deliberately has no
// knowledge of build metadata or command-line configuration.
type RunProvenance struct {
	Version       string
	Commit        string
	BuildDate     string
	OS            string
	Architecture  string
	Interfaces    []string
	Protocols     []catalog.Protocol
	CorpusEntries int
	CorpusSHA256  string
	Timeout       time.Duration
	Concurrency   int
}

// PairedEffect describes the latency difference between a target and the
// deterministic reference for its protocol and declared policy group. A
// positive delta means that the target was slower than the reference.
//
// Only observations that are usable, non-divergent, non-reconnect samples are
// paired. A comparison needs at least MinimumRecommendedSamples paired
// observations, the same floor the recommendation gate uses; below that the
// delta and interval stay zero and Reason explains why. The existing composite
// score remains the ranking authority; these values explain whether a ranked
// difference is distinguishable from noise.
type PairedEffect struct {
	Protocol          catalog.Protocol `json:"protocol"`
	Policy            string           `json:"policy"`
	TargetID          string           `json:"target_id"`
	ReferenceTargetID string           `json:"reference_target_id"`
	Samples           int              `json:"samples"`
	MedianDeltaMS     float64          `json:"median_delta_ms"`
	CILowMS           float64          `json:"ci_low_ms"`
	CIHighMS          float64          `json:"ci_high_ms"`
	Indistinguishable bool             `json:"indistinguishable"`
	Reference         bool             `json:"reference,omitempty"`
	Reason            string           `json:"reason,omitempty"`
}

// DivergenceExclusion identifies a successful response that differed from the
// selected response-class baseline. Usable outliers are removed from the
// latency sample; unusable outliers remain failure-penalized.
type DivergenceExclusion struct {
	TargetID      string `json:"target_id"`
	ResponseClass string `json:"response_class"`
	Treatment     string `json:"treatment"`
}

// DivergenceDetail records the deterministic baseline decision for one query
// and policy group. A tied plurality has no safe baseline, so Ambiguous is
// true and all successful observations in the group are excluded from
// comparative latency scoring.
type DivergenceDetail struct {
	Name      string                `json:"name"`
	QType     uint16                `json:"qtype"`
	Policy    string                `json:"policy"`
	Compared  int                   `json:"compared"`
	Baseline  string                `json:"baseline,omitempty"`
	Ambiguous bool                  `json:"ambiguous,omitempty"`
	Classes   map[string]int        `json:"classes"`
	Excluded  []DivergenceExclusion `json:"excluded,omitempty"`
}

func (r Report) ResultFor(id string) (TargetResult, bool) {
	for _, result := range r.Targets {
		if result.Target.ID() == id {
			return result, true
		}
	}
	return TargetResult{}, false
}

// Run executes one protocol group at a time. All targets in a group receive
// the same shuffled query sequence. The production scheduler interleaves
// measured rounds while bounding the number of in-flight exchanges.
func Run(ctx context.Context, targets []catalog.Target, opts Options) (Report, error) {
	if err := validateOptions(opts); err != nil {
		return Report{}, err
	}
	if len(targets) == 0 {
		return Report{}, errors.New("no supported resolver targets selected")
	}
	queries, err := buildQueries(opts)
	if err != nil {
		return Report{}, err
	}
	started := time.Now()
	report := Report{
		StartedAt:  started,
		Seed:       opts.Seed,
		SampleSize: len(queries) / len(opts.QueryTypes),
		Queries:    len(queries),
		QueryTypes: append([]uint16(nil), opts.QueryTypes...),
	}
	if !opts.Full && opts.Sample > report.SampleSize {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"requested sample of %d domains exceeds the normalized corpus size; using all %d domains",
			opts.Sample, report.SampleSize,
		))
	}

	byProtocol := make(map[catalog.Protocol][]catalog.Target)
	for _, target := range targets {
		byProtocol[target.Protocol] = append(byProtocol[target.Protocol], target)
	}
	protocols := make([]catalog.Protocol, 0, len(byProtocol))
	for protocol := range byProtocol {
		protocols = append(protocols, protocol)
	}
	// Measure protocol groups in the documented order (udp, tcp, doh, dot,
	// doq) rather than the lexicographic order of the Protocol string type.
	sort.Slice(protocols, func(i, j int) bool {
		return catalog.CompareProtocols(protocols[i], protocols[j]) < 0
	})

	for _, protocol := range protocols {
		groupResults := runProtocol(ctx, byProtocol[protocol], queries, opts)
		report.Divergence = append(report.Divergence, markDivergence(groupResults)...)
		for i := range groupResults {
			groupResults[i].Stats = calculateStatistics(groupResults[i], opts.Timeout, opts.Seed)
		}
		report.Targets = append(report.Targets, groupResults...)
	}
	report.FinishedAt = time.Now()
	sort.Slice(report.Targets, func(i, j int) bool {
		return report.Targets[i].Target.ID() < report.Targets[j].Target.ID()
	})
	report.Rankings = makeRankings(report.Targets)
	report.PairedEffects = calculatePairedEffects(report.Targets, report.Rankings, report.Seed)
	report.Warnings = append(report.Warnings, collectWarnings(report.Targets)...)
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if len(report.Rankings) == 0 {
		return report, ErrNoComparableResults
	}
	return report, nil
}

func validateOptions(opts Options) error {
	if len(opts.Domains) == 0 {
		return errors.New("domain corpus is empty")
	}
	if len(opts.QueryTypes) == 0 {
		return errors.New("at least one DNS query type is required")
	}
	if opts.Sample <= 0 && !opts.Full {
		return errors.New("sample size must be positive")
	}
	if opts.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if opts.Concurrency <= 0 {
		return errors.New("concurrency must be positive")
	}
	return nil
}

func buildQueries(opts Options) ([]Query, error) {
	names, err := domains.Normalize(opts.Domains)
	if err != nil {
		return nil, fmt.Errorf("domain corpus has no valid names: %w", err)
	}
	source := append([]string(nil), names...)
	rng := rand.New(rand.NewSource(opts.Seed))
	rng.Shuffle(len(source), func(i, j int) { source[i], source[j] = source[j], source[i] })
	count := opts.Sample
	if opts.Full || count > len(source) {
		count = len(source)
	}
	queries := make([]Query, 0, count*len(opts.QueryTypes))
	for _, domain := range source[:count] {
		for _, qtype := range opts.QueryTypes {
			queries = append(queries, Query{Name: domain, QType: qtype})
		}
	}
	rng.Shuffle(len(queries), func(i, j int) { queries[i], queries[j] = queries[j], queries[i] })
	return queries, nil
}

// runProtocolLegacy dispatches whole targets to a worker pool through the
// runTargetFunc seam and returns only the targets it managed to dispatch. It
// is never selected by production code; tests that fake whole targets select
// it explicitly.
func runProtocolLegacy(ctx context.Context, targets []catalog.Target, queries []Query, opts Options) []TargetResult {
	if len(targets) == 0 {
		return nil
	}
	emitProgress(opts, Progress{
		Protocol:     targets[0].Protocol,
		Phase:        ProgressPreparing,
		TargetsTotal: len(targets),
	})
	results := make([]TargetResult, len(targets))
	dispatched := make([]bool, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var completedTargets atomic.Int32
	var completedExchanges atomic.Int32
	workers := opts.Concurrency
	if workers > len(targets) {
		workers = len(targets)
	}
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				result := runTargetFunc(ctx, targets[index], queries, opts)
				if ctx.Err() != nil {
					// A worker may return just after cancellation, including when a
					// test fixture ignores its context. Keep that target diagnostic
					// but never let a partial result enter rankings.
					markIncomplete(&result, ctx.Err())
				}
				results[index] = result
				targetsDone := int(completedTargets.Add(1))
				exchangesDone := int(completedExchanges.Add(int32(len(result.Observations))))
				emitProgress(opts, Progress{
					Protocol:           targets[index].Protocol,
					Phase:              ProgressMeasuring,
					TargetsCompleted:   targetsDone,
					TargetsTotal:       len(targets),
					ExchangesCompleted: exchangesDone,
					ExchangesTotal:     len(targets) * len(queries),
				})
			}
		}()
	}
dispatch:
	for index := range targets {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- index:
			dispatched[index] = true
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	compacted := dispatchedResults(results, dispatched)
	emitProgress(opts, Progress{
		Protocol:           targets[0].Protocol,
		Phase:              ProgressComplete,
		TargetsCompleted:   int(completedTargets.Load()),
		TargetsTotal:       len(targets),
		ExchangesCompleted: int(completedExchanges.Load()),
		ExchangesTotal:     len(targets) * len(queries),
	})
	return compacted
}

func runProtocolFair(ctx context.Context, targets []catalog.Target, queries []Query, opts Options) []TargetResult {
	orderedTargets := append([]catalog.Target(nil), targets...)
	if len(orderedTargets) == 0 {
		return nil
	}
	sort.Slice(orderedTargets, func(i, j int) bool {
		return orderedTargets[i].ID() < orderedTargets[j].ID()
	})
	emitProgress(opts, Progress{
		Protocol:     orderedTargets[0].Protocol,
		Phase:        ProgressPreparing,
		TargetsTotal: len(orderedTargets),
	})

	runners := make([]*targetRunner, 0, len(orderedTargets))
	ready := make([]*targetRunner, 0, len(orderedTargets))
	for _, target := range orderedTargets {
		if ctx.Err() != nil {
			break
		}
		runner := newTargetRunner(ctx, target, queries, opts)
		runners = append(runners, runner)
		prepared := runner.prepare(ctx)
		preparedTargets := len(runners)
		emitProgress(opts, Progress{
			Protocol:         target.Protocol,
			Phase:            ProgressPreparing,
			TargetsCompleted: preparedTargets,
			TargetsTotal:     len(orderedTargets),
		})
		if prepared {
			ready = append(ready, runner)
			continue
		}
		if ctx.Err() != nil {
			break
		}
	}

	completedExchanges := 0
	exchangesTotal := len(ready) * len(queries)
	if ctx.Err() == nil {
		emitProgress(opts, Progress{
			Protocol:         orderedTargets[0].Protocol,
			Phase:            ProgressMeasuring,
			TargetsCompleted: len(runners),
			TargetsTotal:     len(orderedTargets),
			ExchangesTotal:   exchangesTotal,
		})
		for _, query := range queries {
			completedExchanges += runQueryRound(ctx, ready, query, opts.Concurrency)
			if len(ready) > 0 {
				emitProgress(opts, Progress{
					Protocol:           orderedTargets[0].Protocol,
					Phase:              ProgressMeasuring,
					TargetsCompleted:   len(runners),
					TargetsTotal:       len(orderedTargets),
					ExchangesCompleted: completedExchanges,
					ExchangesTotal:     exchangesTotal,
				})
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	if ctx.Err() != nil {
		for _, runner := range ready {
			runner.abort(ctx.Err())
		}
	}

	results := make([]TargetResult, 0, len(runners))
	for _, runner := range runners {
		runner.close()
		results = append(results, runner.result)
	}
	emitProgress(opts, Progress{
		Protocol:           orderedTargets[0].Protocol,
		Phase:              ProgressComplete,
		TargetsCompleted:   len(runners),
		TargetsTotal:       len(orderedTargets),
		ExchangesCompleted: completedExchanges,
		ExchangesTotal:     exchangesTotal,
	})
	return results
}

func runQueryRound(ctx context.Context, runners []*targetRunner, query Query, concurrency int) int {
	if len(runners) == 0 {
		return 0
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(runners) {
		concurrency = len(runners)
	}
	jobs := make(chan int)
	dispatched := make([]bool, len(runners))
	var completed atomic.Int32
	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if runners[index].measure(ctx, query) {
					completed.Add(1)
				}
			}
		}()
	}
dispatch:
	for index := range runners {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- index:
			dispatched[index] = true
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		for index, wasDispatched := range dispatched {
			if !wasDispatched {
				runners[index].abort(ctx.Err())
			}
		}
	}
	return int(completed.Load())
}

func emitProgress(opts Options, progress Progress) {
	if opts.OnProgress != nil {
		opts.OnProgress(progress)
	}
}

func dispatchedResults(results []TargetResult, dispatched []bool) []TargetResult {
	compacted := make([]TargetResult, 0, len(results))
	for index, wasDispatched := range dispatched {
		if wasDispatched {
			compacted = append(compacted, results[index])
		}
	}
	return compacted
}

// targetRunner owns one target's reusable measured session. The fair
// scheduler prepares all dispatched targets, then advances every target by
// one measured query round at a time. Only query calls are concurrent; a
// runner is never asked to use its session concurrently.
type targetRunner struct {
	target   catalog.Target
	queries  []Query
	opts     Options
	result   TargetResult
	factory  transport.Factory
	session  transport.Session
	ready    bool
	finished bool
	closed   bool
}

func newTargetRunner(ctx context.Context, target catalog.Target, queries []Query, opts Options) *targetRunner {
	runner := &targetRunner{
		target:  target,
		queries: queries,
		opts:    opts,
		result: TargetResult{
			Target:       target,
			Observations: make([]Observation, 0, len(queries)),
		},
	}
	factory, err := newFactory(target, opts.Timeout)
	if err != nil {
		if ctx.Err() != nil {
			runner.abort(ctx.Err())
			return runner
		}
		runner.result.OpenError = err.Error()
		runner.result.Observations = failedObservations(queries, err)
		runner.finished = true
		return runner
	}
	runner.factory = factory
	return runner
}

func (runner *targetRunner) prepare(ctx context.Context) bool {
	if runner.finished {
		return false
	}
	for index := 0; index < 3; index++ {
		if ctx.Err() != nil {
			runner.abort(ctx.Err())
			return false
		}
		probe := warmupNames[index%len(warmupNames)]
		qtype := runner.opts.QueryTypes[index%len(runner.opts.QueryTypes)]
		started := time.Now()
		session, openErr := runner.factory.Open(ctx)
		observation := ColdObservation{Name: probe, QType: qtype}
		if openErr != nil {
			observation.Error = openErr.Error()
			runner.result.Cold = append(runner.result.Cold, observation)
			if ctx.Err() != nil {
				runner.abort(ctx.Err())
				return false
			}
			continue
		}
		queryCtx, cancel := context.WithTimeout(ctx, runner.opts.Timeout)
		_, queryErr := session.Query(queryCtx, probe, qtype)
		// Cold latency ends when the DNS exchange returns. Session teardown is
		// deliberately excluded because its cost differs by transport.
		observation.Latency = time.Since(started)
		observation.LatencyMS = durationMS(observation.Latency)
		cancel()
		_ = session.Close()
		if queryErr != nil {
			observation.Error = queryErr.Error()
		} else {
			observation.Success = true
		}
		runner.result.Cold = append(runner.result.Cold, observation)
		if ctx.Err() != nil {
			runner.abort(ctx.Err())
			return false
		}
	}

	session, err := runner.factory.Open(ctx)
	if err != nil {
		if ctx.Err() != nil {
			runner.abort(ctx.Err())
			return false
		}
		runner.result.OpenError = err.Error()
		runner.result.Observations = failedObservations(runner.queries, err)
		runner.finished = true
		return false
	}
	runner.session = session
	for index, name := range warmupNames {
		if ctx.Err() != nil {
			runner.abort(ctx.Err())
			return false
		}
		warmupType := runner.opts.QueryTypes[index%len(runner.opts.QueryTypes)]
		warmupCtx, cancel := context.WithTimeout(ctx, runner.opts.Timeout)
		_, _ = runner.session.Query(warmupCtx, name, warmupType)
		cancel()
		if ctx.Err() != nil {
			runner.abort(ctx.Err())
			return false
		}
	}
	runner.result.DialAddress = sessionDialAddress(runner.session)
	runner.ready = true
	return true
}

func (runner *targetRunner) measure(ctx context.Context, query Query) bool {
	if runner.finished || !runner.ready {
		return false
	}
	if ctx.Err() != nil {
		runner.abort(ctx.Err())
		return false
	}
	observation := Observation{Name: query.Name, QType: query.QType}
	started := time.Now()
	queryCtx, cancel := context.WithTimeout(ctx, runner.opts.Timeout)
	message, queryErr := runner.session.Query(queryCtx, query.Name, query.QType)
	observation.Reconnected = sessionQueryReconnected(runner.session)
	cancel()
	if ctx.Err() != nil {
		// The parent benchmark cancellation is not a DNS failure sample. Do
		// not manufacture an observation for work that did not complete.
		runner.abort(ctx.Err())
		return false
	}
	observation.Latency = time.Since(started)
	observation.LatencyMS = durationMS(observation.Latency)
	if queryErr != nil {
		observation.Error = queryErr.Error()
	} else if message == nil {
		// The transport should normally return an error for a nil response;
		// keep the benchmark defensive at this boundary.
		observation.Error = "empty DNS response"
	} else {
		observation.RCode = message.Rcode
		observation.Truncated = message.Truncated
		if message.Truncated {
			observation.Error = "truncated DNS response"
		} else {
			observation.Success = true
			observation.ResponseClass = transport.ResponseClass(message)
			observation.Usable = transport.IsUsableResponse(message)
		}
	}
	runner.result.Observations = append(runner.result.Observations, observation)
	return true
}

func (runner *targetRunner) abort(err error) {
	runner.ready = false
	runner.finished = true
	markIncomplete(&runner.result, err)
}

func (runner *targetRunner) close() {
	if runner.closed {
		return
	}
	runner.closed = true
	if runner.session != nil {
		runner.result.DialAddress = sessionDialAddress(runner.session)
		_ = runner.session.Close()
	}
}

func runTarget(ctx context.Context, target catalog.Target, queries []Query, opts Options) TargetResult {
	runner := newTargetRunner(ctx, target, queries, opts)
	if runner.prepare(ctx) {
		for _, query := range queries {
			if !runner.measure(ctx, query) {
				break
			}
		}
	}
	runner.close()
	return runner.result
}

func markIncomplete(result *TargetResult, err error) {
	result.Incomplete = true
	if err != nil {
		result.OpenError = err.Error()
	}
}

func sessionDialAddress(session transport.Session) string {
	type dialAddressSession interface {
		DialAddress() string
	}
	if session, ok := session.(dialAddressSession); ok {
		return session.DialAddress()
	}
	return ""
}

func sessionQueryReconnected(session transport.Session) bool {
	type queryDiagnostics interface {
		LastQueryReconnected() bool
	}
	if session, ok := session.(queryDiagnostics); ok {
		return session.LastQueryReconnected()
	}
	return false
}

func failedObservations(queries []Query, err error) []Observation {
	observations := make([]Observation, 0, len(queries))
	for _, query := range queries {
		observations = append(observations, Observation{Name: query.Name, QType: query.QType, Error: err.Error()})
	}
	return observations
}

type divergenceGroupKey struct {
	name   string
	qtype  uint16
	policy string
}

type divergenceObservation struct {
	resultIndex      int
	observationIndex int
	targetID         string
	responseClass    string
}

// markDivergence selects a plurality response class independently for each
// query and declared policy. Exact policy matching prevents an unfiltered
// resolver from being treated as equivalent to a filtering resolver. A tied
// plurality is intentionally ambiguous: all successful observations in that
// group are excluded from comparative latency scoring rather than receiving an
// arbitrary advantage from a lexicographic tie-break.
func markDivergence(results []TargetResult) []DivergenceDetail {
	groups := make(map[divergenceGroupKey][]divergenceObservation)
	for resultIndex := range results {
		policy := divergencePolicy(results[resultIndex].Target.Resolver.Policy)
		for observationIndex := range results[resultIndex].Observations {
			observation := &results[resultIndex].Observations[observationIndex]
			observation.Divergent = false
			observation.DivergenceBaseline = ""
			if !observation.Success {
				continue
			}
			key := divergenceGroupKey{
				name:   normalizedQueryName(observation.Name),
				qtype:  observation.QType,
				policy: policy,
			}
			groups[key] = append(groups[key], divergenceObservation{
				resultIndex:      resultIndex,
				observationIndex: observationIndex,
				targetID:         results[resultIndex].Target.ID(),
				responseClass:    responseClassName(observation.ResponseClass),
			})
		}
	}

	keys := make([]divergenceGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		if keys[i].qtype != keys[j].qtype {
			return keys[i].qtype < keys[j].qtype
		}
		return keys[i].policy < keys[j].policy
	})

	details := make([]DivergenceDetail, 0)
	for _, key := range keys {
		observations := groups[key]
		counts := make(map[string]int)
		for _, observation := range observations {
			counts[observation.responseClass]++
		}
		if len(counts) <= 1 {
			continue
		}

		classes := make([]string, 0, len(counts))
		maxCount := 0
		for class, count := range counts {
			if count > maxCount {
				maxCount = count
				classes = classes[:0]
			} else if count < maxCount {
				continue
			}
			classes = append(classes, class)
		}
		sort.Strings(classes)

		detail := DivergenceDetail{
			Name:     key.name,
			QType:    key.qtype,
			Policy:   key.policy,
			Compared: len(observations),
			Classes:  cloneIntMap(counts),
		}
		if len(classes) == 1 {
			detail.Baseline = classes[0]
			for _, observation := range observations {
				current := &results[observation.resultIndex].Observations[observation.observationIndex]
				current.DivergenceBaseline = detail.Baseline
				if observation.responseClass == detail.Baseline {
					continue
				}
				current.Divergent = true
				detail.Excluded = append(detail.Excluded, DivergenceExclusion{
					TargetID: observation.targetID, ResponseClass: observation.responseClass,
					Treatment: divergenceTreatment(*current),
				})
			}
		} else {
			detail.Ambiguous = true
			for _, observation := range observations {
				current := &results[observation.resultIndex].Observations[observation.observationIndex]
				current.Divergent = true
				current.DivergenceBaseline = "ambiguous"
				detail.Excluded = append(detail.Excluded, DivergenceExclusion{
					TargetID: observation.targetID, ResponseClass: observation.responseClass,
					Treatment: divergenceTreatment(*current),
				})
			}
		}
		sort.Slice(detail.Excluded, func(i, j int) bool {
			if detail.Excluded[i].TargetID != detail.Excluded[j].TargetID {
				return detail.Excluded[i].TargetID < detail.Excluded[j].TargetID
			}
			return detail.Excluded[i].ResponseClass < detail.Excluded[j].ResponseClass
		})
		details = append(details, detail)
	}
	return details
}

func normalizedQueryName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func divergencePolicy(policy string) string {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		return "unspecified"
	}
	return policy
}

func responseClassName(class string) string {
	if class == "" {
		return "unknown"
	}
	return class
}

func divergenceTreatment(observation Observation) string {
	if observationUsable(observation) {
		return "latency-excluded"
	}
	return "failure-penalized"
}

func cloneIntMap(values map[string]int) map[string]int {
	clone := make(map[string]int, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func queryKey(name string, qtype uint16) string {
	return fmt.Sprintf("%s/%d", normalizedQueryName(name), qtype)
}

type scoreSample struct {
	latencyMS float64
	success   bool
}

func calculateStatistics(result TargetResult, timeout time.Duration, seed int64) Statistics {
	stats := Statistics{Total: len(result.Observations), RCodeCounts: make(map[string]int)}
	latencies := make([]float64, 0, len(result.Observations))
	scoreSamples := make([]scoreSample, 0, len(result.Observations))
	scoringFailures := 0
	for _, observation := range result.Observations {
		if observation.Success {
			stats.Successes++
		}
		if !observation.Success {
			stats.Failures++
		}
		if observation.Truncated {
			stats.Truncated++
		}
		if observation.Reconnected {
			stats.Reconnects++
		}
		usable := observationUsable(observation)
		if observation.Success && !observation.Truncated && usable {
			stats.UsableResponses++
		}
		if observation.Success && !observation.Truncated && !usable {
			stats.ResolverFailures++
		}
		if observation.Success && !observation.Truncated && (observation.ResponseClass != "" || observation.RCode != 0 || observation.Usable) {
			stats.RCodeCounts[transport.ResponseCodeName(observation.RCode)]++
		}

		if observation.Divergent {
			stats.Divergent++
		}
		if observation.Success && !observation.Truncated && usable {
			if observation.Divergent || observation.Reconnected {
				// Valid divergent responses and responses obtained immediately
				// after a reconnect are not ordinary warm-latency samples.
				continue
			}
			stats.Scored++
			latencies = append(latencies, observation.LatencyMS)
			scoreSamples = append(scoreSamples, scoreSample{latencyMS: observation.LatencyMS, success: true})
			continue
		}

		// Unusable transport-valid responses remain scoring failures even
		// when their response class is divergent. This prevents a fast
		// SERVFAIL/REFUSED response from escaping the failure penalty.
		scoringFailures++
		scoreSamples = append(scoreSamples, scoreSample{success: false})
	}
	if len(stats.RCodeCounts) == 0 {
		stats.RCodeCounts = nil
	}
	if stats.Total > 0 {
		stats.SuccessRate = float64(stats.Successes) / float64(stats.Total)
		stats.FailureRate = float64(stats.Failures) / float64(stats.Total)
		stats.UsableRate = float64(stats.UsableResponses) / float64(stats.Total)
		stats.ResolverFailureRate = float64(stats.ResolverFailures) / float64(stats.Total)
	}
	if len(scoreSamples) > 0 {
		stats.ScoringFailureRate = float64(scoringFailures) / float64(len(scoreSamples))
	}
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		stats.MedianMS = percentile(latencies, 0.50)
		stats.P95MS = percentile(latencies, 0.95)
		stats.MinMS = latencies[0]
		stats.MaxMS = latencies[len(latencies)-1]
		stats.MADMS = mad(latencies, stats.MedianMS)
		stats.ScoreMS = scoreFromLatencies(latencies, stats.ScoringFailureRate, durationMS(timeout))
		stats.CILowMS, stats.CIHighMS = bootstrapCI(scoreSamples, timeout, bootstrapSeed(seed, result.Target.ID()))
	}
	cold := make([]float64, 0, len(result.Cold))
	for _, observation := range result.Cold {
		if observation.Success {
			cold = append(cold, observation.LatencyMS)
		}
	}
	if len(cold) > 0 {
		sort.Float64s(cold)
		stats.ColdMedianMS = percentile(cold, 0.5)
	}
	stats.Recommended = !result.Incomplete && stats.Scored >= MinimumRecommendedSamples && stats.UsableRate >= MinimumRecommendedSuccessRate
	return stats
}

// observationUsable keeps the semantic distinction explicit while retaining
// compatibility with synthetic observations created by older callers and
// tests, which only set Success and ResponseClass.
func observationUsable(observation Observation) bool {
	if !observation.Success || observation.Truncated {
		return false
	}
	if observation.Usable {
		return true
	}
	if observation.RCode != 0 {
		return false
	}
	switch observation.ResponseClass {
	case "", "answer", "nodata", "nxdomain":
		return true
	default:
		return false
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	position := p * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	weight := position - float64(lower)
	return sorted[lower] + (sorted[upper]-sorted[lower])*weight
}

func mad(sorted []float64, median float64) float64 {
	deviations := make([]float64, len(sorted))
	for i, value := range sorted {
		deviations[i] = math.Abs(value - median)
	}
	sort.Float64s(deviations)
	return percentile(deviations, 0.5)
}

func scoreFromLatencies(latencies []float64, failureRate, timeoutMS float64) float64 {
	return 0.60*percentile(latencies, 0.50) + 0.40*percentile(latencies, 0.95) + failureRate*timeoutMS
}

func scoreFromSamples(samples []scoreSample, timeoutMS float64) float64 {
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
	if len(latencies) == 0 {
		// This value is used only for confidence intervals because targets
		// without scored samples are never ranked.
		return 2 * timeoutMS
	}
	sort.Float64s(latencies)
	return scoreFromLatencies(latencies, failureRate, timeoutMS)
}

func bootstrapSeed(seed int64, targetID string) int64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(targetID))
	return seed ^ int64(hasher.Sum64())
}

func bootstrapCI(samples []scoreSample, timeout time.Duration, seed int64) (float64, float64) {
	if len(samples) < 2 {
		score := scoreFromSamples(samples, durationMS(timeout))
		return score, score
	}
	rng := rand.New(rand.NewSource(seed))
	scores := make([]float64, BootstrapIterations)
	resample := make([]scoreSample, len(samples))
	for iteration := range scores {
		for index := range resample {
			resample[index] = samples[rng.Intn(len(samples))]
		}
		scores[iteration] = scoreFromSamples(resample, durationMS(timeout))
	}
	sort.Float64s(scores)
	return percentile(scores, 0.025), percentile(scores, 0.975)
}

type pairedGroupKey struct {
	protocol catalog.Protocol
	policy   string
}

// calculatePairedEffects builds policy-local comparisons against the best
// ranked target in each protocol/policy group. It deliberately runs after
// makeRankings so the existing score remains the only ranking authority.
func calculatePairedEffects(results []TargetResult, rankings []Ranking, seed int64) []PairedEffect {
	ranks := make(map[string]int, len(rankings))
	for _, ranking := range rankings {
		ranks[ranking.TargetID] = ranking.Rank
	}
	groups := make(map[pairedGroupKey][]int)
	for index, result := range results {
		if result.Incomplete || result.Stats.Scored == 0 {
			continue
		}
		key := pairedGroupKey{protocol: result.Target.Protocol, policy: divergencePolicy(result.Target.Resolver.Policy)}
		groups[key] = append(groups[key], index)
	}
	keys := make([]pairedGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].protocol != keys[j].protocol {
			return keys[i].protocol < keys[j].protocol
		}
		return keys[i].policy < keys[j].policy
	})

	effects := make([]PairedEffect, 0)
	for _, key := range keys {
		indexes := groups[key]
		sort.Slice(indexes, func(i, j int) bool {
			left, right := results[indexes[i]], results[indexes[j]]
			leftRank, rightRank := ranks[left.Target.ID()], ranks[right.Target.ID()]
			if leftRank == 0 {
				leftRank = len(results) + 1
			}
			if rightRank == 0 {
				rightRank = len(results) + 1
			}
			if leftRank != rightRank {
				return leftRank < rightRank
			}
			if left.Stats.ScoreMS != right.Stats.ScoreMS {
				return left.Stats.ScoreMS < right.Stats.ScoreMS
			}
			return left.Target.ID() < right.Target.ID()
		})
		reference := results[indexes[0]]
		for _, index := range indexes {
			target := results[index]
			effect := PairedEffect{
				Protocol:          key.protocol,
				Policy:            key.policy,
				TargetID:          target.Target.ID(),
				ReferenceTargetID: reference.Target.ID(),
				Reference:         target.Target.ID() == reference.Target.ID(),
			}
			deltas := pairedLatencyDeltas(target, reference)
			effect.Samples = len(deltas)
			if effect.Reference {
				if effect.Samples == 0 {
					effect.Reason = "no scored samples"
				}
				effects = append(effects, effect)
				continue
			}
			if len(deltas) == 0 {
				effect.Reason = "no shared scored samples"
				effects = append(effects, effect)
				continue
			}
			if len(deltas) < MinimumRecommendedSamples {
				effect.Reason = fmt.Sprintf("insufficient paired samples (minimum %d)", MinimumRecommendedSamples)
				effects = append(effects, effect)
				continue
			}
			sort.Float64s(deltas)
			effect.MedianDeltaMS = percentile(deltas, 0.5)
			effect.CILowMS, effect.CIHighMS = bootstrapPairedCI(deltas, pairedBootstrapSeed(seed, key.protocol, key.policy, reference.Target.ID(), target.Target.ID()))
			effect.Indistinguishable = effect.CILowMS <= 0 && effect.CIHighMS >= 0
			effects = append(effects, effect)
		}
	}
	sort.Slice(effects, func(i, j int) bool {
		if effects[i].Protocol != effects[j].Protocol {
			return effects[i].Protocol < effects[j].Protocol
		}
		if effects[i].Policy != effects[j].Policy {
			return effects[i].Policy < effects[j].Policy
		}
		return effects[i].TargetID < effects[j].TargetID
	})
	return effects
}

func pairedLatencyDeltas(target, reference TargetResult) []float64 {
	targetLatencies := pairedObservationLatencies(target)
	referenceLatencies := pairedObservationLatencies(reference)
	keys := make([]string, 0, len(targetLatencies))
	for key := range targetLatencies {
		if _, ok := referenceLatencies[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	deltas := make([]float64, 0, len(keys))
	for _, key := range keys {
		deltas = append(deltas, targetLatencies[key]-referenceLatencies[key])
	}
	return deltas
}

func pairedObservationLatencies(result TargetResult) map[string]float64 {
	latencies := make(map[string]float64)
	for _, observation := range result.Observations {
		if !observationUsable(observation) || observation.Divergent || observation.Reconnected ||
			math.IsNaN(observation.LatencyMS) || math.IsInf(observation.LatencyMS, 0) || observation.LatencyMS < 0 {
			continue
		}
		key := queryKey(observation.Name, observation.QType)
		if _, exists := latencies[key]; !exists {
			latencies[key] = observation.LatencyMS
		}
	}
	return latencies
}

func pairedBootstrapSeed(seed int64, protocol catalog.Protocol, policy, referenceID, targetID string) int64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(string(protocol)))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(policy))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(referenceID))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(targetID))
	return seed ^ int64(hasher.Sum64())
}

func bootstrapPairedCI(deltas []float64, seed int64) (float64, float64) {
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
		scores[iteration] = percentile(resample, 0.5)
	}
	sort.Float64s(scores)
	return percentile(scores, 0.025), percentile(scores, 0.975)
}

func makeRankings(results []TargetResult) []Ranking {
	byProtocol := make(map[catalog.Protocol][]int)
	for index, result := range results {
		if result.Stats.Scored > 0 && !result.Incomplete {
			byProtocol[result.Target.Protocol] = append(byProtocol[result.Target.Protocol], index)
		}
	}
	var rankings []Ranking
	for protocol, indexes := range byProtocol {
		sort.Slice(indexes, func(i, j int) bool {
			left, right := results[indexes[i]], results[indexes[j]]
			if left.Stats.ScoreMS != right.Stats.ScoreMS {
				return left.Stats.ScoreMS < right.Stats.ScoreMS
			}
			return left.Target.ID() < right.Target.ID()
		})
		leader := results[indexes[0]].Stats
		leaderTie := false
		protocolRankingStart := len(rankings)
		for rank, index := range indexes {
			tie := false
			if rank > 0 && confidenceIntervalsOverlap(leader, results[index].Stats) {
				tie = true
				leaderTie = true
			}
			results[index].Stats.Tie = tie
			rankings = append(rankings, Ranking{Protocol: protocol, TargetID: results[index].Target.ID(), Rank: rank + 1, Tie: tie})
		}
		results[indexes[0]].Stats.Tie = leaderTie
		rankings[protocolRankingStart].Tie = leaderTie
	}
	sort.Slice(rankings, func(i, j int) bool {
		if rankings[i].Protocol != rankings[j].Protocol {
			return rankings[i].Protocol < rankings[j].Protocol
		}
		return rankings[i].Rank < rankings[j].Rank
	})
	return rankings
}

func confidenceIntervalsOverlap(left, right Statistics) bool {
	leftLow, leftHigh := left.CILowMS, left.CIHighMS
	rightLow, rightHigh := right.CILowMS, right.CIHighMS
	if leftLow == 0 && leftHigh == 0 && left.ScoreMS != 0 {
		leftLow, leftHigh = left.ScoreMS, left.ScoreMS
	}
	if rightLow == 0 && rightHigh == 0 && right.ScoreMS != 0 {
		rightLow, rightHigh = right.ScoreMS, right.ScoreMS
	}
	return leftLow <= rightHigh && rightLow <= leftHigh
}

// collectWarnings renders one warning per diagnostic. The resolver label and
// the session error are escaped here, at the point they become report text:
// the label carries locally configured resolver names and addresses, and the
// session error carries transport and TLS diagnostics that quote strings the
// remote endpoint chose, such as the subject alternative names in
// "x509: certificate is valid for ...". Warnings are printed verbatim under
// --details, so neither may reach a terminal with its control characters
// intact.
func collectWarnings(results []TargetResult) []string {
	warnings := make([]string, 0)
	for _, result := range results {
		label := safetext.Escape(fmt.Sprintf("%s %s/%s", result.Target.DisplayName(), result.Target.Address, result.Target.Protocol))
		if result.Incomplete {
			warnings = append(warnings, fmt.Sprintf("%s was incomplete and excluded from ranking", label))
		}
		if result.OpenError != "" {
			warnings = append(warnings, fmt.Sprintf("%s could not open a session: %s", label, safetext.Escape(result.OpenError)))
		}
		if result.Stats.Failures > 0 {
			warnings = append(warnings, fmt.Sprintf("%s had %d/%d failed queries", label, result.Stats.Failures, result.Stats.Total))
		}
		if result.Stats.Divergent > 0 {
			warnings = append(warnings, fmt.Sprintf("%s had %d divergent responses excluded from latency scoring", label, result.Stats.Divergent))
		}
		if result.Stats.Truncated > 0 {
			warnings = append(warnings, fmt.Sprintf("%s returned %d truncated responses; SpeeDNS did not fall back to another transport", label, result.Stats.Truncated))
		}
		if result.Stats.ResolverFailures > 0 {
			warning := fmt.Sprintf("%s returned %d unusable DNS responses", label, result.Stats.ResolverFailures)
			if codes := formatRCodeCounts(result.Stats.RCodeCounts); codes != "" {
				warning += " (" + codes + ")"
			}
			warnings = append(warnings, warning)
		}
		if result.Stats.Scored > 0 && !result.Incomplete && !result.Stats.Recommended {
			warnings = append(warnings, fmt.Sprintf("%s is not recommendation-eligible yet: needs at least %d comparable samples and %.0f%% usable responses", label, MinimumRecommendedSamples, MinimumRecommendedSuccessRate*100))
		}
	}
	return warnings
}

func formatRCodeCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func durationMS(duration time.Duration) float64 { return float64(duration) / float64(time.Millisecond) }

// QueryTypeName formats the record type for reports and CLI output.
func QueryTypeName(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}
