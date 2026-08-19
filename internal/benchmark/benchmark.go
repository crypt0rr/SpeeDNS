package benchmark

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/dns-speedtest/internal/catalog"
	"github.com/crypt0rr/dns-speedtest/internal/transport"
	"github.com/miekg/dns"
)

const (
	DefaultSample                 = 100
	DefaultTimeout                = 2 * time.Second
	DefaultConcurrency            = 4
	BootstrapIterations           = 1000
	MinimumRecommendedSamples     = 20
	MinimumRecommendedSuccessRate = 0.99
)

var warmupNames = []string{"example.com", "example.org", "example.net"}

// newFactory is kept as a small dependency seam so the scheduler and
// statistics engine can be tested without contacting a real resolver.
var newFactory = transport.NewFactory

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

type Progress struct {
	Protocol  catalog.Protocol
	Completed int
	Total     int
	Target    catalog.Target
}

type Query struct {
	Name  string
	QType uint16
}

type Observation struct {
	Name          string        `json:"name"`
	QType         uint16        `json:"qtype"`
	Latency       time.Duration `json:"-"`
	LatencyMS     float64       `json:"latency_ms,omitempty"`
	Success       bool          `json:"success"`
	Truncated     bool          `json:"truncated,omitempty"`
	ResponseClass string        `json:"response_class,omitempty"`
	Divergent     bool          `json:"divergent,omitempty"`
	Error         string        `json:"error,omitempty"`
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
	Total        int     `json:"total"`
	Successes    int     `json:"successes"`
	Failures     int     `json:"failures"`
	Scored       int     `json:"scored"`
	Divergent    int     `json:"divergent"`
	Truncated    int     `json:"truncated"`
	SuccessRate  float64 `json:"success_rate"`
	FailureRate  float64 `json:"failure_rate"`
	MedianMS     float64 `json:"median_ms"`
	P95MS        float64 `json:"p95_ms"`
	MinMS        float64 `json:"min_ms"`
	MaxMS        float64 `json:"max_ms"`
	MADMS        float64 `json:"mad_ms"`
	ColdMedianMS float64 `json:"cold_median_ms,omitempty"`
	ScoreMS      float64 `json:"score_ms"`
	CILowMS      float64 `json:"ci_low_ms,omitempty"`
	CIHighMS     float64 `json:"ci_high_ms,omitempty"`
	Recommended  bool    `json:"recommended"`
	Tie          bool    `json:"tie,omitempty"`
}

type TargetResult struct {
	Target       catalog.Target    `json:"-"`
	Observations []Observation     `json:"samples,omitempty"`
	Cold         []ColdObservation `json:"cold,omitempty"`
	Stats        Statistics        `json:"stats"`
	OpenError    string            `json:"open_error,omitempty"`
	DialAddress  string            `json:"-"`
}

type Ranking struct {
	Protocol catalog.Protocol `json:"protocol"`
	TargetID string           `json:"target_id"`
	Rank     int              `json:"rank"`
	Tie      bool             `json:"tie"`
}

type Report struct {
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Seed       int64          `json:"seed"`
	SampleSize int            `json:"sample_size"`
	Queries    int            `json:"queries_per_target"`
	QueryTypes []uint16       `json:"query_types"`
	Targets    []TargetResult `json:"results"`
	Rankings   []Ranking      `json:"rankings"`
	Warnings   []string       `json:"warnings,omitempty"`
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
// the same shuffled query sequence, while the worker limit prevents a run from
// creating an unbounded number of simultaneous connections.
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

	byProtocol := make(map[catalog.Protocol][]catalog.Target)
	for _, target := range targets {
		byProtocol[target.Protocol] = append(byProtocol[target.Protocol], target)
	}
	protocols := make([]catalog.Protocol, 0, len(byProtocol))
	for protocol := range byProtocol {
		protocols = append(protocols, protocol)
	}
	sort.Slice(protocols, func(i, j int) bool { return protocols[i] < protocols[j] })

	for _, protocol := range protocols {
		groupResults := runProtocol(ctx, byProtocol[protocol], queries, opts)
		markDivergence(groupResults)
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
	report.Warnings = collectWarnings(report.Targets)
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if len(report.Rankings) == 0 {
		return report, errors.New("no comparable DNS results were produced")
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
	domains := normalizeDomains(opts.Domains)
	if len(domains) == 0 {
		return nil, errors.New("domain corpus has no valid names")
	}
	source := append([]string(nil), domains...)
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

func normalizeDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(strings.ToLower(domain))
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

func runProtocol(ctx context.Context, targets []catalog.Target, queries []Query, opts Options) []TargetResult {
	results := make([]TargetResult, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var completed atomic.Int32
	workers := opts.Concurrency
	if workers > len(targets) {
		workers = len(targets)
	}
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = runTargetFunc(ctx, targets[index], queries, opts)
				if opts.OnProgress != nil {
					opts.OnProgress(Progress{Protocol: targets[index].Protocol, Completed: int(completed.Add(1)), Total: len(targets), Target: targets[index]})
				}
			}
		}()
	}
	for index := range targets {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func runTarget(ctx context.Context, target catalog.Target, queries []Query, opts Options) TargetResult {
	result := TargetResult{Target: target, Observations: make([]Observation, 0, len(queries))}
	factory, err := newFactory(target, opts.Timeout)
	if err != nil {
		result.OpenError = err.Error()
		result.Observations = failedObservations(queries, err)
		return result
	}
	for index := 0; index < 3; index++ {
		probe := warmupNames[index%len(warmupNames)]
		qtype := opts.QueryTypes[index%len(opts.QueryTypes)]
		started := time.Now()
		session, openErr := factory.Open(ctx)
		observation := ColdObservation{Name: probe, QType: qtype}
		if openErr != nil {
			observation.Error = openErr.Error()
			result.Cold = append(result.Cold, observation)
			continue
		}
		queryCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		_, queryErr := session.Query(queryCtx, probe, qtype)
		cancel()
		_ = session.Close()
		observation.Latency = time.Since(started)
		observation.LatencyMS = durationMS(observation.Latency)
		if queryErr != nil {
			observation.Error = queryErr.Error()
		} else {
			observation.Success = true
		}
		result.Cold = append(result.Cold, observation)
	}

	session, err := factory.Open(ctx)
	if err != nil {
		result.OpenError = err.Error()
		result.Observations = failedObservations(queries, err)
		return result
	}
	defer session.Close()
	for index, name := range warmupNames {
		if ctx.Err() != nil {
			result.OpenError = ctx.Err().Error()
			result.Observations = failedObservations(queries, ctx.Err())
			return result
		}
		warmupType := opts.QueryTypes[index%len(opts.QueryTypes)]
		warmupCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		_, _ = session.Query(warmupCtx, name, warmupType)
		cancel()
	}
	result.DialAddress = sessionDialAddress(session)
	for _, query := range queries {
		observation := Observation{Name: query.Name, QType: query.QType}
		if ctx.Err() != nil {
			observation.Error = ctx.Err().Error()
			result.Observations = append(result.Observations, observation)
			continue
		}
		started := time.Now()
		queryCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		message, queryErr := session.Query(queryCtx, query.Name, query.QType)
		cancel()
		observation.Latency = time.Since(started)
		observation.LatencyMS = durationMS(observation.Latency)
		if queryErr != nil {
			observation.Error = queryErr.Error()
		} else {
			observation.Truncated = message.Truncated
			if message.Truncated {
				observation.Error = "truncated DNS response"
			} else {
				observation.Success = true
				observation.ResponseClass = transport.ResponseClass(message)
			}
		}
		result.Observations = append(result.Observations, observation)
	}
	return result
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

func failedObservations(queries []Query, err error) []Observation {
	observations := make([]Observation, 0, len(queries))
	for _, query := range queries {
		observations = append(observations, Observation{Name: query.Name, QType: query.QType, Error: err.Error()})
	}
	return observations
}

func markDivergence(results []TargetResult) {
	classes := make(map[string]map[string]struct{})
	for _, result := range results {
		for _, observation := range result.Observations {
			if !observation.Success {
				continue
			}
			key := queryKey(observation.Name, observation.QType)
			if classes[key] == nil {
				classes[key] = make(map[string]struct{})
			}
			classes[key][observation.ResponseClass] = struct{}{}
		}
	}
	for i := range results {
		for j := range results[i].Observations {
			observation := &results[i].Observations[j]
			key := queryKey(observation.Name, observation.QType)
			if observation.Success && len(classes[key]) > 1 {
				observation.Divergent = true
			}
		}
	}
}

func queryKey(name string, qtype uint16) string {
	return fmt.Sprintf("%s/%d", strings.ToLower(name), qtype)
}

func calculateStatistics(result TargetResult, timeout time.Duration, seed int64) Statistics {
	stats := Statistics{Total: len(result.Observations)}
	latencies := make([]float64, 0, len(result.Observations))
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
		if observation.Divergent {
			stats.Divergent++
			continue
		}
		if observation.Success {
			stats.Scored++
			latencies = append(latencies, observation.LatencyMS)
		}
	}
	if stats.Total > 0 {
		stats.SuccessRate = float64(stats.Successes) / float64(stats.Total)
		stats.FailureRate = float64(stats.Failures) / float64(stats.Total)
	}
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		stats.MedianMS = percentile(latencies, 0.50)
		stats.P95MS = percentile(latencies, 0.95)
		stats.MinMS = latencies[0]
		stats.MaxMS = latencies[len(latencies)-1]
		stats.MADMS = mad(latencies, stats.MedianMS)
		stats.ScoreMS = 0.60*stats.MedianMS + 0.40*stats.P95MS + stats.FailureRate*durationMS(timeout)
		stats.CILowMS, stats.CIHighMS = bootstrapCI(latencies, stats.FailureRate, timeout, seed+int64(len(result.Target.ID())))
	}
	for _, observation := range result.Cold {
		if observation.Success {
			// Cold probes are kept separate from warm scores. The median is
			// populated after sorting to avoid changing the warm ranking.
		}
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
	stats.Recommended = stats.Scored >= MinimumRecommendedSamples && stats.SuccessRate >= MinimumRecommendedSuccessRate
	return stats
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

func bootstrapCI(latencies []float64, failureRate float64, timeout time.Duration, seed int64) (float64, float64) {
	if len(latencies) < 2 {
		score := 0.60*percentile(latencies, 0.5) + 0.40*percentile(latencies, 0.95) + failureRate*durationMS(timeout)
		return score, score
	}
	rng := rand.New(rand.NewSource(seed))
	scores := make([]float64, BootstrapIterations)
	resample := make([]float64, len(latencies))
	for iteration := range scores {
		for index := range resample {
			resample[index] = latencies[rng.Intn(len(latencies))]
		}
		sort.Float64s(resample)
		scores[iteration] = 0.60*percentile(resample, 0.5) + 0.40*percentile(resample, 0.95) + failureRate*durationMS(timeout)
	}
	sort.Float64s(scores)
	return percentile(scores, 0.025), percentile(scores, 0.975)
}

func makeRankings(results []TargetResult) []Ranking {
	byProtocol := make(map[catalog.Protocol][]int)
	for index, result := range results {
		if result.Stats.Scored > 0 {
			byProtocol[result.Target.Protocol] = append(byProtocol[result.Target.Protocol], index)
		}
	}
	var rankings []Ranking
	for protocol, indexes := range byProtocol {
		sort.Slice(indexes, func(i, j int) bool {
			return results[indexes[i]].Stats.ScoreMS < results[indexes[j]].Stats.ScoreMS
		})
		for rank, index := range indexes {
			tie := false
			if rank > 0 {
				previous := results[indexes[rank-1]].Stats
				current := results[index].Stats
				tie = current.CILowMS <= previous.CIHighMS && previous.CILowMS <= current.CIHighMS
			}
			results[index].Stats.Tie = tie
			rankings = append(rankings, Ranking{Protocol: protocol, TargetID: results[index].Target.ID(), Rank: rank + 1, Tie: tie})
		}
	}
	sort.Slice(rankings, func(i, j int) bool {
		if rankings[i].Protocol != rankings[j].Protocol {
			return rankings[i].Protocol < rankings[j].Protocol
		}
		return rankings[i].Rank < rankings[j].Rank
	})
	return rankings
}

func collectWarnings(results []TargetResult) []string {
	warnings := make([]string, 0)
	for _, result := range results {
		label := fmt.Sprintf("%s %s/%s", result.Target.DisplayName(), result.Target.Address, result.Target.Protocol)
		if result.OpenError != "" {
			warnings = append(warnings, fmt.Sprintf("%s could not open a session: %s", label, result.OpenError))
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
		if result.Stats.Scored > 0 && !result.Stats.Recommended {
			warnings = append(warnings, fmt.Sprintf("%s is not recommendation-eligible yet: needs at least %d comparable samples and %.0f%% success", label, MinimumRecommendedSamples, MinimumRecommendedSuccessRate*100))
		}
	}
	return warnings
}

func durationMS(duration time.Duration) float64 { return float64(duration) / float64(time.Millisecond) }

// QueryTypeName formats the record type for reports and CLI output.
func QueryTypeName(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}
