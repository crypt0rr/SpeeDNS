package benchmark

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// This file holds the target-level scheduler. It is a test fixture rather than
// production code: runProtocol defaults to runProtocolFair, and nothing outside
// a test selects the path below. It is kept because a large number of tests fake
// a whole target rather than a transport, which this scheduler makes cheap. It
// reports an interrupted group the way the fair scheduler does -- every target
// it was given, the undispatched ones as unmeasured incomplete results -- so a
// whole-target fake still describes the shipped result set.

// runTargetFunc is the target-level seam. Replacing it has no effect unless
// runProtocolLegacy is also selected, which useTargetSeam does for both.
var runTargetFunc = runTarget

// runProtocolLegacy dispatches whole targets to a worker pool through the
// runTargetFunc seam and returns a result for every target, in input order. It
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
	for index, wasDispatched := range dispatched {
		if !wasDispatched {
			results[index] = unmeasuredResult(targets[index], ctx.Err())
		}
	}
	emitProgress(opts, Progress{
		Protocol:           targets[0].Protocol,
		Phase:              ProgressComplete,
		TargetsCompleted:   int(completedTargets.Load()),
		TargetsTotal:       len(targets),
		ExchangesCompleted: int(completedExchanges.Load()),
		ExchangesTotal:     len(targets) * len(queries),
	})
	return results
}

func runTarget(ctx context.Context, target catalog.Target, queries []Query, opts Options) TargetResult {
	runner := newTargetRunner(ctx, target, queries, opts)
	if runner.prepare(ctx) {
		for _, query := range queries {
			if !runner.measure(ctx, query) {
				break
			}
		}
		runner.probeDNSSEC(ctx)
	}
	runner.close()
	return runner.result
}
