package benchmark

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/miekg/dns"
)

func TestDeterministicResolverFixtureCoversBenchmarkOutcomes(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
		if target.Resolver.ID == "fixture-open-failure" {
			return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
				return nil, errors.New("fixture connection failure")
			}}, nil
		}
		return &fakeFactory{opens: []fakeOpen{
			{session: fixtureSession(target)},
			{session: fixtureSession(target)},
			{session: fixtureSession(target)},
			{session: fixtureSession(target)},
		}}, nil
	}

	targets := []catalog.Target{
		fixtureTarget("steady", "127.0.0.1", "unfiltered"),
		fixtureTarget("flaky", "127.0.0.2", "unfiltered"),
		fixtureTarget("outlier", "127.0.0.3", "unfiltered"),
		fixtureTarget("protected", "127.0.0.4", "protective"),
		fixtureTarget("open-failure", "127.0.0.5", "unfiltered"),
	}
	opts := Options{
		Domains: []string{
			"answer.example", "divergent.example", "filtered.example",
			"servfail.example", "truncated.example", "lost.example",
		},
		QueryTypes:  []uint16{dns.TypeA},
		Sample:      6,
		Seed:        1234,
		Timeout:     time.Second,
		Concurrency: 2,
	}
	report, err := Run(context.Background(), targets, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Targets) != len(targets) || len(report.Rankings) == 0 {
		t.Fatalf("fixture report targets/rankings = %d/%d", len(report.Targets), len(report.Rankings))
	}
	if len(report.PairedEffects) < 3 {
		t.Fatalf("fixture paired effects = %d, want at least 3", len(report.PairedEffects))
	}

	flaky, ok := report.ResultFor(targets[1].ID())
	if !ok {
		t.Fatal("flaky fixture result missing")
	}
	if flaky.Stats.ResolverFailures == 0 || flaky.Stats.Truncated == 0 || flaky.Stats.Failures == 0 || flaky.Stats.Scored == 0 {
		t.Fatalf("flaky fixture statistics = %#v", flaky.Stats)
	}
	if observation, ok := fixtureObservation(flaky, "servfail.example"); !ok || !strings.Contains(observation.ResponseClass, "rcode-2") || observation.Usable {
		t.Fatalf("SERVFAIL fixture observation = %#v/%v", observation, ok)
	}
	if observation, ok := fixtureObservation(flaky, "truncated.example"); !ok || !observation.Truncated || observation.Usable {
		t.Fatalf("truncated fixture observation = %#v/%v", observation, ok)
	}
	if observation, ok := fixtureObservation(flaky, "lost.example"); !ok || observation.Success || observation.Error == "" {
		t.Fatalf("loss fixture observation = %#v/%v", observation, ok)
	}

	outlier, ok := report.ResultFor(targets[2].ID())
	if !ok {
		t.Fatal("outlier fixture result missing")
	}
	observation, ok := fixtureObservation(outlier, "divergent.example")
	if !ok || !observation.Divergent || observation.DivergenceBaseline != "answer" {
		t.Fatalf("outlier fixture observation = %#v/%v", observation, ok)
	}
	if !fixtureHasDivergence(report, "divergent.example", "unfiltered") {
		t.Fatalf("fixture divergence details = %#v", report.Divergence)
	}
	if fixtureHasDivergence(report, "filtered.example", "protective") {
		t.Fatalf("policy-divergent response was compared: %#v", report.Divergence)
	}

	protected, ok := report.ResultFor(targets[3].ID())
	if !ok {
		t.Fatal("protected fixture result missing")
	}
	if observation, ok := fixtureObservation(protected, "filtered.example"); !ok || observation.ResponseClass != "nxdomain" || !observation.Usable {
		t.Fatalf("policy fixture observation = %#v/%v", observation, ok)
	}

	failed, ok := report.ResultFor(targets[4].ID())
	if !ok || failed.OpenError == "" || failed.Stats.Failures != failed.Stats.Total {
		t.Fatalf("open failure fixture result = %#v/%v", failed, ok)
	}
}

// TestFairSchedulerRunCancellationIsCompleteAndUnranked pins the cancellation
// contract of the scheduler the binary actually ships. A cancelled run lists
// every selected target, marks each of them incomplete, and ranks none of them;
// a target the interrupt kept from reaching a worker is listed with no
// observations rather than dropped.
func TestFairSchedulerRunCancellationIsCompleteAndUnranked(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	cancellationOptions := func() Options {
		return Options{
			Domains:     []string{"one.example", "two.example"},
			QueryTypes:  []uint16{dns.TypeA},
			Sample:      2,
			Seed:        99,
			Timeout:     time.Second,
			Concurrency: 1,
		}
	}
	// Targets are named so the fair scheduler's identity sort prepares and
	// measures "alpha" before "beta".
	targets := []catalog.Target{testTarget(catalog.UDP, "alpha"), testTarget(catalog.UDP, "beta")}

	t.Run("cancelled while measuring", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		measuring := make(chan struct{})
		var measuringOnce sync.Once
		release := make(chan struct{})
		blocking := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			// Warm-up probes use example.com/.org/.net, so only a measured
			// corpus query parks the single worker.
			if strings.HasSuffix(name, ".example") {
				measuringOnce.Do(func() { close(measuring) })
				<-release
			}
			return replyFor(name, qtype), nil
		}}
		newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
			warm := transport.Session(&fakeSession{})
			if target.Address == "alpha" {
				warm = blocking
			}
			return &fakeFactory{opens: []fakeOpen{
				{session: &fakeSession{}},
				{session: &fakeSession{}},
				{session: &fakeSession{}},
				{session: warm},
			}}, nil
		}

		type outcome struct {
			report Report
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			report, err := Run(ctx, targets, cancellationOptions())
			done <- outcome{report: report, err: err}
		}()
		<-measuring
		cancel()
		close(release)
		got := <-done

		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("cancelled fair Run error = %v, want context canceled", got.err)
		}
		if len(got.report.Targets) != len(targets) {
			t.Fatalf("cancelled fair Run returned %d of %d prepared targets: %#v", len(got.report.Targets), len(targets), got.report.Targets)
		}
		for index, result := range got.report.Targets {
			if result.Target.ID() != targets[index].ID() {
				t.Fatalf("cancelled fair Run target[%d] = %q, want %q", index, result.Target.ID(), targets[index].ID())
			}
			if !result.Incomplete || result.OpenError != context.Canceled.Error() {
				t.Fatalf("cancelled fair Run target[%d] = %#v, want an incomplete cancelled result", index, result)
			}
		}
		if len(got.report.Rankings) != 0 {
			t.Fatalf("cancelled fair Run rankings = %#v, want none", got.report.Rankings)
		}
		for _, target := range targets {
			if !containsWarning(got.report.Warnings, target.Address+"/udp was incomplete and excluded from ranking") {
				t.Fatalf("cancelled fair Run warnings = %#v", got.report.Warnings)
			}
		}
	})

	t.Run("cancelled while preparing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
			if target.Address != "alpha" {
				t.Errorf("target %q was prepared after cancellation", target.Address)
			}
			return &scriptedFactory{open: func(index int, _ context.Context) (transport.Session, error) {
				if index == 0 {
					cancel()
				}
				return minimalSession{}, nil
			}}, nil
		}
		report, err := Run(ctx, targets, cancellationOptions())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preparation Run error = %v, want context canceled", err)
		}
		// With one preparation worker, "beta" waits for "alpha"'s cold probes
		// and the interrupt lands first, so it never reaches a worker. It is
		// still part of the selected set and must be listed.
		if len(report.Targets) != len(targets) {
			t.Fatalf("cancelled preparation Run targets = %#v, want every selected target", report.Targets)
		}
		for index, result := range report.Targets {
			if result.Target.ID() != targets[index].ID() || !result.Incomplete ||
				result.OpenError != context.Canceled.Error() || len(result.Observations) != 0 {
				t.Fatalf("cancelled preparation result[%d] = %#v, want incomplete and cancelled with no samples", index, result)
			}
		}
		if beta := report.Targets[1]; len(beta.Cold) != 0 || beta.Stats.Total != 0 || beta.DialAddress != "" {
			t.Fatalf("undispatched target = %#v, want no cold probes, statistics or session", beta)
		}
		if len(report.Rankings) != 0 {
			t.Fatalf("cancelled preparation rankings = %#v, want none", report.Rankings)
		}
	})
}

// TestInterruptedRunListsEverySelectedTarget pins the interrupted-report
// contract across protocol groups. Groups are measured one after another, and
// an interrupt used to drop every group that had not started and every target
// of the current group that had not reached a worker, so the report was
// silently short and speedns diff read the interrupt as removed targets. The
// report now lists exactly the selected targets: a group that finished keeps
// its ranked results, and every other target that had not already failed is
// incomplete, with the cancellation as its diagnostic and no observation it
// did not measure. A target whose session had already failed to open keeps
// that final FAILED result and its own error, which METHODOLOGY's
// interruption section states as the one exception.
func TestInterruptedRunListsEverySelectedTarget(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	// Given out of order on purpose: the report lists targets by identity.
	targets := []catalog.Target{
		testTarget(catalog.DoH, "6"), testTarget(catalog.TCP, "4"), testTarget(catalog.UDP, "1"),
		testTarget(catalog.TCP, "3"), testTarget(catalog.UDP, "2"), testTarget(catalog.DoH, "7"),
		testTarget(catalog.TCP, "5"),
	}
	selected := make([]string, 0, len(targets))
	for _, target := range targets {
		selected = append(selected, target.ID())
	}
	sort.Strings(selected)

	for _, tc := range []struct {
		name string
		// interrupt returns the factory for a target, given the run's cancel.
		interrupt func(target catalog.Target, cancel context.CancelFunc) transport.Factory
		// finished is the protocol whose group completed before the interrupt.
		finished catalog.Protocol
		// started holds the targets that reached a preparation worker.
		started map[string]bool
		// racy is a target the dispatcher may still hand out if the worker
		// returns for it before the dispatcher observes the cancellation. It
		// then aborts before its first cold probe, so it carries no data.
		racy string
		// failed is a target of the interrupted group whose every session
		// open fails before the interrupt, so its outcome is already final.
		failed string
	}{
		{
			name: "during the first measured udp query",
			interrupt: func(target catalog.Target, cancel context.CancelFunc) transport.Factory {
				return dnssecFactory(&fakeSession{query: func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
					// Warm-up probes use example.com/.org/.net, so only a
					// measured corpus query interrupts the run.
					if strings.HasSuffix(name, ".example") {
						cancel()
						return nil, ctx.Err()
					}
					return replyFor(name, qtype), nil
				}})
			},
			started: map[string]bool{targets[2].ID(): true, targets[4].ID(): true},
			// With one worker, udp "1" is prepared first and fails to open,
			// then udp "2" is the only ready target and interrupts the run.
			failed: targets[2].ID(),
		},
		{
			name: "while preparing the second tcp target",
			interrupt: func(target catalog.Target, cancel context.CancelFunc) transport.Factory {
				if target.Protocol != catalog.TCP {
					return dnssecFactory(&fakeSession{})
				}
				// One preparation worker: the first TCP target's cold probe
				// interrupts the run while the other two wait for it.
				return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
					cancel()
					return minimalSession{}, nil
				}}
			},
			finished: catalog.UDP,
			started:  map[string]bool{targets[2].ID(): true, targets[4].ID(): true, targets[3].ID(): true},
			racy:     targets[1].ID(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var mu sync.Mutex
			prepared := make(map[string]bool)
			progressed := make(map[catalog.Protocol]bool)
			newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
				mu.Lock()
				prepared[target.ID()] = true
				mu.Unlock()
				if target.ID() == tc.failed {
					return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
						return nil, errors.New("fixture connection refused")
					}}, nil
				}
				return tc.interrupt(target, cancel), nil
			}
			report, err := Run(ctx, targets, Options{
				Domains: []string{"one.example", "two.example"}, QueryTypes: []uint16{dns.TypeA}, Sample: 2, Seed: 11,
				Timeout: time.Second, Concurrency: 1,
				OnProgress: func(progress Progress) {
					mu.Lock()
					progressed[progress.Protocol] = true
					mu.Unlock()
				},
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted Run error = %v, want the cancellation", err)
			}
			listed := make([]string, 0, len(report.Targets))
			for _, result := range report.Targets {
				listed = append(listed, result.Target.ID())
			}
			if len(listed) != len(selected) {
				t.Fatalf("interrupted report lists %v, want every selected target %v", listed, selected)
			}
			for index, result := range report.Targets {
				id := result.Target.ID()
				if id != selected[index] {
					t.Fatalf("interrupted report target[%d] = %q, want %q", index, id, selected[index])
				}
				endpoint := result.Target.Address + "/" + string(result.Target.Protocol)
				if id == tc.failed {
					// The open failure was final before the interrupt: the
					// target stays FAILED with its own error and one failed
					// observation per query, and is never relabelled as
					// incomplete or given the cancellation as its diagnostic.
					if result.Incomplete || result.OpenError != "fixture connection refused" ||
						len(result.Observations) != 2 || result.Stats.Failures != 2 || result.Stats.Scored != 0 {
						t.Fatalf("%s failed to open before the interrupt but is %+v", id, result)
					}
					if !containsWarning(report.Warnings, endpoint+" could not open a session: fixture connection refused") ||
						containsWarning(report.Warnings, endpoint+" was incomplete") {
						t.Fatalf("%s warnings = %v, want its open failure and no incomplete warning", id, report.Warnings)
					}
					continue
				}
				if result.Target.Protocol == tc.finished {
					if result.Incomplete || len(result.Observations) != 2 || result.Stats.Scored != 2 {
						t.Fatalf("%s finished before the interrupt but is %+v", id, result)
					}
					continue
				}
				// Nothing outside the finished group completed a measured
				// query before the interrupt, so no observation may exist.
				if !result.Incomplete || result.OpenError != context.Canceled.Error() || len(result.Observations) != 0 || result.Stats.Total != 0 {
					t.Fatalf("%s = %+v, want incomplete and cancelled with no observations", id, result)
				}
				if !tc.started[id] && len(result.Cold) != 0 {
					t.Fatalf("%s never reached a worker but carries cold probes: %+v", id, result.Cold)
				}
				if !containsWarning(report.Warnings, endpoint+" was incomplete and excluded from ranking") {
					t.Fatalf("%s has no incomplete warning: %v", id, report.Warnings)
				}
				// Most of these targets never tried to open a session, so the
				// cancellation must not be reported as an open failure.
				if containsWarning(report.Warnings, endpoint+" could not open a session") {
					t.Fatalf("%s reports the cancellation as an open failure: %v", id, report.Warnings)
				}
			}
			for id := range prepared {
				if !tc.started[id] && id != tc.racy {
					t.Fatalf("%s was prepared after the interrupt", id)
				}
			}
			// The DoH group starts after the interrupt, so it is never started:
			// no session opens and no progress event claims it ran.
			if progressed[catalog.DoH] {
				t.Fatal("a group the interrupt arrived before reported progress")
			}
			rankedProtocols := make(map[catalog.Protocol]int)
			for _, ranking := range report.Rankings {
				rankedProtocols[ranking.Protocol]++
			}
			if tc.finished == "" && len(report.Rankings) != 0 {
				t.Fatalf("rankings = %#v, want none when no group finished", report.Rankings)
			}
			if tc.finished != "" && (len(rankedProtocols) != 1 || rankedProtocols[tc.finished] != 2) {
				t.Fatalf("rankings = %#v, want both %s targets ranked and nothing else", report.Rankings, tc.finished)
			}
		})
	}
}

func fixtureTarget(id, address, policy string) catalog.Target {
	return catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "fixture-" + id, Name: "Fixture " + id, Owner: "fixture", Policy: policy},
		Protocol: catalog.UDP,
		Address:  address,
		Spec:     catalog.TransportSpec{Port: 53},
	}
}

func fixtureSession(target catalog.Target) transport.Session {
	return &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		if target.Resolver.ID == "fixture-flaky" {
			switch name {
			case "servfail.example":
				message := replyFor(name, qtype)
				message.Rcode = dns.RcodeServerFailure
				return message, nil
			case "truncated.example":
				message := replyFor(name, qtype)
				message.Truncated = true
				return message, nil
			case "lost.example":
				return nil, errors.New("fixture packet loss")
			}
		}
		if target.Resolver.ID == "fixture-outlier" && name == "divergent.example" {
			message := replyFor(name, qtype)
			message.Rcode = dns.RcodeNameError
			return message, nil
		}
		if target.Resolver.ID == "fixture-protected" && name == "filtered.example" {
			message := replyFor(name, qtype)
			message.Rcode = dns.RcodeNameError
			return message, nil
		}
		return fixtureAnswer(name, qtype), nil
	}}
}

func fixtureAnswer(name string, qtype uint16) *dns.Msg {
	message := replyFor(name, qtype)
	if qtype == dns.TypeA {
		message.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		}}
	}
	return message
}

func fixtureObservation(result TargetResult, name string) (Observation, bool) {
	for _, observation := range result.Observations {
		if observation.Name == name {
			return observation, true
		}
	}
	return Observation{}, false
}

func fixtureHasDivergence(report Report, name, policy string) bool {
	for _, detail := range report.Divergence {
		if detail.Name == name && detail.Policy == policy {
			return true
		}
	}
	return false
}
