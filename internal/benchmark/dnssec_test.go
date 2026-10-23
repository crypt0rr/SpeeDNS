package benchmark

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/miekg/dns"
)

// dnssecReply builds an offline resolver answer. The probe names are never
// sent to the network in tests; every response below is synthesised locally.
func dnssecReply(name string, qtype uint16, rcode int, answers int, authenticated bool) *dns.Msg {
	message := replyFor(name, qtype)
	message.Rcode = rcode
	message.AuthenticatedData = authenticated
	for index := 0; index < answers; index++ {
		message.Answer = append(message.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		})
	}
	return message
}

// validatingSession answers like a resolver that validates DNSSEC: the signed
// control name resolves with AD, the deliberately bogus name is refused.
func validatingSession() *fakeSession {
	return &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		switch name {
		case DNSSECProbeSignedName:
			return dnssecReply(name, qtype, dns.RcodeSuccess, 1, true), nil
		case DNSSECProbeBogusName:
			return dnssecReply(name, qtype, dns.RcodeServerFailure, 0, false), nil
		default:
			return dnssecReply(name, qtype, dns.RcodeSuccess, 1, true), nil
		}
	}}
}

func dnssecFactory(session transport.Session) transport.Factory {
	return &fakeFactory{opens: []fakeOpen{
		{session: &fakeSession{}}, {session: &fakeSession{}}, {session: &fakeSession{}}, {session: session},
	}}
}

func TestDNSSECRunSetsDOBitAndReportsValidatingVerdict(t *testing.T) {
	oldFactory, oldTarget := newFactory, runTargetFunc
	t.Cleanup(func() {
		newFactory = oldFactory
		runTargetFunc = oldTarget
	})
	runTargetFunc = runTarget
	requested := false
	newFactory = func(_ catalog.Target, _ time.Duration, options transport.QueryOptions) (transport.Factory, error) {
		requested = options.DNSSEC
		return dnssecFactory(validatingSession()), nil
	}
	opts := validBenchmarkOptions()
	opts.DNSSEC = true
	report, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "one")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !requested {
		t.Fatal("a --dnssec run did not ask the transport for the DO bit")
	}
	result := report.Targets[0]
	if result.DNSSEC == nil {
		t.Fatal("DNSSEC assessment missing")
	}
	if result.DNSSEC.Verdict != DNSSECValidating {
		t.Fatalf("verdict = %q (%s), want %q", result.DNSSEC.Verdict, result.DNSSEC.Reason, DNSSECValidating)
	}
	if len(result.DNSSEC.Probes) != 2 || result.DNSSEC.Probes[0].Role != DNSSECRoleSigned || result.DNSSEC.Probes[1].Role != DNSSECRoleBogus {
		t.Fatalf("probes = %+v", result.DNSSEC.Probes)
	}
	if !result.DNSSEC.Probes[0].AuthenticatedData || result.DNSSEC.Probes[0].ResponseCode != "NOERROR" {
		t.Fatalf("signed probe = %+v", result.DNSSEC.Probes[0])
	}
	if result.DNSSEC.Probes[1].ResponseCode != "SERVFAIL" || result.DNSSEC.Probes[1].Answers != 0 {
		t.Fatalf("bogus probe = %+v", result.DNSSEC.Probes[1])
	}
	for _, observation := range result.Observations {
		if observation.Name == DNSSECProbeSignedName || observation.Name == DNSSECProbeBogusName {
			t.Fatalf("probe query %q entered the measured samples", observation.Name)
		}
		if !observation.AuthenticatedData {
			t.Fatalf("observation %+v did not record the AD flag", observation)
		}
		if observation.CheckingDisabled {
			t.Fatalf("observation %+v recorded an unexpected CD flag", observation)
		}
	}
}

func TestDefaultRunDoesNotProbeDNSSEC(t *testing.T) {
	oldFactory, oldTarget := newFactory, runTargetFunc
	t.Cleanup(func() {
		newFactory = oldFactory
		runTargetFunc = oldTarget
	})
	runTargetFunc = runTarget
	probed := false
	newFactory = func(_ catalog.Target, _ time.Duration, options transport.QueryOptions) (transport.Factory, error) {
		if options.DNSSEC {
			t.Error("default run requested the DO bit")
		}
		session := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			if name == DNSSECProbeSignedName || name == DNSSECProbeBogusName {
				probed = true
			}
			return replyFor(name, qtype), nil
		}}
		return dnssecFactory(session), nil
	}
	report, err := Run(context.Background(), []catalog.Target{testTarget(catalog.UDP, "one")}, validBenchmarkOptions())
	if err != nil {
		t.Fatal(err)
	}
	if probed {
		t.Fatal("default run contacted a DNSSEC probe name")
	}
	if report.Targets[0].DNSSEC != nil {
		t.Fatalf("default run produced a DNSSEC assessment: %+v", report.Targets[0].DNSSEC)
	}
}

func TestDNSSECProbeUsesConfiguredNamesAndDetectsNonValidation(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return dnssecFactory(&fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return dnssecReply(name, qtype, dns.RcodeSuccess, 1, false), nil
		}}), nil
	}
	opts := validBenchmarkOptions()
	opts.DNSSEC = true
	opts.DNSSECProbe = DNSSECProbeNames{Signed: "signed.test.invalid", Bogus: "bogus.test.invalid"}
	result := runTarget(context.Background(), testTarget(catalog.UDP, "one"), []Query{{Name: "example.com", QType: dns.TypeA}}, opts)
	if result.DNSSEC == nil || result.DNSSEC.Verdict != DNSSECNotValidating {
		t.Fatalf("assessment = %+v, want %q", result.DNSSEC, DNSSECNotValidating)
	}
	if result.DNSSEC.Probes[0].Name != "signed.test.invalid" || result.DNSSEC.Probes[1].Name != "bogus.test.invalid" {
		t.Fatalf("probe names = %+v, want the configured overrides", result.DNSSEC.Probes)
	}
}

func TestDNSSECProbeRecordsTransportFailures(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return dnssecFactory(&fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			switch name {
			case DNSSECProbeSignedName:
				return nil, nil
			case DNSSECProbeBogusName:
				return nil, errors.New("probe timed out")
			default:
				return replyFor(name, qtype), nil
			}
		}}), nil
	}
	opts := validBenchmarkOptions()
	opts.DNSSEC = true
	result := runTarget(context.Background(), testTarget(catalog.UDP, "one"), []Query{{Name: "example.com", QType: dns.TypeA}}, opts)
	if result.DNSSEC == nil || result.DNSSEC.Verdict != DNSSECInconclusive {
		t.Fatalf("assessment = %+v, want %q", result.DNSSEC, DNSSECInconclusive)
	}
	if !strings.Contains(result.DNSSEC.Reason, "probe timed out") {
		t.Fatalf("reason = %q, want the transport error", result.DNSSEC.Reason)
	}
	if result.DNSSEC.Probes[0].Success || result.DNSSEC.Probes[0].Error != "empty DNS response" {
		t.Fatalf("signed probe = %+v, want an empty-response failure", result.DNSSEC.Probes[0])
	}
}

func TestDNSSECProbeIsSkippedForUnpreparedTargets(t *testing.T) {
	runner := &targetRunner{opts: Options{DNSSEC: true, Timeout: time.Second}}
	runner.probeDNSSEC(context.Background())
	if runner.result.DNSSEC != nil {
		t.Fatalf("assessment = %+v, want none for a target without a session", runner.result.DNSSEC)
	}
}

func TestDNSSECProbeNamesFallBackToPinnedDefaults(t *testing.T) {
	names := DNSSECProbeNames{}.withDefaults()
	if names.Signed != DNSSECProbeSignedName || names.Bogus != DNSSECProbeBogusName {
		t.Fatalf("defaults = %+v", names)
	}
	custom := DNSSECProbeNames{Signed: "a.invalid", Bogus: "b.invalid"}.withDefaults()
	if custom.Signed != "a.invalid" || custom.Bogus != "b.invalid" {
		t.Fatalf("overrides = %+v", custom)
	}
}

func TestAssessDNSSECIsConservative(t *testing.T) {
	probe := func(role string, success bool, rcode, answers int) DNSSECProbe {
		return DNSSECProbe{
			Role: role, Name: role + ".invalid", Success: success, RCode: rcode,
			ResponseCode: transport.ResponseCodeName(rcode), Answers: answers,
		}
	}
	signedOK := probe(DNSSECRoleSigned, true, dns.RcodeSuccess, 1)
	cases := []struct {
		name        string
		signed      DNSSECProbe
		bogus       DNSSECProbe
		wantVerdict string
		wantReason  string
	}{
		{
			name: "bogus probe failed", signed: signedOK,
			bogus:       DNSSECProbe{Role: DNSSECRoleBogus, Error: "dial failed"},
			wantVerdict: DNSSECInconclusive, wantReason: "dial failed",
		},
		{
			name: "bogus probe failed without an error", signed: signedOK,
			bogus:       DNSSECProbe{Role: DNSSECRoleBogus},
			wantVerdict: DNSSECInconclusive, wantReason: "no response",
		},
		{
			name: "bogus data served", signed: signedOK,
			bogus:       probe(DNSSECRoleBogus, true, dns.RcodeSuccess, 2),
			wantVerdict: DNSSECNotValidating, wantReason: "deliberately bogus",
		},
		{
			name: "bogus probe refused", signed: signedOK,
			bogus:       probe(DNSSECRoleBogus, true, dns.RcodeRefused, 0),
			wantVerdict: DNSSECInconclusive, wantReason: "instead of SERVFAIL",
		},
		{
			name: "control probe did not resolve", signed: probe(DNSSECRoleSigned, true, dns.RcodeServerFailure, 0),
			bogus:       probe(DNSSECRoleBogus, true, dns.RcodeServerFailure, 0),
			wantVerdict: DNSSECInconclusive, wantReason: "did not resolve",
		},
		{
			name: "validating", signed: signedOK,
			bogus:       probe(DNSSECRoleBogus, true, dns.RcodeServerFailure, 0),
			wantVerdict: DNSSECValidating, wantReason: "refused with SERVFAIL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessment := assessDNSSEC(tc.signed, tc.bogus)
			if assessment.Verdict != tc.wantVerdict {
				t.Fatalf("verdict = %q (%s), want %q", assessment.Verdict, assessment.Reason, tc.wantVerdict)
			}
			if !strings.Contains(assessment.Reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to mention %q", assessment.Reason, tc.wantReason)
			}
			if len(assessment.Probes) != 2 {
				t.Fatalf("probes = %+v, want both raw outcomes", assessment.Probes)
			}
		})
	}
}

// isDNSSECProbeName reports whether a query is one of the two pinned probes.
func isDNSSECProbeName(name string) bool {
	return name == DNSSECProbeSignedName || name == DNSSECProbeBogusName
}

// TestDNSSECProbesShareTheBoundedPool pins the post-measurement probe phase
// to the --concurrency pool. The probes used to run one target at a time, so
// eight ready targets whose probes each wait out a timeout cost 8 × 2 ×
// timeout of extra wall-clock time instead of about 2 × timeout.
//
// Timing would make that a flaky assertion, so the fixture proves the
// concurrency structurally: every probe holds its worker until four probes
// are in flight at the same moment, which a serial loop can never reach. The
// guard releases everything and fails the test rather than letting it hang.
func TestDNSSECProbesShareTheBoundedPool(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	const concurrency = 4
	var inFlight, peak atomic.Int32
	allIn := make(chan struct{})
	var allInOnce sync.Once
	var mu sync.Mutex
	probes := make(map[string][]string)
	newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
		warm := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			if !isDNSSECProbeName(name) {
				return dnssecReply(name, qtype, dns.RcodeSuccess, 1, true), nil
			}
			mu.Lock()
			probes[target.ID()] = append(probes[target.ID()], name)
			mu.Unlock()
			current := inFlight.Add(1)
			for {
				seen := peak.Load()
				if current <= seen || peak.CompareAndSwap(seen, current) {
					break
				}
			}
			if current == concurrency {
				allInOnce.Do(func() { close(allIn) })
			}
			select {
			case <-allIn:
			case <-time.After(10 * time.Second):
				t.Error("DNSSEC probes never had more than one target in flight")
				allInOnce.Do(func() { close(allIn) })
			}
			inFlight.Add(-1)
			if name == DNSSECProbeBogusName {
				return dnssecReply(name, qtype, dns.RcodeServerFailure, 0, false), nil
			}
			return dnssecReply(name, qtype, dns.RcodeSuccess, 1, true), nil
		}}
		return dnssecFactory(warm), nil
	}

	targets := make([]catalog.Target, 0, 8)
	for index := 8; index >= 1; index-- {
		targets = append(targets, testTarget(catalog.UDP, fmt.Sprintf("probe-%d", index)))
	}
	var events []Progress
	report, err := Run(context.Background(), targets, Options{
		Domains: []string{"measured.example"}, QueryTypes: []uint16{dns.TypeA}, Sample: 1, Seed: 3,
		Timeout: time.Second, Concurrency: concurrency, DNSSEC: true,
		OnProgress: func(progress Progress) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, progress)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got != concurrency {
		t.Fatalf("peak probes in flight = %d, want exactly the %d-worker pool", got, concurrency)
	}

	mu.Lock()
	defer mu.Unlock()
	for index, result := range report.Targets {
		id := result.Target.ID()
		if index > 0 && report.Targets[index-1].Target.ID() >= id {
			t.Fatalf("results left target-ID order: %s after %s", id, report.Targets[index-1].Target.ID())
		}
		if got := probes[id]; len(got) != 2 || got[0] != DNSSECProbeSignedName || got[1] != DNSSECProbeBogusName {
			t.Fatalf("%s probes = %v, want signed then bogus on its own session", id, got)
		}
		if result.DNSSEC == nil || result.DNSSEC.Verdict != DNSSECValidating {
			t.Fatalf("%s assessment = %+v, want %q", id, result.DNSSEC, DNSSECValidating)
		}
		for _, observation := range result.Observations {
			if isDNSSECProbeName(observation.Name) {
				t.Fatalf("probe query %q entered %s's measured samples", observation.Name, id)
			}
		}
	}

	// The phase is visible: it opens with 0/8 after the last measured round,
	// counts every probed target, and is closed by the completion event.
	lastMeasuring, firstDNSSEC, maxProbed := -1, -1, 0
	for index, event := range events {
		switch event.Phase {
		case ProgressMeasuring:
			lastMeasuring = index
		case ProgressDNSSEC:
			if firstDNSSEC < 0 {
				firstDNSSEC = index
			}
			if event.DNSSECTotal != len(targets) || event.DNSSECCompleted > event.DNSSECTotal {
				t.Fatalf("DNSSEC progress event = %#v", event)
			}
			maxProbed = max(maxProbed, event.DNSSECCompleted)
		}
	}
	if firstDNSSEC < lastMeasuring || events[firstDNSSEC].DNSSECCompleted != 0 {
		t.Fatalf("the DNSSEC phase must open at 0 after the last measured round: %#v", events)
	}
	if maxProbed != len(targets) || events[len(events)-1].Phase != ProgressComplete {
		t.Fatalf("DNSSEC progress reached %d/%d before completion: %#v", maxProbed, len(targets), events)
	}
}

// TestDNSSECProbesStartNothingAfterCancellation covers the pool's cancel
// path. One worker takes the first target, whose signed probe is where the
// interrupt lands; the targets still queued behind it must never reach their
// sessions, and the phase must count only the target that was probed.
func TestDNSSECProbesStartNothingAfterCancellation(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	probes := make(map[string]int)
	newFactory = func(target catalog.Target, _ time.Duration, _ transport.QueryOptions) (transport.Factory, error) {
		warm := &fakeSession{query: func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
			if isDNSSECProbeName(name) {
				mu.Lock()
				probes[target.Address]++
				mu.Unlock()
				if target.Address == "1" && name == DNSSECProbeSignedName {
					cancel()
				}
			}
			return dnssecReply(name, qtype, dns.RcodeSuccess, 1, true), nil
		}}
		return dnssecFactory(warm), nil
	}

	var maxProbed int
	results := runProtocol(ctx, []catalog.Target{testTarget(catalog.UDP, "1"), testTarget(catalog.UDP, "2"), testTarget(catalog.UDP, "3")},
		[]Query{{Name: "a.example", QType: dns.TypeA}}, Options{
			QueryTypes: []uint16{dns.TypeA}, Timeout: time.Second, Concurrency: 1, DNSSEC: true,
			OnProgress: func(progress Progress) {
				if progress.Phase == ProgressDNSSEC {
					maxProbed = max(maxProbed, progress.DNSSECCompleted)
				}
			},
		})
	if probes["1"] == 0 || probes["2"] != 0 || probes["3"] != 0 {
		t.Fatalf("probes after cancellation = %v, want only the target in flight", probes)
	}
	if maxProbed != 1 {
		t.Fatalf("DNSSEC progress counted %d probed targets, want 1", maxProbed)
	}
	for _, result := range results {
		if !result.Incomplete {
			t.Fatalf("%s was not marked incomplete after the interrupt", result.Target.ID())
		}
		if result.Target.Address != "1" && result.DNSSEC != nil {
			t.Fatalf("%s gained an assessment without being probed: %+v", result.Target.ID(), result.DNSSEC)
		}
	}
}
