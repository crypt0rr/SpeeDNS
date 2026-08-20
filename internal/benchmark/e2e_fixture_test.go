package benchmark

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/miekg/dns"
)

func TestDeterministicResolverFixtureCoversBenchmarkOutcomes(t *testing.T) {
	oldFactory := newFactory
	oldTarget := runTargetFunc
	t.Cleanup(func() {
		newFactory = oldFactory
		runTargetFunc = oldTarget
	})
	runTargetFunc = runTarget

	newFactory = func(target catalog.Target, _ time.Duration) (transport.Factory, error) {
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
