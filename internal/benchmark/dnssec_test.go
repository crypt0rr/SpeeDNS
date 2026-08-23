package benchmark

import (
	"context"
	"errors"
	"strings"
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
