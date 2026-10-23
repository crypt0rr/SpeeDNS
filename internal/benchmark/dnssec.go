package benchmark

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/miekg/dns"
)

// The DNSSEC probe uses exactly two pinned public test names. To use different
// vectors, change these two constants (or set Options.DNSSECProbe); nothing
// else in the probe depends on the specific names.
const (
	// DNSSECProbeSignedName is a correctly signed name from the DNSSEC-Tools
	// test zone. Every resolver, validating or not, must answer it with
	// NOERROR and at least one address record, so it is the control probe: if
	// it does not resolve, the resolver is unreachable, filtering, or broken
	// and the bogus probe cannot be interpreted on its own.
	DNSSECProbeSignedName = "good-a.test.dnssec-tools.org"
	// DNSSECProbeBogusName is a deliberately mis-signed public test zone. A
	// resolver that validates DNSSEC must fail closed and answer SERVFAIL; a
	// resolver that does not validate returns the unverifiable address record.
	DNSSECProbeBogusName = "dnssec-failed.org"
)

// dnssecProbeQType keeps both probes on the same record type so the two
// outcomes are comparable. Both pinned names publish address records.
const dnssecProbeQType = dns.TypeA

// Probe roles as reported in JSON and in the table output.
const (
	DNSSECRoleSigned = "signed"
	DNSSECRoleBogus  = "bogus"
)

// Per-target DNSSEC verdicts. The verdict describes what the resolver did for
// these two names at this moment; it is not an audit of the resolver.
const (
	DNSSECValidating    = "validating"
	DNSSECNotValidating = "not-validating"
	DNSSECInconclusive  = "inconclusive"
)

// DNSSECProbeNames selects the pinned probe names for one run. An empty field
// falls back to the corresponding default constant.
type DNSSECProbeNames struct {
	Signed string
	Bogus  string
}

func (names DNSSECProbeNames) withDefaults() DNSSECProbeNames {
	if names.Signed == "" {
		names.Signed = DNSSECProbeSignedName
	}
	if names.Bogus == "" {
		names.Bogus = DNSSECProbeBogusName
	}
	return names
}

// DNSSECProbe is the raw outcome of one probe query. The flags and response
// code are recorded exactly as received so a reader can reach their own
// conclusion without trusting the summary verdict.
type DNSSECProbe struct {
	Role              string  `json:"role"`
	Name              string  `json:"name"`
	QType             uint16  `json:"qtype"`
	LatencyMS         float64 `json:"latency_ms,omitempty"`
	Success           bool    `json:"success"`
	RCode             int     `json:"rcode,omitempty"`
	ResponseCode      string  `json:"response_code,omitempty"`
	Answers           int     `json:"answers"`
	AuthenticatedData bool    `json:"authenticated_data,omitempty"`
	CheckingDisabled  bool    `json:"checking_disabled,omitempty"`
	Error             string  `json:"error,omitempty"`
}

// DNSSECAssessment is the per-target result of the opt-in probe.
type DNSSECAssessment struct {
	Verdict string        `json:"verdict"`
	Reason  string        `json:"reason"`
	Probes  []DNSSECProbe `json:"probes,omitempty"`
}

// probeDNSSECTargets probes every ready runner through at most concurrency
// workers and calls probed with the running count after each target.
//
// The probes used to run one target at a time. Each probe can take a full
// timeout, and every target that answered its warm-ups is probed -- including
// one whose warm-ups all timed out -- so a phase that ignored the pool cost up
// to ready × 2 × timeout of wall-clock time with nothing on the progress line.
// Each runner is still taken by exactly one worker and its two probes stay
// sequential on its own session, because a session is never used
// concurrently. Every outcome lands in that runner's own result, so the
// report keeps target-ID order no matter which probe finishes first.
func probeDNSSECTargets(ctx context.Context, runners []*targetRunner, concurrency int, probed func(int)) {
	// Queue every runner up front: a worker that finds the run cancelled gets
	// false from probeDNSSEC, so no probe is sent after an interrupt and the
	// dispatcher never has to race a cancellation against a send.
	jobs := make(chan *targetRunner, len(runners))
	for _, runner := range runners {
		jobs <- runner
	}
	close(jobs)
	var completed atomic.Int32
	var wg sync.WaitGroup
	workers := max(1, min(concurrency, len(runners)))
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for runner := range jobs {
				if runner.probeDNSSEC(ctx) {
					probed(int(completed.Add(1)))
				}
			}
		}()
	}
	wg.Wait()
}

// probeDNSSEC runs the pinned probes on the already warmed session, after all
// measured rounds for the target, so it can never influence latency samples.
// The probe names are never added to the measured query matrix. It reports
// whether both probes ran.
func (runner *targetRunner) probeDNSSEC(ctx context.Context) bool {
	if !runner.opts.DNSSEC || !runner.ready || runner.session == nil || ctx.Err() != nil {
		return false
	}
	names := runner.opts.DNSSECProbe.withDefaults()
	signed := runner.dnssecProbe(ctx, DNSSECRoleSigned, names.Signed)
	// An interrupt during the signed probe must not start the bogus one. Its
	// cancelled context would fail at once, and the verdict would then call
	// the resolver inconclusive over a probe the operator cut short. The
	// target is left without a verdict, like every target the pool had not
	// reached yet, and is marked incomplete with them.
	if ctx.Err() != nil {
		return false
	}
	bogus := runner.dnssecProbe(ctx, DNSSECRoleBogus, names.Bogus)
	assessment := assessDNSSEC(signed, bogus)
	runner.result.DNSSEC = &assessment
	return true
}

func (runner *targetRunner) dnssecProbe(ctx context.Context, role, name string) DNSSECProbe {
	probe := DNSSECProbe{Role: role, Name: name, QType: dnssecProbeQType}
	started := time.Now()
	queryCtx, cancel := context.WithTimeout(ctx, runner.opts.Timeout)
	message, err := runner.session.Query(queryCtx, name, dnssecProbeQType)
	cancel()
	probe.LatencyMS = durationMS(time.Since(started))
	switch {
	case err != nil:
		probe.Error = err.Error()
	case message == nil:
		probe.Error = "empty DNS response"
	default:
		probe.Success = true
		probe.RCode = message.Rcode
		probe.ResponseCode = transport.ResponseCodeName(message.Rcode)
		probe.Answers = len(message.Answer)
		probe.AuthenticatedData = message.AuthenticatedData
		probe.CheckingDisabled = message.CheckingDisabled
	}
	return probe
}

// assessDNSSEC is deliberately conservative. Only two outcomes are treated as
// evidence: serving an answer for the bogus name proves the resolver did not
// fail closed, and refusing the bogus name with SERVFAIL while the signed
// control still resolves is the expected behaviour of a validating resolver.
// Everything else is inconclusive, because a SERVFAIL can also come from an
// unrelated outage, a blocklist, or a forwarder that never saw the query.
//
// The AD flag is reported per probe but is not required for the verdict: some
// forwarders clear AD on responses they relay even though the upstream
// validated the data.
func assessDNSSEC(signed, bogus DNSSECProbe) DNSSECAssessment {
	assessment := DNSSECAssessment{Probes: []DNSSECProbe{signed, bogus}}
	switch {
	case !bogus.Success:
		assessment.Verdict = DNSSECInconclusive
		assessment.Reason = "the bogus probe did not complete: " + probeFailureReason(bogus)
	case bogus.RCode == dns.RcodeSuccess && bogus.Answers > 0:
		assessment.Verdict = DNSSECNotValidating
		assessment.Reason = "the resolver returned answers for the deliberately bogus name " + bogus.Name
	case bogus.RCode != dns.RcodeServerFailure:
		assessment.Verdict = DNSSECInconclusive
		assessment.Reason = "the bogus probe returned " + bogus.ResponseCode + " instead of SERVFAIL or an answer"
	case !signed.Success || signed.RCode != dns.RcodeSuccess || signed.Answers == 0:
		assessment.Verdict = DNSSECInconclusive
		assessment.Reason = "the bogus probe was refused, but the signed control probe " + signed.Name + " did not resolve"
	default:
		assessment.Verdict = DNSSECValidating
		assessment.Reason = "the signed control probe resolved and the bogus probe was refused with SERVFAIL"
	}
	return assessment
}

func probeFailureReason(probe DNSSECProbe) string {
	if probe.Error == "" {
		return "no response"
	}
	return probe.Error
}
