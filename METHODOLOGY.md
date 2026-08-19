# SpeeDNS benchmark methodology

This document describes the ranking rules used by the current SpeeDNS
benchmark. A run records its random seed and corpus size so that the query
matrix can be reproduced, subject to the normal variability of the network and
the recursive resolvers being measured.

## Query matrix and execution

The default run samples 100 distinct names from the embedded, pinned
1,000-name corpus. `--full` uses every name. Each selected name is queried for
each selected record type, normally A and AAAA. Names are normalized before
sampling, and the same shuffled matrix is given to every resolver eligible for
the same protocol.

Protocols are benchmarked separately in the order `udp`, `tcp`, `doh`, `dot`,
and `doq`. Targets are ordered by their complete target identity rather than
catalog input order. Each dispatched target is prepared once and keeps one
reusable measured session. The measured phase advances in synchronized query
rounds: every eligible target receives query `i` before any target receives
query `i+1`. At most the configured `--concurrency` number of measured DNS
exchanges are in flight at once, and a target's session is never used
concurrently. This preserves bounded active work while preventing early
catalog entries from receiving a different sequence of measurement rounds.
Preparation (cold probes and warmups) is kept separate from the measured
rounds. There is no transport fallback.

Three excluded warm-up queries are sent before the measured phase. Encrypted
and stream transports reuse their connections during measured queries. UDP
reports the DNS transaction time only.

## What is measured

Warm latency is measured from immediately before a DNS exchange until the
validated response or error returns. TCP, DoT, and any recovered stream
connection are not closed before the timer stops. A query that follows a TCP,
DoT, or DoQ reconnect is recorded as a reconnect sample and excluded from
ordinary warm-latency scoring; its reconnect count and selected dial address
remain visible in detailed output and machine-readable results. DoQ sessions
use TLS 1.3 with ALPN `doq`, an explicit keepalive period equal to the
configured timeout, and a maximum idle timeout of twice that timeout. The
failed exchange that caused the reconnect is counted once and is never
retried.

Cold probes use three separate sessions. Their timer includes session opening,
the first DNS exchange, and response validation, but stops before session
teardown. Cold medians are reported separately and never enter the warm score.

Only transport-valid DNS messages are transport successes. A response is
usable when it is a validated `NOERROR` response (including NODATA) or
`NXDOMAIN`. SERVFAIL, REFUSED, truncated messages, malformed responses,
timeouts, connection errors, and other resolver errors are not usable.

## Scoring and divergence

Lower scores are better:

```text
score_ms = 0.60 × median_ms
         + 0.40 × p95_ms
         + scoring_failure_rate × timeout_ms
```

For each name/type, SpeeDNS builds separate comparison groups for each
normalized declared resolver policy. This prevents an unfiltered resolver from
being treated as equivalent to a filtering resolver. Within a policy group,
the response class with the largest plurality is the deterministic baseline.
The classes are `answer`, `nodata`, `nxdomain`, and DNS response-code classes
such as `rcode-2` (SERVFAIL) or `rcode-5` (REFUSED). A successful observation
whose class differs from a unique plurality baseline is divergent and is
excluded from comparative latency scoring.

If two or more classes are tied for the plurality, the group is ambiguous:
there is no defensible baseline, so every successful observation in that group
is marked divergent and excluded from comparative latency scoring. SpeeDNS
does not break this tie by address, catalog order, or class name. Policy groups
with only one observed class are not divergent, even when another declared
policy group returns a different class; unlike policy profiles are not treated
as having identical behavior.

Divergent usable observations are removed from the scoring denominator.
Unusable observations are never removed this way: even when marked divergent,
they remain scoring failures and contribute to the failure penalty. This
prevents a fast SERVFAIL or REFUSED response from winning by escaping the
denominator.

The detailed table includes a divergence section showing the policy group,
selected baseline (or an ambiguous decision), response-class counts, and the
excluded target observations. Each exclusion is labeled either
`latency-excluded` for a usable outlier or `failure-penalized` for an unusable
transport-valid response. Raw JSON observations carry the selected baseline,
and the additive `divergence` report section carries the same decision details.

`SuccessRate` describes receipt of transport-valid DNS messages. `UsableRate`
describes semantic DNS usability over all measured observations.
`ScoringFailureRate` describes scoring failures over the observations eligible
for scoring after valid divergent and reconnect-only samples are excluded.
The detailed report shows the counts behind these rates.

An endpoint needs at least 20 scored samples and at least 99% usable responses
to receive `RECOMMENDED`. A result with valid samples but insufficient quality
is `INELIGIBLE`; a result with no transport-valid response is `FAILED`.
Interrupted targets are `INCOMPLETE` and are never ranked.

## Confidence intervals and ties

Confidence intervals use a deterministic bootstrap seeded from the run seed
and the complete target identity, not from a target-ID length or process-wide
random state. Each bootstrap replicate resamples the complete scoring outcome
vector: successful latency observations and scoring failures. This means the
uncertainty of the failure penalty is represented as well as latency
uncertainty.

Rank order is deterministic: score first, then target ID. A target is in the
leader's tie group when its 95% bootstrap interval overlaps the leader's
interval. The leader is marked as tied too, so the tie is visible from either
row.

## Interruption and diagnostics

Cancellation never creates synthetic observations for queries that were not
completed. A dispatched target may retain the observations completed before
cancellation, but it is marked `INCOMPLETE`, excluded from rankings, and
reported with its cancellation diagnostic. Targets that were never dispatched
do not appear in the report.

JSON contains the structured result and optional raw observations. CSV keeps
the aggregate schema and adds reconnect/incomplete diagnostics at the end.
CSV cells beginning with `=`, `+`, `-`, `@`, tab, or carriage return are
prefixed with an apostrophe to prevent spreadsheet formula interpretation.
For encrypted targets, these reports also expose the effective TLS server
name, whether it was configured explicitly or derived from the endpoint,
whether bootstrap came from explicit IP candidates, the target address, or
the system resolver, and the selected dial address when a connection opened.
An explicit `server_name` is the only way to opt into a different TLS identity;
`bootstrap_addresses` only changes connection candidates and never disables
certificate validation.

## Reproducibility limits

The seed reproduces the selected names and query order, not Internet timing.
Resolver anycast routing, cache state, rate limiting, local contention,
packet loss, and policy changes can alter results. Filtering, protective, and
unfiltered resolvers may intentionally return different response classes; the
policy is shown beside every target and those differences should be considered
when interpreting a winner.

The embedded corpus is pinned and never downloaded at runtime. Its source,
Tranco list ID, retrieval date, entry count, and SHA-256 checksum are stored in
`data/domains.meta.json`.
