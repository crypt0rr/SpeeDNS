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
rounds. Preparation itself also runs with at most `--concurrency` targets in
flight, and a single target is always prepared by one worker so its session is
never used concurrently. Preparing targets one after another would have made a
target's cold probes start systematically later, and left its warm session
idle for longer, the further down the ordered catalog it sat; bounded parallel
preparation shrinks that positional bias by the concurrency factor. Results
and rankings stay in target-identity order regardless of which preparation
finished first. There is no transport fallback.

Three excluded warm-up queries are sent before the measured phase. Encrypted
and stream transports reuse their connections during measured queries. UDP
reports the DNS transaction time only.

A default run sends roughly 8,650 DNS queries: about 206 per resolver/transport
target, being 3 cold probes, 3 warm-ups and 200 measured exchanges, over the ten
bundled profiles and the transports they declare. The load is not even. Four of
the ten bundled profiles are DNS4EU addresses, so the smallest of the four
operators receives roughly 38% of the total. `CACHE_MISS.md` states the
separate reserved-zone budget for `--cache-miss`, which is 200 queries.

Each target also records how many of its usable responses carried an actual
record rather than NODATA, published as `answers` and `answer_rate`. NODATA is
usable and is scored, so without this a resolver answering every query with an
empty answer section is indistinguishable from a working one on the success and
usable columns. It is disclosed and never penalised: on the default `A,AAAA`
corpus a real resolver returns a record only about 45% of the time, so an
absolute threshold would produce false accusations.

## What is measured

Warm latency is measured from immediately before a DNS exchange until the
validated response or error returns. Per-query deadline setup and post-exchange
bookkeeping, such as the reconnect check, fall outside the timed section. TCP,
DoT, and any recovered stream
connection are not closed before the timer stops. A query that follows a TCP,
DoT, DoH, or DoQ reconnect is recorded as a reconnect sample and excluded from
ordinary warm-latency scoring; its reconnect count and selected dial address
remain visible in detailed output and machine-readable results. A DoH session
reuses one pooled HTTPS connection; when that connection is gone, the HTTP
client opens a new one transparently, so the query that pays for the new TCP,
TLS, and HTTP handshake is the reconnect sample. The connection the session
opens for its first exchange is the DoH equivalent of the dial the stream
transports perform when the session is opened, and is not a reconnect. DoQ
sessions use TLS 1.3 with ALPN `doq`, an explicit keepalive period equal to
the configured timeout, and a maximum idle timeout of twice that timeout. The
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

A response is classified `answer` only when its answer section carries a record
of the queried type. A NOERROR response without one is `nodata`, including the
canonical form that carries an SOA in the authority section. Authority records
are never read as an answer: doing so would make "this name has no such record"
indistinguishable from "here is the address", which is the most common genuine
difference between resolvers on the default `A,AAAA` query set.

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

A resolver that runs on the local host, such as a loopback stub or forwarder,
is measured and reported but is never ranked and never recommended. "On the
local host" means a loopback address or any address the measuring machine
itself holds on an up interface, and the classification is applied to every
resolver the run selects -- bundled, `--resolver`, `--resolver-file` and
discovered alike -- rather than only to discovered ones. It answers
from its own cache, so the measurement is cache-hit latency and excludes the
upstream resolution it forwards to; comparing it with a resolver reached over
the network would compare two different quantities. Such a target is
`NOT COMPARABLE`, has no rank, and carries a permanent warning naming that
reason.

A resolver reached over the local network but not on the measuring host -- an
RFC 1918, CGNAT, link-local or unique-local address -- is treated differently
and deliberately more weakly. It is still ranked, because SpeeDNS cannot tell a
caching forwarder from a self-hosted recursive resolver and refusing to rank one
would penalise a legitimate setup. The report warns that its latency may exclude
the upstream resolution it is being compared against, so the reader can apply
the judgement the tool cannot. Under `--redact-system` the count is disclosed
without the address.

The local-host classification comes from the address inventory, not from the
resolver file format, so it cannot be asserted by a catalog. JSON reports it
in the additive `local` field on the target and CSV in a trailing `local`
column, so a consumer can tell a missing rank caused by non-comparability
apart from one caused by a failure.

Targets whose 95% score confidence intervals overlap are ordered among
themselves by median latency rather than by score. The score is 60% median and
40% p95, and p95 is by far the less stable half: over the same observations the
median interval is 9-14% of its point estimate while the p95 interval is
66-143%. Ordering indistinguishable targets by score therefore made the
presented order a function of run-to-run noise -- four runs of one command at
one seed produced three different orders, and the target with the worst median
in every run took rank one twice. Using the median settles that order with the
most stable statistic available. No measured value changes, and targets whose
intervals do not overlap are still ranked by score.

## Confidence intervals and ties

Confidence intervals use a deterministic bootstrap seeded from the run seed
and the complete target identity, not from a target-ID length or process-wide
random state. Each bootstrap replicate resamples the complete scoring outcome
vector: successful latency observations and scoring failures. This means the
uncertainty of the failure penalty is represented as well as latency
uncertainty. A replicate that happens to draw only failures has no latency
term, so it scores the timeout penalty itself, exactly as the score function
would for a failure rate of 1. No out-of-range sentinel is used, because a
replicate score the score function cannot produce would inflate the reported
upper bound and change which targets are reported as tied.

Rank order is deterministic: score first, then target ID. A target is in the
leader's tie group when its 95% bootstrap interval overlaps the leader's
interval. The leader is marked as tied too, so the tie is visible from either
row.

Every output surfaces that flag. The human table has a `Tie` column in the
recommendation summary and in each per-protocol comparison; a tied row reads
`TIED`, an untied row reads `—`. When a recommended or provisional winner is
tied, the recommendation block also carries a `TIED:` note stating that the
ordering is not statistically distinguishable, so a rank-one row is never
presented as an unqualified winner. CSV keeps its `tie` column and JSON keeps
`tie` on both `rankings[]` and `results[].stats`. The strict `1..N` rank is
still reported: a tie qualifies the ordering, it does not remove it.

The report also includes paired latency effects. For each protocol, the
best-ranked target of that protocol is the reference, and each other target is
paired with it by normalized query name and record type. Only usable,
non-divergent observations that were not recorded immediately after a reconnect
are included, and a pair is formed only where both resolvers returned the same
response class.

The grouping used to include the resolver's declared policy. That string is
free text, and in practice most groups had one member -- five of the ten
bundled profiles sit alone in their policy string, as does every `--resolver`
endpoint and every discovered system resolver -- so most targets could only be
compared with themselves. Since the rankings these effects exist to explain are
scoped to a protocol, the comparisons now share that scope.

The response-class requirement is what the policy grouping was really for. A
filtering resolver that sinkholes a name answers from its own blocklist while
the reference performs a real recursion, and comparing those two measures the
filtering policy rather than the resolver's speed. Requiring a matching class
removes exactly those pairs, one observation at a time, without requiring every
resolver in a comparison to declare the same policy string. Divergence
detection is unchanged and still groups by declared policy, where a fine
grouping is correct: two resolvers with different filtering policies are
*expected* to return different answers, and treating that as divergence would
be a false positive.

Resolvers on the local host are excluded from paired effects entirely. They are
never ranked, and pairing one against the protocol winner would present a
cache-hit latency as though it were comparable. The reported delta is the
median of `target latency - reference latency`, so a positive value means the
target was slower. A deterministic bootstrap of those paired deltas provides
the 95% confidence interval. When the interval contains zero, the report says
`NO CLEAR DIFFERENCE`: the observed ranking difference is not distinguishable
from noise in this run. These effects explain the existing score and never
change ranking order.

A paired comparison requires at least 20 paired observations, the same minimum
sample count the recommendation gate uses. Below that floor no delta and no
interval are reported: the effect keeps its paired sample count, records the
reason `insufficient paired samples`, and the report says `NOT COMPARABLE`. The
reason is a fixed phrase rather than one naming the current threshold, so a
consumer matching on it does not break when the threshold changes; the sample
count is in the same record.

A target that is the only measured member of its protocol has no peer to be
paired against, so it is its own reference and its row carries no information.
The human table omits those rows and reports how many were omitted; `--details`
and the `paired_effects` JSON section keep every entry, so the detailed view
remains a complete record of what was measured. A one-sample or few-sample run
measures cold-path noise, so it must not be presented as a directional `FASTER`
or `SLOWER` verdict under a 95% confidence interval heading. JSON exposes these
effects in the additive `paired_effects` section; the human table shows them
below the protocol comparisons, while CSV retains its aggregate
one-row-per-target schema.

## Interruption and diagnostics

Cancellation never creates synthetic observations for queries that were not
completed. A target that was handed to a worker may retain the observations it
completed before cancellation, but it is marked `INCOMPLETE`, excluded from
rankings, and reported with its cancellation diagnostic. Only a target that was
never handed to a worker is absent from the report.

In practice that means an interrupted run lists every selected target. Targets
are prepared concurrently, so all of them normally reach a worker within the
first moments of a run, and an interrupt has to arrive before preparation
begins for any of them to be missing. An interrupted report is therefore the
full comparison set with every entry marked `INCOMPLETE`, not a shortened
list.

JSON contains the structured result and optional raw observations. CSV keeps
the aggregate schema and adds reconnect/incomplete diagnostics at the end.
Text that SpeeDNS did not produce itself is escaped before it reaches a
terminal or a CSV cell. Session errors quote strings chosen by the endpoint,
such as the certificate names in an `x509` hostname mismatch, and resolver
names, owners, and policies arrive from `--resolver`, `--resolver-file`, or
the system resolver configuration; control characters in any of them are
rendered as visible `\x1b`-style sequences, so neither a certificate field nor
a configured name can rewrite the terminal. The status colours are the only
escape sequences the table emits itself. CSV cells are escaped first and the
formula guard runs afterwards on the escaped value: a cell beginning with
`=`, `+`, `-`, `@`, or an escape sequence - which is how a leading tab,
carriage return, or ESC is rendered - is prefixed with an apostrophe to
prevent spreadsheet formula interpretation.
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

## Cache-miss mode and profile view

The normal run uses the embedded corpus and is treated as the warm-cache
population. The opt-in `--cache-miss` mode instead generates a bounded set of
unique labels below the IANA-reserved `example.com` zone. It allows at most 20
names and two measured exchanges in flight, records a per-run random nonce,
and rejects custom domain files and `--full`. `--sample` still selects the
measured names from that generated corpus, so a `--sample` below
`--cache-miss-sample` measures only part of it and the run reports a warning
naming both sizes; `run.provenance.corpus_entries` and `corpus_sha256` keep
describing the corpus the run drew from, as they do for warm-cache runs, while
`sample_size` reports how many names were measured. The generated population is
never appended to the normal corpus, and its results must not be interpreted
as a warm-cache ranking. The ownership, traffic limits, and intended use are
documented in [`CACHE_MISS.md`](CACHE_MISS.md).

A resolver holds one cache, shared across every transport it offers and every
address it answers on, so any second lookup of a generated name at that
resolver is a warm read. Cache-miss mode therefore measures each resolver
exactly once — keeping its earliest declared transport at its lowest-sorting
address, and naming the dropped endpoints in a warning — and asks each
generated name exactly one question, rotating the selected query types across
the corpus rather than pairing them per name. A resolver caches an NXDOMAIN for
the name rather than for the query type, so asking one name for both `A` and
`AAAA` measured a miss and then a cache hit. Both rules together are what make
every measured cache-miss query a genuine miss; the cost is that a cache-miss
run cannot compare transports, because doing so requires measuring one name
twice at one resolver.

`--profile-view` groups the measured target rows by resolver profile and
address, then lists each available selected transport side by side in a
stable order. It reuses each transport's existing median, p95, cold median,
score, and deterministic score confidence interval. Missing transport
combinations are shown as unavailable in the table; profile view is a view of
the same run, not a new cross-transport ranking and not a replacement for the
per-protocol score.

## DNSSEC probing

`--dnssec` is opt-in and changes the run in two ways. Every query of the run
carries the EDNS(0) DO bit, and each prepared target answers two extra queries
after all of its measured rounds have finished. The CD (checking disabled) bit
is never set, because the point of the probe is to observe validation rather
than to suppress it.

The two probe names are pinned constants in `internal/benchmark/dnssec.go`:

- `good-a.test.dnssec-tools.org` is a correctly signed control name. Every
  resolver must answer it with NOERROR and at least one address record.
- `dnssec-failed.org` is a deliberately mis-signed public test zone. A
  resolver that validates DNSSEC must fail closed and answer SERVFAIL; a
  resolver that does not validate returns the unverifiable address record.

Changing the vectors is a two-line edit of those constants; the probe logic
does not depend on the specific names.

The per-target verdict is deliberately narrow:

- `validating` means the control name resolved and the bogus name was refused
  with SERVFAIL.
- `not-validating` means the resolver returned answers for the bogus name, so
  it did not fail closed.
- `inconclusive` covers everything else, including a probe that did not
  complete, a bogus response that was neither SERVFAIL nor an answer, and a
  SERVFAIL for the bogus name while the signed control also failed to resolve.

The AD (authentic data) and CD flags are recorded per measured observation and
per probe, and are reported as raw evidence. AD is not required for the
`validating` verdict, because forwarders may clear AD on responses they relay
even when the upstream validated the data.

This probe shows what a resolver did for these two names at this moment from
this network path. It is not a DNSSEC audit: it does not cover algorithm
support, negative-answer validation, NSEC/NSEC3 handling, key rollovers, or
any other name. A SERVFAIL can also be produced by an outage, a blocklist, or
a forwarder that never reached the authoritative servers, which is why those
cases stay inconclusive.

The probe never touches ranking, scoring, or divergence. Its queries are run
on the already warm session after the measured rounds, are not part of the
query matrix, and never enter the latency samples. A default run without
`--dnssec` sends byte-identical queries to earlier releases and produces no
probe traffic, so default results stay comparable with published reports.

## Assertions

The repeatable `--assert` option provides a small automation gate without
changing JSON or CSV schemas. `usable` and `success` compare rates between 0
and 1. `median`, `p95`, and `score` compare milliseconds; a bare number means
milliseconds and Go-style duration suffixes such as `50ms` or `1.5s` are
accepted. All support `>=`, `>`, `<=`, `<`, and `=`.

A protocol whose endpoints all returned no usable DNS response fails every
assertion of the run. Without that rule a transport failing outright is a
quieter result than one merely degrading: assertions are evaluated per ranked
protocol, and a dead transport produces no ranking, so nothing was ever
checked for it. Two cases are deliberately exempt. A protocol that no selected
resolver declares is never required, so the default `udp,tcp,doh,dot,doq`
selection does not demand five transports of a single-resolver run. A resolver
on the local host does not make its protocol required either, because it is
measured but never ranked.

The test is "returned no usable response", not "produced no ranking". A
resolver that answers every query but reconnects for each one has all of its
samples excluded from warm-latency scoring, so it is unranked while being
entirely healthy; requiring a ranking would fail that run.

An assertion prefixed with `SUBJECT:` is evaluated against every measured
endpoint of the named resolver instead of against the winners. That is a
deliberately different question: an unqualified assertion asks whether the best
resolver is good enough, while a subject-qualified one asks whether a specific
resolver still meets a bar, which is what a monitoring gate usually means. All
of the subject's endpoints are checked rather than its best, so a resolver
degrading on one transport cannot pass on the strength of another. A subject
that matches no measured endpoint fails rather than passing silently, and the
name is validated against the selected resolvers before any query is sent.

Unqualified numeric assertions are evaluated against the rank-one target of
every protocol that produced a ranking -- one target per protocol, chosen deterministically.
Confidence-interval tie-group members are deliberately not included: tie
membership depends on bootstrap interval overlap, so it moves with sample size
and network noise, and a threshold applied to the whole group would pass or
fail the same command on identical infrastructure.

`winner=PROFILE-ID` or `winner=TARGET-ID` is a different question and keeps the
wider set: it requires the requested profile or target to be among the rank-one
winners for every such protocol, and confidence-interval ties count as winner
membership, because a tie means the run cannot say the resolver did not win. The requested winner is checked against the
targets selected for the run before any query is sent, so an ID that no
selected profile or target carries is invalid input (status 2) rather than a
lost comparison; a benchmark never reports that a resolver failed to win when
it was never measured. The ordinary report is emitted before an assertion
failure; invalid expressions return status 2 and failed assertions return
status 4. No-comparable and interruption statuses retain precedence.

## Address-family selection

Every resolver address is syntax-checked before the run starts: an entry must
be an IP literal (bare, bracketed, or zoned) or a syntactically valid
hostname. Ports are configured per transport, so an address carrying one is
rejected as invalid input instead of producing a run in which every query
fails with a dial error attributed to the resolver.

Bundled resolver profiles carry the provider-published IPv4 and IPv6 literals.
`--family 4`, `--family 6`, and `--family both` are deterministic filters.
The default `--family auto` uses the up-interface address inventory without
performing DNS lookups or connection probes; when no usable family can be
detected, both literal families are retained rather than silently claiming a
route. Loopback literals are exempt from the `auto` filter, because a local
stub resolver is answered by the host's own stack regardless of which families
have external routes. Hostname-only custom endpoints remain available in
`auto` and `both`, while explicit family selection requires literals so the
benchmark does not include an unmeasured bootstrap lookup. Explicit `4`, `6`,
and `both` stay exact filters, loopback included.

Auto-detection treats the two families differently. An RFC 1918 IPv4 address
counts as IPv4 availability because NAT makes a private v4 address an ordinary
path to the Internet. A unique-local IPv6 address (`fc00::/7`, which covers
Tailscale's `fd7a::/48` and the ULAs many home routers hand out) does not count
as IPv6 availability: IPv6 has no NAT equivalent, so a ULA is not evidence of a
public route, and treating it as one produced comparison tables where every
IPv6 endpoint failed. Only global unicast IPv6 outside `fc00::/7` marks IPv6 as
available.

Auto-detection is a heuristic, so it prunes only the bundled catalog. Resolvers
the operator named explicitly — `--resolver`, `--resolver-file`, and
`--include-system` discovery — are never dropped by `auto`, because a resolver
someone asked for by address should be measured and reported rather than
silently removed. An explicit `--family 4`, `6`, or `both` is a deliberate
instruction and still filters every profile, explicit ones included. When
`auto` drops bundled addresses the run emits a warning naming the detected
families and the number of addresses removed, so the reduced comparison table
is visible rather than silent.

## Comparing two runs

`speedns diff` answers one question about two saved reports: did any resolver
behave differently? It reports what each resolver did and never how fast it did
it.

That boundary is not caution, it is what the evidence supports. The confound
between two runs is not sampling noise but an unobserved variable -- which
anycast site answered, over which transit, at what time of day -- and a report
contains no field that records it, so no threshold computed from two reports
can bound it. Measured on one host, six byte-identical back-to-back runs moved
one target's p95 by 248% and its composite score by 50%, while every
categorical count was identical across all six. Two runs thirteen hours apart
with identical settings drifted by different amounts per target, so the drift
cancels against neither an absolute baseline nor a reference target. The sound
way to compare resolver speed is to measure the resolvers together in one run,
where synchronized query rounds expose them to the same conditions.

A comparison proceeds only when both runs asked the same questions. The seed,
sample size, queries per target, query types, corpus mode and digest, timeout,
concurrency, address family, DNSSEC setting and feature version must all match.
Each of those decides what was measured rather than how it was reported, so a
difference means the two runs answered different questions. A cache-miss run is
refused unconditionally, including against another cache-miss run: its names are
generated fresh per run, so no two of them asked the same names, and an equal
nonce would prove the second run read the first run's cached answers.

Counts are compared against a floor of `max(2, 1% of responses)`. The 1% is the
budget the recommendation gate already declares acceptable, and the floor of two
is empirical: the observed run-to-run amplitude of every categorical count
across identical runs was zero to one responses.

Two suppressions exist because a categorical field can still be a threshold on
a noisy measurement. A status flip from `qualified` to `ineligible` that turns
on a sub-floor movement in usable responses is a one-response crossing of the
99% bar, not a behaviour change, and is disclosed rather than reported. A flip
that turns on `scored` is suppressed because `scored` excludes divergent
responses, which are decided by a plurality vote over the other targets present
-- a property of the cohort rather than of the resolver. Every suppression is
named in the output; silence would leave a reader unable to tell "nothing
changed" from "this was not checked".
