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
preparation shrinks that positional bias by the concurrency factor.
Preparation has a barrier between the cold probes and the reusable measured
sessions: all dispatched targets finish cold preparation before any target's
warm session is opened. This prevents a blocked target's cold-probe timeout
from aging a healthy target's connection before measurement. Results and
rankings stay in target-identity order regardless of which preparation
finished first. There is no transport fallback.

Every measured round waits for its slowest dispatched target, so a target
that never answers costs wall-clock time for the whole protocol group, not
only failed samples of its own. Opening a UDP or DoH session sends nothing, so
a silent UDP or DoH endpoint still enters measurement, as does a TCP, DoT, or
DoQ endpoint that completes its connection and then never answers; each of its
measured queries waits out the full `--timeout`. Per protocol, unresponsive
targets therefore add roughly `queries_per_target × ceil(unresponsive /
concurrency) × timeout` to the run, and every healthy target in the group is
paced at that slower rate. One silent UDP target in a default run costs about
200 × 2 s, close to seven minutes, and about 67 minutes with `--full`. Its
cold probes and warm-ups add a few more timeouts during preparation, and a
`--dnssec` run adds about `2 × ceil(unresponsive / concurrency) × timeout` for
its probes, which share the same pool. There is deliberately no cutoff: a
resolver that stops answering is measured and reported as failed rather than
silently dropped mid-run. On a network where one address family or resolver
is black-holed, `--family`, a smaller resolver selection, or a lower
`--timeout` shortens the run.

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
record rather than NODATA, published as `answers` and `answer_rate`. Like
`success_rate`, `failure_rate`, `usable_rate` and `resolver_failure_rate`,
`answer_rate` is divided by all measured queries (`total`), not by usable
responses, so failed, unusable and NXDOMAIN queries lower it too;
`answers / usable_responses` is the share of usable responses that carried a
record. NODATA is usable and is scored, so without this a resolver answering
every query with an empty answer section is indistinguishable from a working
one on the success and usable columns. It is disclosed and never penalised: on
the default `A,AAAA` corpus a real resolver returns a record only about 45% of
the time, so an absolute threshold would produce false accusations.

## What is measured

Warm latency is measured from immediately before a DNS exchange until the
validated response or error returns. Per-query deadline setup and post-exchange
bookkeeping, such as the reconnect check, fall outside the timed section. TCP,
DoT, and any recovered stream
connection are not closed before the timer stops. A query that follows a TCP,
DoT, DoH, or DoQ reconnect is recorded as a reconnect sample and excluded from
ordinary warm-latency scoring; its reconnect count and selected dial address
remain visible in detailed output and machine-readable results. A DoH session
opens its HTTPS connection when the session is opened, as the stream
transports do, and that connection is not a reconnect. The session reuses it;
when it is gone, the HTTP client opens a new one transparently, so the query
that pays for the new TCP, TLS, and HTTP handshake is the reconnect sample. An
HTTP/2 connection that stops answering without being closed is pinged after
one timeout of silence and dropped when the ping goes unanswered for another
timeout, so a dead path costs DoH about as many failed queries as the other
transports rather than one per HTTP/2 stream the server allows. DoQ sessions
use TLS 1.3 with ALPN `doq`, an explicit keepalive period equal to the
configured timeout, and a maximum idle timeout of twice that timeout. The
failed exchange that caused the reconnect is counted once and is never
retried. A DoT or DoQ reconnect runs inside one query's deadline, so it first
tries the bootstrap candidate the session last connected to and then the
others in configured order; when a reconnect runs out of time, the next one
starts at the following candidate, so a candidate that stopped answering
cannot consume every later query's budget.

Cold probes use three separate sessions. Their timer includes session opening,
the first DNS exchange, and response validation, but stops before session
teardown. Cold medians are reported separately and never enter the warm score.

Only transport-valid DNS messages are transport successes. A UDP datagram,
TCP, DoT, or DoQ frame, or DoH body that carries bytes after the complete DNS
message is malformed, not accepted as the message alone. A response is
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
in the additive `local` field on the target and CSV in its `local` column, so
a consumer can tell a missing rank caused by non-comparability apart from one
caused by a failure.

Members of the score-order leader's tie group -- the leader and every target
whose 95% score confidence interval overlaps the leader's, as defined under
"Confidence intervals and ties" below -- are ordered among themselves by the
score with only its p95 term removed, then by median latency, then by target
ID:

```text
tie_order_ms = 0.60 × median_ms
             + scoring_failure_rate × timeout_ms
```

The score is 60% median and 40% p95, and p95 is by far the less stable half:
over the same observations the median interval is 9-14% of its point estimate
while the p95 interval is 66-143%. Ordering indistinguishable targets by score
therefore made the presented order a function of run-to-run noise -- four runs
of one command at one seed produced three different orders, and the target with
the worst median in every run took rank one twice. Dropping the p95 term settles
that order with the most stable latency statistic available. When no member has
a scoring failure, the order is exactly median order.

The failure term stays because it is the score's only reliability signal. With
one to three scoring failures in a default 200-query run, enough bootstrap
replicates draw no failure at all that the target's interval reaches down to
its latency-only score. A target about as fast as the leader therefore joins
the leader's group however large its failure penalty, and ordering the group
by median alone gave rank one -- and `RECOMMENDED`, while the target still had
99% usable responses -- to a resolver that lost 2 of 200 queries over one that
lost none, because its median was 1 ms lower. The key uses the scoring-failure
rate, so timeouts, transport failures, truncated responses and resolver errors
such as SERVFAIL or REFUSED count exactly as they do in the score, priced at
the run's `--timeout`.

That is a deliberate trade-off. Failure counts are sampled too: two resolvers
with the same true loss rate can lose different numbers of queries in one run,
and for two otherwise near-identical resolvers that difference can now swap
their order within the group where median order would have kept it. SpeeDNS
prefers that to recommending the less reliable resolver. Membership does not
depend on the order, so both remain `TIED` either way.

No measured value changes. Targets outside the leader's tie group keep the
score/ID order, even when their intervals overlap each other or a member other
than the leader. Every member is presented ahead of every non-member, so a
member with a large failure penalty can still be listed above a non-member
whose score is better but whose interval does not reach the leader's.

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

Rank order is deterministic. SpeeDNS first orders eligible targets by score,
then target ID, and selects that order's leader. A target is in the leader's
tie group when its 95% bootstrap interval overlaps the leader's interval.
Members of that one leader-anchored group are presented by
`0.60 × median_ms + scoring_failure_rate × timeout_ms`, then median, then
target ID, for the reasons given under "Scoring and divergence" above; targets
outside it keep the score/ID order. The leader is marked as tied too whenever
another target overlaps it, so the tie is visible from either row. The group is
deliberately anchored to one leader: interval overlap is not transitive, and
treating every pair as a separate sort decision would not define a stable
order. Each protocol therefore has at most one tie group, and
`--assert winner=` counts membership in it as sharing rank one.

Every output surfaces that flag, and it means membership in the leader's tie
group, not overlap with any other ranked target. The human table has a `Tie`
column in the recommendation summary and in each per-protocol comparison; a
member reads `TIED` and every other row reads `—`. A `—` row is not in the
leader's group, but its interval may still overlap another row outside the
group, or a member other than the leader. When a recommended or provisional
winner is tied, the recommendation block also carries a `TIED:` note stating
that the ordering is not statistically distinguishable, so a rank-one row is
never presented as an unqualified winner. CSV keeps its `tie` column and JSON
keeps `tie` on both `rankings[]` and `results[].stats`. The strict `1..N` rank
is still reported: a tie qualifies the ordering, it does not remove it.

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

Protocol groups are measured one after another, so what an interrupted report
lists depends on the group the interrupt reached. A group that had already
finished keeps its complete results and its rankings. Within the group being
measured, targets are prepared concurrently, so all of them normally reach a
worker within the first moments of that group, and an interrupt has to arrive
before the group's preparation begins for any of them to be missing. That
group is therefore listed in full, with every target still being measured
marked `INCOMPLETE`, not as a shortened list. A group the interrupt arrived
before is never dispatched, and its targets are absent from the report.

An interrupt can also land after the last protocol group has finished, while
statistics and rankings are still being computed. That report is complete and
ranked, and its warning says so -- `interrupt received after measurement
completed; results are complete` -- instead of `benchmark interrupted before
all targets completed`, which a report carries whenever some selected target
is incomplete or missing. An interrupt during the last group's `--dnssec`
probes is still before completion: that group's prepared targets are marked
`INCOMPLETE`. Either way the run exits with status 130 and assertions are not
evaluated, because the operator asked it to stop.

JSON contains the structured result and optional raw observations. CSV keeps
the aggregate schema and carries these diagnostics in its `reconnects` and
`incomplete` columns.
Text that SpeeDNS did not produce itself is escaped before it reaches a
terminal, a CSV cell, or a JSON string. Session errors and DNSSEC probe errors
quote strings chosen by the endpoint, such as the certificate names in an
`x509` hostname mismatch or the reason phrase of a DoH HTTP/1.1 status line,
and resolver IDs, names, owners, policies, DoH endpoint URLs, TLS server
names, and bootstrap addresses arrive from `--resolver`, `--resolver-file`, or
the system resolver configuration. Control characters in any of them are
rendered as visible `\x1b`-style sequences, so neither a certificate field nor
a configured name can rewrite the terminal. Bidirectional controls (U+061C,
U+200E, U+200F, U+202A-U+202E, U+2066-U+2069) and invisible format characters
(U+200B-U+200D, U+2060-U+2064, U+FEFF) are rendered as `\u{202e}`-style
sequences, so they cannot reorder or hide the text around them either. That
includes the zero-width joiners U+200C and U+200D, which legitimate Persian
and Indic-script names use; they are shown escaped rather than dropped.
Table column widths count format characters other than the soft hyphen as zero
cells. JSON carries these values in the same escaped form as the table and
CSV, so a consumer that decodes and prints a string, such as `jq -r`, gets the
escaped text as well; that includes interface names in the run provenance and
every target ID, detail and warning that `speedns diff --format json` echoes
from its input reports. The failure messages that `--assert` and
`speedns diff --require` print to stderr escape the target IDs and finding
details they quote. The status colours are the only escape sequences the table
emits itself. CSV cells are escaped first and the formula guard runs
afterwards on the escaped value: a cell beginning with `=`, `+`, `-`, `@`, or
an escape sequence of either form - which is how a leading tab, carriage
return, ESC, or bidirectional override is rendered - is prefixed with an
apostrophe to prevent spreadsheet formula interpretation.
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
`AAAA` measured a miss and then a cache hit. Both rules together mean that no
measured query repeats a question SpeeDNS has already asked that resolver, so
none is answered from the cached reply to its own earlier question. That is
not proof the resolver recursed: a validating resolver using RFC 8198
aggressive NSEC/NSEC3 synthesis can answer an unseen name from a denial proof
cached for a different name, and that proof can come from SpeeDNS's own earlier
generated names in the run, which `CACHE_MISS.md` names as a limit. The cost of
the rules is that a cache-miss run cannot compare transports, because doing so
requires measuring one name twice at one resolver. Separate runs cannot stand
in for that either -- each generates fresh names, and cross-run latency is
dominated by the network conditions at the time of each run, which no report
captures -- so `speedns diff` refuses every cache-miss report.

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
than to suppress it. Up to `--concurrency` targets are probed at once; a
target's two probes run one after the other on its own measured session, and
no probe is sent after an interrupt. A target the interrupt reaches before
both of its probes have finished gets no verdict, whichever probe was cut
short, like the targets not yet reached, and is marked incomplete with them.

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

A subject endpoint with no scored latency samples fails every `median`, `p95`
and `score` assertion, whatever the operator. Those statistics are only
computed from scored samples and stay zero without one, so comparing them would
let a resolver that timed out, refused every query or answered only `SERVFAIL`
pass an upper bound, and would report a fabricated `0.000ms` against a lower
one. The same holds for an endpoint whose every usable answer was divergent or
followed a reconnect: it may be healthy, but it produced no latency the bar
could be checked against, so the gate cannot confirm it. The structural rule above does not catch this case: it skips local
resolvers and stays quiet while any other endpoint of the protocol answers.
`usable` and `success` are rates over every measured query, so they keep their
ordinary meaning. Unqualified assertions are unaffected, because a rank-one
target always has scored samples.

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

The `--require` conditions read the findings, so they inherit every
suppression. A gate that measured and failed exits 4; a gate that could not
evaluate exits 3 and never 0. A refused comparison is the first case of the
second kind. The other is a comparable pair in which no endpoint was compared
because every target was incomplete on either side, local, redacted, or
present in only one run. Every condition then reads an empty set of paired
findings, so a pass would describe nothing, and the gate exits 3 with a count
of the targets each reason excluded. A condition that fails on such a pair
still exits 4, because a target missing from one run is a real finding that
needs no pairing. Every condition that does not hold is reported, in the order
given, rather than only the first.

`no-new-failed-targets` asks whether the current run introduced a failed
target. The findings it reads are two-way, because a recovery is a behaviour
change. The condition is not two-way: it fails only when a target with
successes in the baseline has none in the current run, when a target that
opened in the baseline cannot open now, or when a target measured only in the
current run failed every query and is neither local nor interrupted. A recovery
passes, since a baseline saved during an outage would otherwise fail the gate
exactly when the resolver came back.
