# Cache-miss mode

Cache-miss mode is an explicit, bounded experiment for recursive lookups that
are unlikely to be present in a resolver cache. It is separate from the
normal benchmark and is never combined with the embedded Tranco corpus or a
custom domain list.

## Safe scope

SpeeDNS uses the IANA-reserved `example.com` zone. SpeeDNS does not own this
zone and does not claim that it can provide authoritative cache-miss
measurements. The generated names are unique random labels such as
`speedns-0123456789abcdef-0001.example.com`; the nonce is shown in the report
so the run can be audited.

The mode has deliberate limits:

- 1–20 generated names per invocation, with 20 as the default;
- at most two measured DNS exchanges in flight;
- no domain-list download, telemetry, persistence, or DNS configuration change;
- no public live cache-miss test is part of CI.

The 20-name limit means up to 20 measured DNS queries per resolver, because
cache-miss mode asks each generated name exactly one question and measures each
resolver once. A default run against the bundled catalog therefore sends 200
reserved-zone queries — fewer than the same command sent before, since a
resolver is no longer measured once per transport and address. Keep runs
occasional and use only the reserved zone supplied by SpeeDNS. Do not replace
it with a third-party zone or automate repeated high-volume runs.

## Usage

Use a custom resolver and keep the target set small while validating a local
setup:

```sh
speedns --cache-miss --cache-miss-sample 10 --no-defaults \
  --resolver lab=udp://192.0.2.53:53 --type A --no-color
```

`--cache-miss` cannot be combined with `--domains` or `--full`.
`--cache-miss-sample` sizes this bounded generated corpus, and `--sample`
still selects how many of those names are measured. Keep `--sample` at least
as large as `--cache-miss-sample`; a smaller `--sample` measures only that
many generated names, and the report warns that the corpus was truncated.
Because each name is asked one question, the corpus size is also the scored
sample count, and the default of 20 is the minimum the paired confidence
intervals need. The report labels the corpus mode, zone, and
nonce. Cache-miss results receive their own rankings and must not be compared
with a warm-cache run as if they were the same sample population.

## Interpretation

The generated names normally produce negative answers, and resolver policy,
local interception, aggressive negative caching, and authoritative behavior
can all affect the result. A cache-miss run is therefore a diagnostic view of
one controlled query population, not a claim about every uncached domain.

## Every measured query is a real miss

A resolver holds one cache, shared across every transport it offers and every
address it answers on. So the first lookup of a generated name at a resolver is
a genuine miss, and every later lookup of that name at that resolver is a warm
read however it is reached. Two consequences follow, and cache-miss mode now
enforces both rather than reporting them.

**Each resolver is measured once.** Cache-miss mode keeps one endpoint per
resolver — its earliest declared transport at its lowest-sorting address — and
names the endpoints it dropped in a report warning. Without this, selecting two
protocols meant the second measured a warm cache for every name the first had
already resolved.

**Each name is asked one question.** The generated names normally produce
NXDOMAIN, and a resolver caches that negative answer for the *name*, not for
the query type. Asking `speedns-<nonce>-0001.example.com` for `A` and then for
`AAAA` therefore measured a miss and then a cache hit. Cache-miss mode asks
each name exactly one question, rotating the selected types across the corpus,
so a multi-type selection is still represented without any name being asked
twice.

The deliberate consequence is that **a cache-miss run does not compare
transports.** Comparing two transports requires measuring the same name twice
at the same resolver, which is exactly what makes the second measurement warm.
Measure one transport per invocation and compare the runs, accepting that they
used different names.

For the same reason `--profile-view` is a warm-cache tool: in cache-miss mode a
resolver contributes a single transport, so the view has nothing to compare.
Use it on an ordinary run to inspect transport cost for one resolver and
address, with median, p95, cold latency, the score, and its deterministic 95%
score confidence interval.
