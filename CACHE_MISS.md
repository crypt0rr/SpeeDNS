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

- 1–20 generated names per invocation, with 10 as the default;
- at most two measured DNS exchanges in flight;
- no domain-list download, telemetry, persistence, or DNS configuration change;
- no public live cache-miss test is part of CI.

The 20-name limit means up to 40 measured DNS queries with the default A and
AAAA types, per resolver/transport target. Keep runs occasional and use only
the reserved zone supplied by SpeeDNS. Do not replace it with a third-party
zone or automate repeated high-volume runs.

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
many generated names, and the report warns that the corpus was truncated. The report labels the corpus mode, zone, and
nonce. Cache-miss results receive their own rankings and must not be compared
with a warm-cache run as if they were the same sample population.

## Interpretation

The generated names normally produce negative answers, and resolver policy,
local interception, aggressive negative caching, and authoritative behavior
can all affect the result. A cache-miss run is therefore a diagnostic view of
one controlled query population, not a claim about every uncached domain.

## One cache miss per run

Protocols are measured one group at a time, in the documented order `udp`,
`tcp`, `doh`, `dot`, `doq`, and every group replays the same generated name
set. A resolver keeps one cache across its transports, so only the first
measured protocol sees a genuine cache miss; the later protocols re-query
names the resolver has already looked up and therefore measure a warm cache.
Selecting more than one protocol in cache-miss mode adds a report warning that
names the protocol that got the cold lookup. Treat a cross-protocol comparison
from a single cache-miss run as biased in favor of the later protocols, and
measure one protocol per invocation when the comparison matters. Removing the
bias, rather than only reporting it, is tracked as issue #108.

Use `--profile-view` to inspect the transport cost for the same resolver and
address within the same run. The view includes median, p95, cold latency, the
existing score, and its deterministic 95% score confidence interval. It does
not merge transports into the protocol rankings.
