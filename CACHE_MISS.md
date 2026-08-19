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

`--cache-miss` cannot be combined with `--domains` or `--full`. The regular
`--sample` flag controls the warm-cache corpus; `--cache-miss-sample` controls
this bounded generated corpus. The report labels the corpus mode, zone, and
nonce. Cache-miss results receive their own rankings and must not be compared
with a warm-cache run as if they were the same sample population.

## Interpretation

The generated names normally produce negative answers, and resolver policy,
local interception, aggressive negative caching, and authoritative behavior
can all affect the result. A cache-miss run is therefore a diagnostic view of
one controlled query population, not a claim about every uncached domain.

Use `--profile-view` to inspect the transport cost for the same resolver and
address within the same run. The view includes median, p95, cold latency, the
existing score, and its deterministic 95% score confidence interval. It does
not merge transports into the protocol rankings.
