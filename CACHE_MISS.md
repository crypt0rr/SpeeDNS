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
resolver once. A default run against the bundled catalog therefore sends 180
reserved-zone queries: its ten profiles reach nine resolvers, because both
Google profiles answer as `dns.google`. That is fewer than the same command
sent before, since a resolver is no longer measured once per transport,
address and profile. Keep runs occasional and use only the reserved zone
supplied by SpeeDNS. Do not replace it with a third-party zone or automate
repeated high-volume runs.

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
as large as `--cache-miss-sample`, which the default of 100 already is: a
larger `--sample` simply measures every generated name. A smaller `--sample`
measures only that many generated names, and the report warns that the corpus
was truncated. Without `--cache-miss`, `--cache-miss-sample` has no effect,
and SpeeDNS says so in a warning on standard error.
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

## No name is asked twice at one resolver

A resolver holds one cache, shared across every transport it offers and every
address it answers on. So once a generated name has been looked up at a
resolver, every later lookup of that name at that resolver is a warm read
however it is reached. Two consequences follow, and cache-miss mode now
enforces both rather than reporting them.

**Each resolver is measured once.** Cache-miss mode keeps one endpoint per
resolver and names every endpoint it dropped in a report warning. Without
this, selecting two protocols meant the second measured a warm cache for every
name the first had already resolved.

A resolver here is a server, not a profile. Two profiles that share an
address, on any port, or a TLS identity — a DoH URL host or a `server_name`,
compared without regard to case or a trailing dot — reach the same server, so
they count as one resolver, and so does every profile linked to them through
another shared address or name. Two `--resolver` flags aimed at one server
therefore count once, and so do the bundled `google-8888` and `google-8844`,
which both answer as `dns.google`. Nothing beyond those identical endpoints is
inferred: profiles that answer on different addresses and names stay separate
even when one operator runs both. The rule errs towards dropping, because a
dropped endpoint is named in the warning while a warm read measured as a miss
is not disclosed anywhere: two independent resolvers on different ports of
one address, or DoH services told apart only by their URL path, are measured
as one. Under `--redact-system` a dropped system resolver endpoint is counted
in the warning rather than named. The comparison uses every address a profile
declares, including those `--family` leaves out, because a cache belongs to
the server rather than to the address family a run selects: two profiles that
share only an IPv6 address are one resolver under `--family 4` too.

An `--assert` that names only dropped endpoints — `winner=google-8844` on a
default cache-miss run, or the second of two `--resolver` flags aimed at one
server — is invalid input (status 2), checked before any query is sent,
because nothing it names will be measured. The error names the endpoint
measured for that resolver instead, which the assertion can name.

The endpoint kept for a resolver is chosen by an explicit rule: the earliest
declared profile, its first transport in the documented order (UDP, TCP, DoH,
DoT, DoQ), at its earliest declared address. Profiles count in load order:
the bundled catalog, then `--resolver-file` entries, then `--resolver` flags in
the order given, then discovered system resolvers. Every bundled profile declares
its IPv4 address first, so a dual-stack run measures every bundled resolver
over IPv4. The kept endpoint used to be the one whose target ID sorted first,
which measured Cloudflare over IPv4 and the other bundled resolvers over IPv6
and so compared address families by accident of string order.

**Each name is asked one question.** The generated names normally produce
NXDOMAIN, and a resolver caches that negative answer for the *name*, not for
the query type. Asking `speedns-<nonce>-0001.example.com` for `A` and then for
`AAAA` therefore measured a miss and then a cache hit. Cache-miss mode asks
each name exactly one question, rotating the selected types across the corpus,
so a multi-type selection is still represented without any name being asked
twice.

Together the two rules mean that no measured query repeats a question SpeeDNS
has already asked that resolver, so none is answered from the cached reply to
its own earlier question. That is all they guarantee: they do not prove that
the resolver had to recurse. A validating resolver that uses RFC 8198
aggressive NSEC/NSEC3 synthesis can answer a generated name it has never seen
from a denial proof cached for a different name in the zone, and that proof
can come from SpeeDNS's own earlier generated names in the same run, so later
names in a run may be answered from cache. Whether that happens depends on how
`example.com` signs its denials, which SpeeDNS neither controls nor detects; a
warm-up that asks `example.com` for a record type the apex lacks can cache
such a proof before the first measured query.

A resolver that forwards to another is not an independent cache either. On
Linux, `--include-system` can add both the systemd-resolved stub
(`system-stub-`) and the default-route servers it forwards to
(`system-resolved-`). SpeeDNS measures them as separate resolvers, but every
name the stub is asked is forwarded to one of those servers, so the stub's
query can warm the cache that a ranked `system-resolved-` row then reads, or
arrive while that row's own query is in flight. The stub is local and never
ranked, so the warm reads it causes are on the network row. For a cache-miss
measurement of the host's upstream, name it with `--resolver` instead of
`--include-system`.

The deliberate consequence of the two rules is that **a cache-miss run does
not compare transports.** Comparing two transports requires measuring the same
name twice at the same resolver, which is exactly what makes the second
measurement warm. Separate runs cannot stand in for that: every run generates
fresh names, and the latency difference between two runs is dominated by the
network conditions at the time of each run, which no report captures.
Cache-miss mode therefore cannot produce a sound transport comparison, and
`speedns diff` refuses every cache-miss report by design, including against
another cache-miss run. Reading two single-transport cache-miss reports side by
side is an anecdote, not a comparison.

For the same reason `--profile-view` is a warm-cache tool: in cache-miss mode a
resolver contributes a single transport, so the view has nothing to compare.
Use it on an ordinary run to inspect transport cost for one resolver and
address, with median, p95, cold latency, the score, and its deterministic 95%
score confidence interval. Even there the transports are measured in a fixed
order over the same names, so a later one can read answers an earlier one
cached; [`METHODOLOGY.md`](METHODOLOGY.md#cache-miss-mode-and-profile-view)
describes that bias.
