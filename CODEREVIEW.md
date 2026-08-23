# SpeeDNS code review

Review of `main` at `c999763` (2026-08-22). Go 1.25 target, ~13.9k LOC.

## How this was reviewed

Nine specialist reviewers covered benchmark core, transports/TLS, report+schema,
CLI+assertions, catalog/domains/systemdns, security+supply chain, test quality,
docs drift, and design. A completeness critic then hunted for what they all
missed, and an adversarial pass stress-tested the proposed fixes — which found
real defects in two of them.

Findings were then verified independently, not taken on report:

- the suite was run across three Go toolchains;
- the binary was built and run against live public resolvers;
- the real `scripts/live-smoke.sh` and `scripts/publish-live-results.py` were
  executed against real output;
- live JSON was validated against the shipped schemas with a real JSON Schema
  validator;
- the scoring engine was mutation-tested;
- all four fuzz targets were actually fuzzed;
- the P0/P1 fixes were prototyped and re-verified end to end.

Where a claim could not be demonstrated, that is stated.

---

## Verdict

This is a well-built project, and the hard parts are the good parts. The
methodology is unusually rigorous for a DNS benchmark: policy-scoped divergence
detection, deterministic seeded bootstrap CIs, paired policy-local effects, an
explicit usable-vs-transport-success distinction, reconnect-aware sample
exclusion, atomic report writes, a strictly-validated published JSON schema.
The supply chain is better than most: every Action SHA-pinned, release behind an
environment gate with Sigstore signing and GitHub attestations, CodeQL and
`govulncheck` scheduled.

The problems cluster in four places:

1. **A latent build-portability failure.** The suite is red on Go 1.27, and the
   same root cause silently changes which domain names the shipped binary accepts
   depending on the toolchain that built it.
2. **Contract drift between components CI never tests together.** The encoder,
   the schemas, and the live-results publisher disagree. The scheduled publishing
   pipeline cannot succeed on any real run — and CI is green because the only
   fixture feeds it synthetic data the encoder cannot produce.
3. **Analysis features that are quietly inert.** Divergence detection and the
   paired confidence intervals are keyed on a free-text `policy` string that no
   package validates. For every filtering resolver in the bundled catalog, every
   `--resolver`, and every system resolver, that key is a singleton — so no
   comparison is ever made and nothing says so.
4. **Checks that report success on inputs they never see.** `--assert` exits 0
   when an entire transport is down. The release "reproducibility gate" compares
   two throwaway builds and never touches what ships. 100% statement coverage
   sits on top of a scoring engine where 6 of 7 wrong-constant mutants survive.

Nothing here is a conventional security hole. The risk is "a benchmark that
sometimes reports the wrong thing confidently" — which for this project is worse.

---

## P0 — Ship first

### P0-1 Suite red on Go 1.27; domain validation depends on the building toolchain

`internal/domains/domains.go` — `normalize()` strips the root label *after* IDNA:

```go
name, err := lookupProfile.ToASCII(value)   // IDNA first …
if err != nil {
    return "", err
}
name = strings.TrimSuffix(name, ".")        // … root label trimmed after
```

UTS-46 `ToASCII` with `VerifyDNSLength(true)` rejects the trailing empty label,
and whether it does depends on the Unicode tables `x/net/idna` picks **by Go
build tag**:

```
x/net/idna/tables15.0.0.go   //go:build !go1.27
x/net/idna/tables17.0.0.go   //go:build go1.27
```

Measured on this repo, unmodified:

| Toolchain | `go test ./...` |
|---|---|
| `GOTOOLCHAIN=go1.25.0` | pass |
| `GOTOOLCHAIN=go1.26.0` | pass |
| `GOTOOLCHAIN=go1.27.0` | **7 failures** — 4 in `internal/domains`, 3 in `internal/benchmark` |

`git bisect` puts the code shape at `473f20b` (#25); it only surfaces on 1.27.
CI pins `GO_VERSION: '1.25.x'`, so it has never been visible there.

**This is not only a CI problem.** `go install …@latest` builds with the *user's*
toolchain, and README tells people to build from source with "Go 1.25 or newer".
On Go 1.27 that binary rejects `example.com.` — the form `dig +short`, zone
dumps and `host -t ns` emit — and since `validateInputs` returns on the first bad
entry, **one such line aborts the whole run** before a packet is sent.

**Fix — and note the obvious version is incomplete.** Trimming `"."` before
`ToASCII` is right, but UTS-46 *maps* three more code points onto the label
separator, so an ASCII-only trim still fails on 1.27. Verified:

```
"example.com。"(U+3002) after TrimSuffix(".") -> ToASCII -> idna: invalid label "example.com."
"example.com．"(U+FF0E) after TrimSuffix(".") -> ToASCII -> idna: invalid label "example.com."
"example.com｡"(U+FF61) after TrimSuffix(".") -> ToASCII -> idna: invalid label "example.com."
```

Trim all four forms, and restore the empty-after-trim guard (`"。"` alone is not
caught by the existing `value == "."` check):

```go
// UTS-46 maps the ideographic and fullwidth stops onto the ASCII label
// separator, so all four forms have to be trimmed before ToASCII.
const rootLabelSeparators = ".。．｡"

value = strings.TrimRight(value, rootLabelSeparators)
if value == "" {
    return "", nil
}
name, err := lookupProfile.ToASCII(value)
```

Verified: identical, correct results for all four forms on Go 1.25 **and** 1.27.

**Also:** make CI a Go-version matrix. See the sequencing note — it needs the
artifact name fixed at the same time.

---

## P1 — Correctness and trust

### P1-1 The scheduled live-results pipeline rejects every real run

`Statistics.Tie` is `json:"tie,omitempty"`, so the key vanishes when false. But
`schema/live-results-v1.json` marks `tie` required, and
`scripts/publish-live-results.py` enforces it (`STAT_KEYS`, `validate_stats`).

Reproduced end to end — real `live-smoke.sh` → real evidence → real validator:

```
main (current)  udp: publisher REJECTED -> udp: stats.tie is missing
main (current)  tcp: publisher REJECTED -> tcp: stats.tie is missing
with fixes      udp: publisher ACCEPTED
with fixes      tcp: publisher ACCEPTED
```

The smoke script runs one endpoint per transport, so there is never a tie, so the
key is *always* absent. The publish job cannot succeed on any real run; the
results branch and Pages site are never updated. CI stays green because
`scripts/publish-live-results-fixture.sh` hand-writes `"tie": False` — a value
the encoder cannot emit.

The inconsistency is internal too: `Ranking.Tie` has no `omitempty` and *is*
emitted; only `Statistics.Tie` disappears.

**Fixing `Tie` alone is not enough.** Three more required fields are `omitempty`
and are exactly zero whenever a transport is fully down. Verified against the
real validator with a real all-failed run:

```
tie only         -> REJECTED -> udp: stats.cold_median_ms is missing
all four dropped -> validate_stats: ACCEPTED
```

**Fix:** drop `,omitempty` from `Tie`, `ColdMedianMS`, `CILowMS` and `CIHighMS`
in one change, and regenerate `internal/report/testdata/golden/report.json`
(7 added lines). Then rework the fixture to generate evidence from the real
encoder and validate `latest.json` against its shipped schema.

### P1-2 `rankings: null` violates SpeeDNS's own published v1 schema

```go
rankings := append([]benchmark.Ranking(nil), report.Rankings...)
```

A nil-preserving append on an empty slice yields `nil` → `null`.
`schema/report-v1.json` declares `rankings` required and `{"type": "array"}`.

Reproduced:

```
$ speedns --no-defaults --resolver 'blackhole=udp://203.0.113.1:53' \
          --sample 2 --timeout 1s --format json      # exit 3
report-v1.json:  ['rankings']  None is not of type 'array'
```

This is exactly the case the tool exists to reveal — offline laptop, firewall
blocking DoT/DoQ, everything timing out — and there the output fails the contract
SpeeDNS publishes as v1.

**Fix:** `append(make([]benchmark.Ranking, 0, len(report.Rankings)), …)`.
Verified: the same run now emits `rankings: []` and validates. Add a schema test
covering a no-comparable-results report.

### P1-3 `policy` is an unvalidated free-text grouping key, so the two headline analyses are inert for most targets

This is the deepest finding in the review.

`policy` is written in three packages and validated in none —
`catalog.go` (`Policy: "user supplied"` for `--resolver`), `systemdns.go`
(`"unknown"`, `"local forwarding (upstream unknown)"`), and free text in
`data/resolvers.yaml`. `catalog.Validate` only `TrimSpace`s it. It is then used
as a **grouping key** in `benchmark.go` for both `divergenceGroupKey` and
`pairedGroupKey`.

A group of one can never produce a comparison: `markDivergence` bails at
`len(counts) <= 1`, and `calculatePairedEffects` makes a lone member its own
reference. In the shipped catalog, 5 of 10 profiles are alone in their policy
string — and so is every `--resolver` and every system resolver.

Observed live, in default output (not `--details`): the paired-effects block
printed **30 rows, 15 of them `REFERENCE` self-comparisons**
(`+0.00 ms [+0.00, +0.00]`).

So the Comparisons table happily ranks Quad9 ("threat blocking + DNSSEC") against
Cloudflare across a policy boundary, but no confidence interval ever crosses one
— the reader is never told whether that ranking is distinguishable from noise.
A one-character difference in a YAML policy string silently changes which
resolvers are statistically comparable. Nothing warns.

**Fix:** decide what `policy` means and enforce it — either normalise to a closed
vocabulary in `catalog.Validate` (keeping the prose in a separate non-key label
field), or stop keying on it and record the policy mismatch as an annotation.
At minimum, warn for every `(protocol, policy)` group of size 1 and label the row
`NOT COMPARABLE` rather than `REFERENCE`.

### P1-4 Paired-effect CIs have no minimum-sample gate

`bootstrapPairedCI` short-circuits `len(deltas) == 1` by returning
`(deltas[0], deltas[0])` — a zero-width interval — and `calculatePairedEffects`
gates only on emptiness. `Indistinguishable` is therefore false, and the report
prints a directional `SLOWER`.

Meanwhile the ranking engine *does* gate: `Recommended` needs
`Scored >= MinimumRecommendedSamples` (20).

The result is two contradictory verdicts in one report. From
`--protocol udp --sample 1`: every ranking row says `INELIGIBLE`, while the
paired block says

```
udp  unfiltered  Cloudflare 1.1.1.1  Google 8.8.4.4  1  +83.42 ms  [+83.42, +83.42] ms  SLOWER
```

under a column headed "95% CI". `--sample 1` is not hypothetical —
`scripts/live-smoke.sh` runs exactly that.

**Fix:** apply the same minimum-sample gate to paired effects; drop the `n == 1`
special case rather than returning a degenerate interval.

### P1-5 `--assert` passes when an entire selected protocol produced no ranking

`evaluateAssertions` fails only when `len(winners) == 0` across *all* protocols;
`winnerProtocols()` iterates the winners map, so a protocol with no ranking is
never iterated.

Reproduced:

```
$ speedns --no-defaults \
    --resolver 'good=udp://8.8.8.8:53' \
    --resolver 'bad=quic://203.0.113.1:853' \
    --protocol udp,doq --sample 3 --assert 'usable>=0.99'
exit 0
```

DoQ scored 0 samples, `usable_rate` 0, "could not open a session" — and the
health gate went green. **Total failure of a transport is less likely to trip
the gate than partial degradation.**

**Fix — not the obvious one.** Driving this from `report.Provenance.Protocols`
over-fires: `--protocol` defaults to all five, and `catalog.Expand` only creates
targets for transports a profile declares, so the README's own example
(`--no-defaults --resolver good=udp://…`) would start exiting 4 for four
transports that never had an endpoint. Derive the required set from the protocols
actually present in `report.Targets` instead — available inside
`evaluateAssertions` with no new plumbing.

Related dead code: `benchmark.Options.Protocols` is assigned in `main.go` and
**never read anywhere** in the benchmark package.

### P1-6 Numeric `--assert` applies to the whole tie group, and the group size is unpredictable

README and METHODOLOGY both scope numeric assertions to "every qualified or
provisional **winner**". In practice `reportWinners` admits rank 1 *plus every
CI tie-group member*, and that set swings wildly with sample size and network
noise. Measured on the same catalog and seed:

| `--sample` | targets a numeric `--assert` is evaluated against |
|---|---|
| 3 | 6 of 10 |
| 10 | 3 of 10 |
| 25 | **10 of 10** |

So `--assert p95<50ms` often means "every resolver's p95 must be under 50 ms",
and whether it does is decided by run-to-run noise. For a CI gate that is
non-determinism, not strictness.

**Fix:** scope numeric assertions to rank 1 only, or add explicit scoping syntax
(`doh.p95<50ms`, `winner.p95<50ms`) and document which is which.

### P1-7 Canonical NODATA is classified as an answer

```go
if len(message.Answer) == 0 && len(message.Ns) == 0 {
    return "nodata"
}
return "answer"
```

A real NODATA carries an SOA in the **authority** section, so `Ns != 0` and it
falls through to `"answer"`. The `nodata` class only fires for a response with no
records at all — the *non*-canonical form.

Live, against `8.8.8.8`:

```
github.com    AAAA  NOERROR ANSWER=0 AUTHORITY=1  ->  ResponseClass="answer"
example.com   AAAA  NOERROR ANSWER=2 AUTHORITY=0  ->  ResponseClass="answer"
```

"No AAAA here" and "here are two AAAA records" get the same class. Across a live
500-observation `--type A,AAAA` run over 10 resolvers: **478 `answer`, 2
`nodata`**. METHODOLOGY.md advertises a class that is effectively dead, and the
divergence engine cannot see the most common difference on the default query set.

**Fix:** classify on the question type. With the fix, the same live run gives
**270 `answer`, 209 `nodata`**, divergence groups unchanged at 0, scored samples
480 → 479 — the label becomes truthful without destabilising scoring.

**Blast radius to budget for.** Once `answer` and `nodata` are distinct classes,
an answer-vs-NODATA split inside a policy group becomes a divergence group and
minority observations get latency-excluded; a tied plurality excludes the whole
group. Three shapes can produce that from resolver *verbosity* rather than
policy: a CNAME chain returned without the terminal RRset, DNAME, and `--type NS`
/ `SOA` where the RRset commonly arrives in AUTHORITY. Consider accepting a CNAME
in ANSWER as answering the query (or giving it its own class), and update
METHODOLOGY.md's divergence section in the same commit.

### P1-8 `--family auto` false-positives on ULA and Tailscale addresses

`detectAddressFamilies` accepts any `ip.IsGlobalUnicast()`. Go returns **true for
unique-local IPv6** (`fc00::/7`), which covers Tailscale's `fd7a::/48` and the
ULAs many routers hand out:

```
fd47:a90b:1d35:4f2d::1      GlobalUnicast=true  IsPrivate=true
fd7a:115c:a1e0::6a36:ec14   GlobalUnicast=true  IsPrivate=true
2606:4700:4700::1111        GlobalUnicast=true  IsPrivate=false
```

On this review host — ULAs only, no default IPv6 route — auto concluded IPv6 was
available and every IPv6 measurement failed. Measured:

```
main:   targets=20  unreachable=10
fixed:  targets=10  unreachable=0
```

**Fix:** for IPv6 require `IsGlobalUnicast() && !IsPrivate()`; keep
`IsGlobalUnicast()` alone for IPv4, where RFC 1918 plus NAT is a real path.

**Caveat that must ship with it.** `FilterProfilesByFamily` runs over *all*
profiles, including `--resolver`, `--resolver-file` and `--include-system`. After
this change, a user who explicitly names a ULA resolver under the default
`--family auto` has it silently dropped — and if it is the only one, the run dies
with "no resolver addresses match". Exempt explicitly-supplied profiles from auto
filtering (or apply auto filtering only to `catalog.DefaultResolvers()`), and warn
with the detected families and the number of addresses dropped.

### P1-9 Protocols are measured in a different order than documented

METHODOLOGY.md says `udp, tcp, doh, dot, doq`. `catalog.Protocol` is a `string`
and `Run` sorts it lexicographically, giving **`doh, doq, dot, tcp, udp`**.
Confirmed live:

```
main:   tested doq → tcp → udp
fixed:  tested udp → tcp → doq
```

It also disagrees with `catalog.AllProtocols`, which `canonicalProtocols()` uses
for *display* — so the report shows one order and measures another. And the test
suite **pins the wrong order** (`coverage_test.go` asserts
`progress[0].Protocol == catalog.TCP`), so the drift cannot self-correct.

**Fix:** rank by index in `catalog.AllProtocols`. See P1-10 — this must not ship
alone.

### P1-10 `--cache-miss` only measures a cache miss for whichever protocol runs first

`main.go` generates one nonce and one name set; `Run` replays the same matrix per
protocol group. Each resolver has one cache, so after the first group has queried
`speedns-<nonce>-0001.example.com`, every later group measures a **warm** lookup.

Combined with P1-9, the transport that gets the honest cold measurement is
whichever sorts first — today `doh`. Fixing the order alone does not remove the
bias, it **moves it onto `udp`**, the baseline transport, and a cold cache is
*slower* — so the headline udp-vs-doh comparison in cache-miss mode can flip
direction on P1-9 alone. CACHE_MISS.md documents none of this.

**Fix:** fold the protocol into the generated label so each group gets fresh
names, and ship it with P1-9. If it cannot land together, gate `--cache-miss` to
one protocol per run and document the transfer.

### P1-11 A hostile DoH endpoint gets unbounded redirects

The custom `CheckRedirect` correctly pins the origin, but Go's 10-hop cap lives
*only* inside `defaultCheckRedirect` — replacing the callback removes it.
Measured against a self-redirecting local server:

```
SpeeDNS's CheckRedirect : 15,457 requests in 3s, then Client.Timeout
Go's default            : 10 redirects, "stopped after 10 redirects"
```

Every cold probe, warm-up and measured query becomes a ~15k-request burst from
the user's machine for the whole timeout window, and `via`/`reqs` grow throughout.
For a tool that markets itself as read-only and polite, that is a self-inflicted
amplifier.

**Fix:** `if len(via) >= 5 { return errors.New("DoH endpoint exceeded the redirect limit") }`
ahead of the origin check.

### P1-12 Untrusted text reaches the terminal and CSV unescaped

`--details` prints `report.Warnings` verbatim; those embed `result.OpenError`,
which for TCP/DoT/DoQ carries certificate-supplied strings (`x509: certificate is
valid for <SAN>, not <host>` — ESC `0x1b` passes Go's IA5String check). Verified:

```
ESC (0x1b) present in --details table output: true
raw CR present:                                true
ESC present in CSV output:                     true
```

The code already guards CSV *formula* injection; the control-character case is
the same class and was missed.

**Fix — placement matters.** Sanitise at the *value* level, inside or immediately
ahead of `csvCell` and the `*Text` helpers — never at `writeAlignedTable` or
`writeWarnings`:

- it must run **before** the CSV formula guard. `csvCell` only inspects
  `value[0]`; an owner of `"\x1b=cmd|'/C calc'!A1"` starts with ESC, gets no
  apostrophe, and a downstream sanitiser then hands the spreadsheet a live
  formula;
- it must **not** run at the table sink, where `styledStatus` legitimately emits
  ESC colour codes.

Prefer escaping (`\x1b`) over stripping, and cover flag/YAML-derived fields, not
only `OpenError`.

### P1-13 DoH is structurally exempt from reconnect detection

`streamSession` and `doqSession` implement `LastQueryReconnected()`;
`doHSession` does not, so `sessionQueryReconnected` returns false for every DoH
query. `http.Transport` re-dials transparently, so a full TCP + TLS + HTTP/2
handshake is billed into a single "warm" sample — the exact event TCP, DoT and
DoQ exclude. It lands on p95, which carries 40% of the composite score, and
`stats.reconnects` is always 0 for DoH.

**Fix:** track re-dials in the existing `DialTLSContext` hook (it already fires
per new connection) and expose `LastQueryReconnected()` on `doHSession`.

*Confirmed by code reading; not reproduced live — it needs a mid-run drop.*

### P1-14 The scoring engine is not pinned by any test

100% statement coverage, and the only assertion on the numbers is a shape check
(`MedianMS <= 0 || P95MS < MedianMS || ScoreMS <= 0`). Everything else hand-sets
`Stats{ScoreMS: …}` as an *input*. Mutation-tested against the full suite
(gofmt + vet + race + 100% gate):

| Mutation to the scoring/statistics engine | Result |
|---|---|
| swap the documented 0.60/0.40 score weights | **survived** |
| drop the p95 term entirely | **survived** |
| report the 5th percentile in the `median_ms` column | **survived** |
| report p99 as p95 | **survived** |
| widen the "95%" bootstrap CI to 80% | **survived** |
| lower the RECOMMENDED threshold from 20 samples to 2 | **survived** |
| drop the failure penalty | killed |

Six of seven. A refactor that transposes the weights or reports the wrong
percentile ships green and users read a published `report.json` whose numbers are
silently wrong.

**Fix:** one table-driven test feeding a fixed latency vector through
`calculateStatistics` and asserting exact values for median, p95, MAD, score and
CI bounds.

### P1-15 The production scheduler is selected by reflect-comparing a test seam

```go
if reflect.ValueOf(runTargetFunc).Pointer() != reflect.ValueOf(runTarget).Pointer() {
    return runProtocolLegacy(ctx, targets, queries, opts)
}
return runProtocolFair(ctx, targets, queries, opts)
```

**24 test sites** replace `runTargetFunc`, and every one of them therefore
exercises `runProtocolLegacy` — not the scheduler that ships. The two differ
observably: legacy returns only dispatched targets via `dispatchedResults`, while
fair returns *all* runners including never-prepared ones. So the end-to-end
cancellation semantics CI asserts are not the ones the binary produces.
(`runProtocolFair` and `runQueryRound` are reached by a few narrower tests, so
this is "the wrong path is asserted", not "never tested".)

**Fix:** make the scheduler an explicit option rather than an inferred one, and
add end-to-end cancellation assertions against the fair path.

---

## P2 — Accuracy, safety and usability

### P2-1 A local stub or forwarder is ranked and recommended like a real resolver

`systemdns` detects the stub and labels it (`"System DNS stub"`, policy
`"local forwarding (upstream unknown)"`) but the classification never leaves the
package:

```
$ grep -rn "stub" --include=*.go internal/ cmd/ | grep -v _test.go
internal/systemdns/systemdns.go:56,198,199,201     # comment + strings only
```

`makeRankings` admits any target with `Scored > 0` and orders purely by
`ScoreMS`; nothing warns. On systemd-resolved, `--include-system` will put
`127.0.0.53` at rank 1 with a sub-millisecond median and mark it `RECOMMENDED`,
because a cache hit excludes the upstream cost entirely. Observed here: the local
forwarder ranked **2nd of 11**, above eight public resolvers, `QUALIFIED`.

### P2-2 The tie flag never reaches the human-facing table

```
$ grep -n "\.Tie\b\|\"tie\"" internal/report/report.go
212:  … "recommended", "tie",          # CSV header
233:  strconv.FormatBool(stats.Tie), … # CSV value
```

That is the only use — verified live, a real table report contains **zero**
occurrences of "tie". The default output presents a strict 1..N ranking and a
single `RECOMMENDED` winner while discarding the flag saying the ordering is not
distinguishable. (Partly mitigated: the paired block prints `NO CLEAR DIFFERENCE`
— but only for policy-local pairings, not the headline ranking.)

Note when fixing: `RECOMMENDED (tied)` would print **uncoloured**, since
`styledStatus` switches on exact strings and falls through `default`. Either add
the new strings to that switch or use a separate column. Budget for `table.txt`
and `details.txt` regeneration on top of `report.json`.

### P2-3 Non-interactive progress never reports progress

`renderUpdateLocked` prints each phase only the first time it is seen — and the
first update of a phase always has `completed == 0`:

```
progress dot: preparing 0/20 targets
progress dot: measuring 0/80 exchanges
tested dot 20/20 targets
```

That is the redirected/CI path, exactly where the line has to carry information.

### P2-4 The default table is dominated by uninformative rows

From one live run (`--protocol udp,tcp,dot`, host without IPv6): **30 of 60**
comparison rows were IPv6 `FAILED` rows already summarised by the collapsed
warning, and the paired block was **30 rows, 15 of them self-comparisons** (see
P1-3 for the root cause).

### P2-5 Bundled Cloudflare DoH profile authenticates TLS against the wrong name

```yaml
doh:
  server_name: one.one.one.one
  url: https://cloudflare-dns.com/dns-query
```

Checked programmatically, it is the **only** mismatch among all 10 bundled DoH
profiles. Because `doHFactory.Open` installs `DialTLSContext`, `http.Transport`
does no verification of its own — the certificate is checked for
`one.one.one.one` while the request authority is `cloudflare-dns.com`. This
contradicts METHODOLOGY.md's own promise that *"an explicit `server_name` is the
only way to opt into a different TLS identity"*. It works today only because
Cloudflare's certificate covers both.

### P2-6 Unsafe and pseudo query types are accepted

`parseQueryTypes` rejects only `ANY`. Verified accepted: **AXFR, IXFR, OPT, TSIG,
MAILA**. Zone transfers against public resolvers are abusive (and refused, so the
data is meaningless); `OPT`(41) and `TSIG`(250) are pseudo-RRs that are not valid
QTYPEs. The error string already says "unsupported or **unsafe**" — the deny-list
is just incomplete.

### P2-7 Shipped man page has drifted

`docs/speedns.1` is what the Debian/RPM/APK/Arch packages install, and README
does not ship in them. It is missing **exit code 4** (assertion failure, which
`exitCodeForError` returns and both README and METHODOLOGY document) and **7 of
23 flags**: `--assert`, `--family`, `--cache-miss`, `--cache-miss-sample`,
`--profile-view`, `--redact-system`, `--no-defaults`.

### P2-8 Release "reproducibility gate" never touches what ships

`release.yml` builds `release --snapshot --clean --skip=publish --skip=sign`
twice and compares those two to each other, then separately builds
`release --clean --skip=publish` to produce the actual artifacts. The comparison
never sees the published assets, yet the step name and the
`speedns-release-verification` artifact present it as evidence about the release.

### P2-9 README's provenance command names a file that is never produced

`.goreleaser.yaml` has `project_name: SpeeDNS` and
`name_template: "{{ .ProjectName }}_{{ .Version }}_…"`, so archives are
`SpeeDNS_1.2.3_linux_amd64.tar.gz`. README says:

```sh
gh attestation verify speedns_VERSION_OS_ARCH.tar.gz --repo crypt0rr/SpeeDNS
```

The lowercase prefix is correct only for the nfpm *packages* (`package_name:
speedns`), which README uses correctly elsewhere. So the one command that proves
provenance — and which RELEASE_CHECKLIST.md requires before announcing — fails
with file-not-found on any case-sensitive filesystem.

### P2-10 README promises Homebrew cask installs on Linux

README's primary install path says the cask works "on macOS or Debian/Linux with
Linuxbrew". Homebrew on Linux does not support casks at all, and
`scripts/homebrew-cask.sh` emits `on_linux` stanzas that can never be reached —
along with two `checksum_for` lookups that exist only to feed them. Nothing in CI
runs `brew install --cask`.

### P2-11 Everything else verified at P2

| Item | Evidence |
|---|---|
| `--include-system` on Windows opens `/etc/resolv.conf` and aborts | no `_windows.go` in `internal/systemdns`; `Discover` branches darwin vs everything-else |
| `--cache-miss-sample 20 --sample 5` measures 5 names while provenance reports 20 | live JSON: `sample_size: 5`, `corpus_entries: 20`, no warning |
| `--output /dev/null` (also FIFOs, `/proc/self/fd/1`, read-only dirs) fails | `create temporary output file: open /dev/.null.speedns-…: permission denied` |
| Underscore service labels rejected while `--type SRV` is accepted | `normalize("_sip._tcp.example.com")` → `idna: disallowed rune U+005F`; SRV/TLSA names are unreachable |
| One invalid name aborts the entire corpus | `validateInputs` returns on first error; no skip-and-warn |
| Table alignment uses `text/tabwriter` (rune counts, not display width) | wide CJK cells shear every column right; `main.go` already has a correct `displayWidth()` that is not shared |
| Bootstrap replicates with zero successes return the `2 × timeout` sentinel | outside the score function's range; inflates the CI upper bound, which feeds tie detection |
| Targets prepared strictly sequentially in target-ID order | cold medians and warm-session idle age biased by catalog position |
| UDP re-resolves a hostname target every query, inside the timed region | `udpSession.Query` builds a fresh `dns.Client` per call |
| DoT TLS config omits the `dot` ALPN token | DoQ sets `doq`, DoH sets `h2`/`http/1.1`; RFC 8310 says SHOULD, ALPN-routing middleboxes can require it |
| Catalog `addresses:` never syntax-checked | `addresses: ["192.0.2.53:5353"]` validates, then fails every query as if the resolver were down |
| IPv6 nameservers with a zone ID dropped in discovery | `net.ParseIP` has no zone support; `fe80::1%en0` → "no system nameservers found" |
| `--family auto` discards loopback system resolvers | loopback is never global unicast, so it never joins the allow-set, yet the filter applies to it |
| `--assert winner=ID` not validated against loaded profiles | a typo becomes exit 4 ("does not win") instead of exit 2 |
| Fuzz targets assert only "does not panic" | all four discard return values; `validateResponse` is the anti-spoofing boundary and its verdict is never checked. Fuzzed here for 45–60 s each: no crashes, but **21 / 75 / 67 / 257 new interesting inputs**, so the committed corpora are shallow and CI's seed-only run explores very little |
| `systemdns`'s only real-OS paths are assertion-free coverage filler | `TestSystemSourceHelpers` opens the host's real `/etc/resolv.conf` and shells out to real `scutil`, discarding both — non-hermetic *and* unverified |
| Subcommand wiring unasserted | `_ = newRootCommand()` with no assertion; deleting the `corpus` subcommand keeps the suite green |
| Warnings passed between packages as pre-formatted strings, re-parsed by prefix | change the label format in `benchmark` and `isTargetWarningWithOptions` stops matching; compact (default) table output degrades silently |
| CLI report dispatch has behaviourally identical branch arms that route around the package's own test seams | every CLI test injecting a write failure is silently skipped for redacted and profile-view runs |

---

## P3 — Hygiene and polish

| Item | Note |
|---|---|
| No static analysis beyond `go vet` | `staticcheck` finds 2 real issues on `main`: `benchmark.go:549` SA4011 ineffective `break` inside `select` (masked by the following ctx check; the sibling loop uses a correct labelled break), and `transport/coverage_test.go:610` SA4006 dead assignment. `shellcheck` is clean but is not run in CI either |
| Coverage is partly unasserted | Removing `SetDeadline` from the context-deadline branch of `doqSession.Query` leaves `go test ./internal/transport/` **green** — that is the SA4006 above: the test reassigns `fakeStream` and never reads it, so the branch runs unasserted |
| No golden regeneration path | `golden_test.go` says "regenerate the fixture intentionally" but offers no `-update` flag; four files are hand-edited |
| `TestTCPSessionReusesConnection` never checks reuse | two `err == nil` checks; `LastQueryReconnected()` exists and is asserted everywhere else |
| No DNSSEC capability | the DO bit is never set and there is no `--dnssec` flag, yet the Policy column asserts "+ DNSSEC" as fact from a YAML string. The most common non-latency question about a resolver cannot be answered |
| `.goreleaser.yaml` `homebrew_casks:` is dead config | duplicates and diverges from `scripts/homebrew-cask.sh`; unreachable only because every invocation passes `--skip=publish`. If that is ever dropped, GoReleaser publishes its own differently-shaped cask over the working one |
| `--output` files are created `0600` | `os.CreateTemp` mode survives the rename; differs from shell redirection |
| Ctrl-C prints `context canceled` | raw error text; exit 130 is correct |
| Warm-latency timer includes post-query bookkeeping | `time.Since(started)` is read *after* `sessionQueryReconnected()` (a mutex acquisition) and `cancel()`; sub-microsecond, but METHODOLOGY says "until the validated response or error returns" |
| Repeated Ctrl-C cannot force-quit | `signal.NotifyContext` keeps the handler registered, suppressing the default terminate action. Mechanically true; **not demonstrated as harmful** — shutdown completed in ~1 s here |
| DoH error paths don't drain the body | drops the keep-alive connection on non-200 |
| `streamSession` / `doqSession` duplicate the framed exchange | the copies have already diverged on deadline computation |
| Default ports defined twice | `defaultPort()` vs an inline map in `ParseResolverFlag` |
| `README` says `man ./speedns.1` | the archive stores it at `docs/speedns.1` |
| Loop-invariant work per iteration | redaction map rebuilt per CSV row; winner map rebuilt per assertion |
| Everything under `internal/` | the schema'd report contract has no Go consumer path; a CI system must exec the binary and re-derive types that already exist |

---

## Plan

### Batch 1 — unblock

P0-1 (corrected trim) · P1-1 (all four `omitempty` fields) · P1-2 · P2-7 man page
· Go-version matrix in CI.

Prototyped and verified together in a scratch clone, with P1-7, P1-8 and P1-9:
`go build` OK, `go test ./...` **passes on Go 1.25, 1.26 and 1.27**, `go vet`
clean, `-race` clean. Diff is 67 insertions across 7 files. Companion edits:
regenerate `internal/report/testdata/golden/report.json` (7 lines) and update two
order assertions in `internal/benchmark/coverage_test.go`. Coverage lands at
99.9% — two small tests for the new fallback branches (`protocolOrder` with an
unknown protocol, `answersQuestion` with `len(Question) != 1`) restore the gate.

The patch is checked in beside this file as `speedns-p0-p1-fixes.patch`; it
applies cleanly to a pristine tree (`git apply --check` OK) and the suite passes
on Go 1.25 and 1.27 after applying.

### Batch 2 — restore trust in the numbers

P1-3 policy key · P1-4 paired-CI minimum · P1-7 NODATA (+ METHODOLOGY divergence
section) · P1-9 order **with** P1-10 cache-miss · P1-13 DoH reconnects · P1-14
score-engine test · P2-1 stub handling · P2-2 surface ties.

These change what the tool *reports* and should ship with a METHODOLOGY.md pass.

### Batch 3 — gates and pipelines that lie

P1-5 `--assert` protocol coverage (from `report.Targets`, not `Provenance`) ·
P1-6 assertion scoping · P1-15 scheduler seam · the publisher fixture rework ·
P2-8 reproducibility gate.

One theme: a check that reports success on inputs it never sees.

### Batch 4 — safety and UX

P1-11 redirect cap · P1-12 sanitisation (value-level, before `csvCell`) ·
P1-8 family auto **with** the explicit-profile exemption · P2-5 Cloudflare
`server_name` · P2-6 query-type deny-list · P2-3 progress · P2-4 table noise ·
P2-9/P2-10 install docs · the P2-11 table.

### Batch 5 — hygiene

Fix SA4011 and SA4006 **first**, then add `staticcheck` and `shellcheck` gates.
Add a golden `-update` flag. Work the P3 table.

### Ordering constraints

1. **P0-1 before the Go matrix**, same PR or earlier — otherwise `stable` is red
   on day one.
2. **The matrix needs the artifact name fixed in the same change.** `ci.yml`
   uploads `coverage-${{ matrix.os }}` with `if-no-files-found: error`; adding a
   go-version axis makes two jobs claim one name, which `upload-artifact` v4+
   rejects. Branch-protection check names change too.
3. **P1-1 and P1-2 land with the golden regeneration**, and P1-1 must be complete
   (all four fields). A `Tie`-only intermediate still leaves the publisher
   rejecting failed-run evidence, so "Batch 1 unblocks the pipeline" would be
   false until a second commit.
4. **The fixture rework lands after** complete P1-1/P1-2, not before — against
   today's encoder it fails immediately, which is the point, but it would block
   the branch.
5. **P1-9 and P1-10 land together.** Order alone relocates the cache-warming bias
   from `doh` onto `udp`, the baseline transport, and can flip the direction of
   the headline cache-miss comparison.
6. **P1-5 lands after P1-7 and P1-9 settle**, or its blast radius is measured
   against a moving baseline.
7. **Fix SA4011/SA4006 before enabling `staticcheck`.**

---

## Two structural suggestions

**Contract tests, not fixture tests.** P1-1, P1-2 and the fixture problem behind
them share one cause: components that must agree — the Go encoder, `schema/*.json`,
and `scripts/publish-live-results.py` — are only ever tested against hand-written
data. One test that runs the real encoder (including a fully-failed target),
validates against both shipped schemas, and feeds the result to the real publisher
would have caught all three before merge.

**The 100% coverage gate is doing less than it looks.** It is a useful floor and
worth keeping, but 6 of 7 scoring mutants survive it, and several
`*coverage_test.go` blocks exist to reach lines rather than to check behaviour.
A small mutation pass over the statistics and classification code — where a
wrong-but-consistent constant is most expensive and least visible — would be worth
more than the last few percent of statement coverage.

---

## Verified as sound (checked, no action needed)

- **UDP EDNS0 buffer size** — the query advertises 1232 in the OPT record and
  `miekg/dns` copies that into `co.UDPSize`; no silent truncation.
- **Resolver YAML parsing** — `KnownFields(true)`, explicit multiple-document
  rejection, thorough `Validate` (duplicate IDs and addresses, port ranges,
  `bootstrap_addresses` refused on UDP/TCP, `server_name` required for DoT/DoQ).
- **JSON schema discipline** — `additionalProperties: false` at every level; live
  output including `--raw` validates cleanly against `schema/report-v1.json`.
- **CSV formula injection** — guarded.
- **DoH hardening** — cross-origin redirects refused, 1 MiB body limit, 64 KiB
  header limit, `CloseIdleConnections` on close. (Hop count is the gap — P1-11.)
- **Atomic `--output`** — temp file, `Sync`, rename, discard-on-error.
- **Signal handling** — SIGINT produced a complete partial report, an
  `interrupted` warning, `INCOMPLETE` targets excluded from ranking, exit 130.
- **Exit codes** — 0 / 2 / 3 / 4 / 130 all verified live.
- **Machine-readable output purity** — `--format json` wrote valid JSON to stdout
  and **zero bytes** to stderr.
- **Fuzz targets** — no crashes in 45–60 s each (466k / 604k / 732k / 168k execs).
- **Shell scripts** — every script sets `set -euo pipefail`; `shellcheck` clean at
  all levels.
- **CI/CD supply chain** — all actions SHA-pinned, minimal permissions, release
  behind an environment gate, Sigstore signing plus GitHub attestations,
  `govulncheck` and CodeQL scheduled.

*Note: DoH/DoT/DoQ live smoke runs failed in this sandbox (blocked outbound
443/853 and no system DNS resolution for `dns.google` / `dns.quad9.net`). That is
an environment limit, not a SpeeDNS defect — UDP and TCP smoke runs passed.*

---

## Traceability

Every finding above is tracked. Four P1s became issues because they need a
design decision before code can be written; everything else is an open pull
request with offline regression tests, docs updates, and all five CONTRIBUTING
gates green on the CI-pinned toolchain.

| Finding | Summary | Tracked as |
|---|---|---|
| P0-1 | Root label trimmed after IDNA; suite red on Go 1.27 | #109 ✅ |
| P1-1 | omitempty hides fields the live-results contract requires | #110 ✅ #123 ✅ |
| P1-2 | rankings: null violates report-v1.json | #110 ✅ |
| P1-3 | policy is an unvalidated grouping key | issue #105 |
| P1-4 | Paired-effect CIs have no minimum-sample gate | #115 ✅ |
| P1-5 | --assert passes when a protocol produced no ranking | issue #106 |
| P1-6 | Numeric --assert applies to the whole tie group | issue #107 |
| P1-7 | Canonical NODATA classified as an answer | #111 ✅ |
| P1-8 | --family auto false-positives on ULA / Tailscale | #116 ✅ |
| P1-9 | Protocols measured in undocumented order | #119 ✅ |
| P1-10 | --cache-miss only cold for the first protocol group | issue #108 disclosed in #119 ✅ |
| P1-11 | Hostile DoH endpoint gets unbounded redirects | #112 ✅ |
| P1-12 | Untrusted text reaches terminal and CSV unescaped | #120 ✅ |
| P1-13 | DoH exempt from reconnect detection | #117 ✅ |
| P1-14 | Scoring engine not pinned by any test | #114 ✅ |
| P1-15 | Scheduler selected by reflect-comparing a test seam | #121 ✅ |
| P2-1 | Local stub ranked and recommended | #126 ✅ |
| P2-2 | Tie flag never reaches the table | #124 ✅ |
| P2-3 | Non-interactive progress never reports progress | #127 ✅ |
| P2-4 | Default table dominated by uninformative rows | #133 ✅ |
| P2-5 | Cloudflare DoH authenticates the wrong name | #118 ✅ |
| P2-6 | Unsafe and pseudo-RR query types accepted | #129 ✅ |
| P2-7 | Man page drifted; exit code 4 missing | #113 ✅ |
| P2-8 | Release reproducibility gate never checks what ships | #128 ✅ |
| P2-9 | README names an archive that is never produced | #113 ✅ |
| P2-10 | README promises Homebrew casks on Linux | #113 ✅ |
| P2-11 | Windows --include-system opens /etc/resolv.conf | #131 ✅ |
| P2-11 | IPv6 zone IDs dropped in discovery | #131 ✅ |
| P2-11 | --family auto discards loopback resolvers | #131 ✅ |
| P2-11 | Catalog addresses never syntax-checked | #130 ✅ |
| P2-11 | --assert winner=ID never validated | #130 ✅ |
| P2-11 | --output cannot write non-regular files | #132 ✅ |
| P2-11 | --sample silently truncates cache-miss corpus | #132 ✅ |
| P2-11 | Underscore service labels rejected | #134 ✅ |
| P2-11 | One invalid name aborts the whole corpus | #143 ✅ |
| P2-11 | Table aligned by rune count, not display width | #138 ✅ |
| P2-11 | Bootstrap 2xtimeout sentinel distorts ties | #135 ✅ |
| P2-11 | Sequential preparation biases by catalog position | #135 ✅ |
| P2-11 | UDP re-resolves a hostname every query | #122 ✅ |
| P2-11 | DoT omits the dot ALPN token | #122 ✅ |
| P2-11 | Fuzz targets assert only no-panic | #136 ✅ |
| P2-11 | systemdns real-OS paths unasserted, non-hermetic | #136 ✅ |
| P2-11 | Subcommand wiring unasserted | #136 ✅ |
| P2-11 | Warnings passed as strings, re-parsed by prefix | #139 ✅ |
| P2-11 | Report dispatch arms identical, bypass test seams | #143 ✅ |
| P3 | No static analysis beyond go vet (SA4011, SA4006) | #125 ✅ |
| P3 | DoQ ctx-deadline branch unasserted (mutation survived) | #125 ✅ |
| P3 | No golden fixture regeneration path | #136 ✅ |
| P3 | TestTCPSessionReusesConnection never checks reuse | #143 ✅ |
| P3 | No DNSSEC capability | #141 ✅ |
| P3 | Dead homebrew_casks config in .goreleaser.yaml | #140 ✅ |
| P3 | --output files created 0600 | #137 ✅ |
| P3 | Ctrl-C prints 'context canceled' | #137 ✅ |
| P3 | Warm timer includes post-query bookkeeping | #137 ✅ |
| P3 | Repeated Ctrl-C cannot force-quit | #137 ✅ |
| P3 | DoH error paths do not drain the body | #137 ✅ |
| P3 | streamSession/doqSession duplicate the framed exchange | #140 ✅ |
| P3 | Default ports defined twice | #140 ✅ |
| P3 | README says man ./speedns.1 | #113 ✅ |
| P3 | Loop-invariant work rebuilt per iteration | #140 ✅ |
| P3 | Report contract has no Go consumer path | #142 — closed; JSON schema remains the contract |

**36 pull requests merged, 1 closed, 4 issues open.** ✅ marks merged.

All of these are merged except **#142** (public Go report types), closed in
favour of keeping `schema/report-v1.json` as the sole published contract.
`main` is green on Go
1.25, 1.26 and 1.27 with gofmt, vet, staticcheck, shellcheck, `go mod tidy`,
`-race` and 100% statement coverage all clean.