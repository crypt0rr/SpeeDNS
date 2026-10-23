# SpeeDNS test fixtures

The regression suite is offline and deterministic. It does not depend on a
public resolver or on the embedded Tranco corpus being refreshed.

Run the ordinary suite and quality gates with:

```sh
go test -count=1 ./...
go test -count=1 -race ./...
go vet ./...
bash scripts/coverage.sh
```

The `internal/report/testdata/golden/` files lock down compact tables, detailed
tables, JSON, and CSV. The golden report contains a qualified UDP target, a
failed TCP target, a warning, and a divergence detail. JSON is checked for its
additive divergence section; CSV remains the aggregate schema.

Regenerating the golden fixtures is a deliberate, two-step action. Run the
suite first without the flag and read the reported difference, then rewrite the
fixtures only once the new output is the intended output:

```sh
go test -count=1 ./internal/report -run TestGoldenReports
go test -count=1 ./internal/report -run TestGoldenReports -update
```

Always review `git diff internal/report/testdata/golden/` before committing a
regenerated fixture. Never regenerate to make a failing test pass.

The JSON writer streams the `results` array one element at a time instead of
encoding the report as one value, and must stay byte-identical to that single
encoding. Besides the golden JSON, `TestStreamedJSONMatchesTheEncoderOnFixtures`
and `TestStreamedJSONMatchesTheEncoderOnRandomReports` compare every streamed
byte with what one `json.Encoder` writes for the whole document, over the
fixture reports, hundreds of random reports and a multi-megabyte `--raw`
report. `TestJSONReportMembersMatchTheStreamer` pins the document's top-level
members, so one added to `JSONReport` fails until the streamer writes it too.
The confidence-interval bootstraps read each replicate's percentiles
from rank counts instead of sorting the resample; the previous implementation
is kept in `internal/benchmark/bootstrap_equivalence_test.go`, and
`TestRankCountBootstrapMatchesSortedResampling` requires bit-identical
intervals from both over random sample vectors and seeds, next to the pinned
interval in `scoring_test.go`.

Go benchmarks compare those two paths with the ones they replaced, and query
construction from an already-normalized corpus with normalizing it again. They
are offline, assert nothing about timing, and run only when asked:

```sh
go test -run '^$' -bench . -benchmem ./internal/benchmark ./internal/report
```

`TestDeterministicResolverFixtureCoversBenchmarkOutcomes` uses in-memory
resolver sessions to exercise the full benchmark scheduler and statistics
path. Its targets cover:

- a steady usable answer that can be ranked;
- same-policy response-class divergence and plurality exclusion;
- a different declared policy returning `NXDOMAIN`, which is not compared to
  the unfiltered group;
- SERVFAIL, truncation, and packet-loss observations that remain visible and
  penalized; and
- a connection/open failure that produces a failed, unranked target.

The fuzz harnesses cover domain normalization, resolver URI/YAML parsing, and
DNS response validation. Their seed corpus runs in normal `go test`; longer
fuzzing runs are optional and remain offline.

Apart from domain normalization these harnesses are property tests, not
panic checks. `FuzzValidateResponseMatchesRequest` asserts the biconditional
for the anti-spoofing boundary: a response is accepted exactly when it carries
the response flag, one question matching the requested name, type, and class
`IN`, and a transaction ID that matches the query (or is zero on DoH and DoQ).
Malformed wire data is handed to `validateResponse` instead of being skipped.
`FuzzParseResolverFlagInvariants` asserts that an accepted `NAME=URI` flag
yields exactly one transport for the URI scheme, with the right default port
and with TLS or HTTP settings only where the scheme needs them, so no resolver
can silently gain a second transport; an accepted explicit port is 1-65535,
and an accepted URI carries no user credentials and a printable NAME.
`FuzzLoadYAMLInvariants` asserts that every accepted resolver file revalidates
unchanged, declares at least one transport per profile, carries `url` and
`server_name` only on protocols that read them, stores `server_name` trimmed,
and has printable ids, names, owners and addresses. The seed corpora in
`internal/catalog/testdata/fuzz/` pin the interesting accept and reject paths.

Transport recovery runs against local fixtures bound to `127.0.0.1` only,
because macOS runners cannot bind other loopback addresses: bootstrap
candidates that accept a connection and never speak, a TCP proxy that silences
an established HTTP/2 connection without closing it, and a DoQ server that
withholds its FIN. They use timeouts of a few hundred milliseconds and assert
outcomes, such as which query reconnected and which connections the server
saw closed, rather than durations.
