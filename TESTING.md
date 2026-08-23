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
`IN`, and a transaction ID that matches the query (or is zero on DoQ).
Malformed wire data is handed to `validateResponse` instead of being skipped.
`FuzzParseResolverFlagInvariants` asserts that an accepted `NAME=URI` flag
yields exactly one transport for the URI scheme, with the right default port
and with TLS or HTTP settings only where the scheme needs them, so no resolver
can silently gain a second transport. `FuzzLoadYAMLInvariants` asserts that
every accepted resolver file revalidates unchanged. The seed corpora in
`internal/catalog/testdata/fuzz/` pin the interesting accept and reject paths.
