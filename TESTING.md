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
