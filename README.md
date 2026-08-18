# SpeeDNS

SpeeDNS (`speedns`) is a read-only CLI for comparing recursive DNS resolvers from your current network. It measures UDP, TCP, DNS-over-HTTPS, DNS-over-TLS, and dedicated DNS-over-QUIC independently, then shows which eligible resolver is fastest and reliable enough to recommend.

It never changes the machine's DNS configuration, needs no root privileges, and sends no telemetry.

## What it measures

The default run samples 100 names from the embedded, versioned 1,000-name Tranco corpus and sends A and AAAA queries. Use `--full` to test the complete corpus. Every selected resolver receives the same domain/type matrix and the same randomized ordering.

Encrypted transports are reported in two parts:

- cold first-query latency, including a fresh connection/handshake;
- warm query latency over a reused connection.

Resolvers are ranked separately per transport. SpeeDNS does not claim that a UDP result and a DoH result are directly interchangeable.

The bundled catalog currently includes Google, Quad9, Cloudflare, and DNS4EU profiles. Filtering policy is shown beside the owner because a protective resolver is not behaviorally equivalent to an unfiltered resolver.

## Build from source

Requires Go 1.25 or newer. Builds are pure Go and do not require a runtime dependency.

```sh
go build -trimpath -ldflags "-s -w" -o speedns ./cmd/speedns
./speedns --help
```

## Usage

Run the default benchmark:

```sh
./speedns
```

Run a short, reproducible UDP comparison:

```sh
./speedns --protocol udp --sample 25 --type A --seed 42
```

Run all bundled protocols against the complete corpus:

```sh
./speedns --full --details
```

Include the currently configured system resolver as a baseline:

```sh
./speedns --include-system
```

The system resolver is read only. On Debian/Linux SpeeDNS reads `/etc/resolv.conf`; on macOS it uses `scutil --dns` and falls back to `/etc/resolv.conf`.

Export results for automation:

```sh
./speedns --format json --output result.json
./speedns --format csv --output result.csv
./speedns --format json --raw --output result-with-samples.json
```

One-off custom endpoints use `NAME=URI` syntax:

```sh
./speedns --no-defaults \
  --resolver office=udp://10.0.0.53:53 \
  --resolver private-dot=tls://dns.example.net:853 \
  --resolver private-doh=https://dns.example.net/dns-query \
  --resolver private-doq=quic://dns.example.net:853
```

For a complete profile with an owner, policy, address, TLS name, and multiple transports, use YAML:

```sh
./speedns --resolver-file resolvers.yaml
```

See [`resolvers.example.yaml`](resolvers.example.yaml) for the schema.

Custom domain lists are newline-delimited. Blank lines and lines beginning with `#` are ignored, names are case-normalized, and duplicates are removed:

```sh
./speedns --domains my-domains.txt --sample 200
```

## Interpreting results

The primary comparison is the warm query latency. Cold latency tells you what a newly started client pays for connection setup. The ranking score is:

```text
0.60 × median + 0.40 × p95 + failure_rate × timeout
```

Lower is better. A result is marked recommended only when it has at least 20 comparable samples and at least 99% successful responses. Divergent response classes—such as one filtered/NXDOMAIN response and one normal answer—are reported and excluded from latency scoring for that query.

Short runs can still show a provisional fastest result, but SpeeDNS labels it separately and does not present it as a recommendation until the evidence threshold is met.

`—` means that a resolver does not advertise that transport. `FAIL` means it was configured for the transport but the connection or DNS exchange failed. SpeeDNS never silently falls back from one protocol to another.

## Default resolver profiles

| Address | Owner | Policy | Encrypted names |
| --- | --- | --- | --- |
| 8.8.8.8, 8.8.4.4 | Google | unfiltered | `dns.google` |
| 9.9.9.9 | Quad9 | threat blocking + DNSSEC | `dns.quad9.net` |
| 9.9.9.10 | Quad9 | unfiltered | `dns10.quad9.net` |
| 1.1.1.1 | Cloudflare | unfiltered | `one.one.one.one`, `cloudflare-dns.com` |
| 1.1.1.2 | Cloudflare | malware filtering | `security.cloudflare-dns.com` |
| 86.54.11.1 | DNS4EU / JOINDNS4.eu | protective | `protective.joindns4.eu` |
| 86.54.11.12 | DNS4EU / JOINDNS4.eu | protective + child protection | `child.joindns4.eu` |
| 86.54.11.13 | DNS4EU / JOINDNS4.eu | protective + ad blocking | `noads.joindns4.eu` |
| 86.54.11.100 | DNS4EU / JOINDNS4.eu | unfiltered | `unfiltered.joindns4.eu` |

Dedicated DoQ is currently configured for Quad9. DoH over HTTP/3 is a separate transport from dedicated DoQ and is not mislabeled as DoQ in v1.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
bash scripts/coverage.sh
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./cmd/speedns
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/speedns
```

`scripts/coverage.sh` runs each package with atomic instrumentation, merges the profiles, and fails unless total statement coverage is exactly 100.0%. CI runs this gate on both Ubuntu and macOS.

## GitHub automation

All repository automation lives in `.github/` and runs on GitHub-hosted runners:

- `CI` runs formatting, module verification, unit/integration tests, `go vet`, race detection, the 100% coverage gate, four pure-Go cross-builds, and a GoReleaser snapshot on every push and pull request.
- `CodeQL` uploads Go code-scanning results on pushes, pull requests, and a weekly schedule.
- `Go security` runs Go's vulnerability reachability scan on pushes, pull requests, and a weekly schedule.
- `Live DNS smoke` checks one official endpoint for UDP, TCP, DoH, DoT, and DoQ weekly. It is deliberately non-blocking and stores its JSON/log evidence as a workflow artifact; normal CI never depends on public DNS.
- `Dependabot` opens weekly update pull requests for Go modules and GitHub Actions.

The release workflow runs for `v*` tags and can also be dispatched with an existing tag. It runs the full preflight again, then creates a draft GitHub release containing macOS and Linux archives, Debian packages, checksums, SBOMs, and keyless Sigstore signatures. Add a repository secret named `HOMEBREW_TAP_TOKEN` with write access to `crypt0rr/homebrew-tap` before using the release workflow; the automatically provided `GITHUB_TOKEN` handles the release in this repository.

The recommended first public build is a prerelease such as `v0.1.0-alpha.1`. GoReleaser accepts SemVer prerelease tags and marks them as prereleases automatically; `v1.0.0` should wait until the hosted CI, release artifacts, macOS/Debian installs, and real-world DNS comparisons have been exercised by testers.

To publish the first prerelease after the GitHub CI run is green:

```sh
git tag -a v0.1.0-alpha.1 -m "SpeeDNS v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

The `workflow_dispatch` controls on CI, CodeQL, security, and live smoke are available from the repository Actions tab. The release workflow's manual input is an existing `v*` tag, so it cannot accidentally release an arbitrary branch.

## License

MIT. The embedded Tranco snapshot carries source/date metadata in `data/domains.meta.json`; retain that attribution when updating or redistributing the corpus.
