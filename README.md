# SpeeDNS

SpeeDNS (`speedns`) is a read-only command-line DNS benchmark. It compares recursive DNS resolvers from your current network over UDP, TCP, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and dedicated DNS-over-QUIC (DoQ), then shows which resolver is fastest for each transport.

SpeeDNS does not change your system DNS settings, requires no root privileges, and sends no telemetry.

## Install

Prebuilt macOS and Linux binaries and packages are published with each release on the [GitHub Releases page](https://github.com/crypt0rr/SpeeDNS/releases). Choose the archive for your platform and architecture. Releases include:

- macOS Intel (`amd64`) and Apple silicon (`arm64`);
- Linux `amd64` and `arm64` archives;
- Debian, RPM, APK, and Arch Linux packages for Linux `amd64` and `arm64`.

The package files are independent release assets. Verify the release
checksums and Sigstore signature before installing. For example:

```sh
# Fedora/RHEL and compatible distributions
sudo rpm -Uvh ./speedns_VERSION_linux_amd64.rpm

# Alpine Linux; --allow-untrusted is needed because this is a downloaded
# package, not an APK repository package with a local Alpine repository key.
sudo apk add --allow-untrusted ./speedns_VERSION_linux_amd64.apk

# Arch Linux
sudo pacman -U ./speedns_VERSION_linux_amd64.pkg.tar.zst
```

Use the `arm64` asset on a 64-bit ARM host. Package-manager signatures are
not substituted for the release checksum and Sigstore verification described
below.

### Homebrew / Linuxbrew

Install the SpeeDNS cask from the tap on macOS or Debian/Linux with Linuxbrew:

```sh
brew tap crypt0rr/speedns
brew install --cask speedns
```

After installation, verify the command and run a benchmark:

```sh
speedns version
speedns
```

Upgrade or uninstall it with Homebrew:

```sh
brew upgrade --cask speedns
brew uninstall --cask speedns
```

The current prerelease macOS binaries are not Apple-signed or notarized. On
first use, macOS may show a Gatekeeper warning. If you trust the release,
open **System Settings → Privacy & Security**, select **Open Anyway**, and
then run `speedns` again. Do not disable Gatekeeper globally.

To build from source, install [Go 1.25 or newer](https://go.dev/dl/):

```sh
git clone https://github.com/crypt0rr/SpeeDNS.git
cd SpeeDNS
go build -trimpath -ldflags "-s -w" -o speedns ./cmd/speedns
./speedns version
```

The build is pure Go and has no runtime dependencies.

### Shell completion and the man page

Generate a completion script for your shell:

```sh
speedns completion bash >speedns.bash
speedns completion zsh >_speedns
speedns completion fish >speedns.fish
speedns completion powershell >speedns.ps1
```

Release archives include `speedns.1`; Debian packages install it as
`/usr/share/man/man1/speedns.1`. View it directly from an extracted archive
with `man ./speedns.1`.

The canonical Go module path is `github.com/crypt0rr/SpeeDNS`. Install the
latest published command directly with:

```sh
go install github.com/crypt0rr/SpeeDNS/cmd/speedns@latest
```

Older releases used `github.com/crypt0rr/dns-speedtest`. GitHub redirects that
historical path, and existing users can continue to use old release tags while
migrating imports. New source references and release metadata use the canonical
`SpeeDNS` path.

### Verify a downloaded release

From the release assets directory, verify the checksums and the keyless
Sigstore signature on the checksum file:

```sh
sha256sum -c checksums.txt
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/crypt0rr/SpeeDNS/\.github/workflows/release\.yml@refs/(tags/v[^/]+|heads/main)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Release archives also carry a GitHub artifact attestation. With the GitHub CLI,
verify an archive against this repository:

```sh
gh attestation verify speedns_VERSION_OS_ARCH.tar.gz --repo crypt0rr/SpeeDNS
```

Replace the archive name with the exact asset you downloaded. The release
workflow uses the protected `release` environment; maintainers must store
`HOMEBREW_TAP_TOKEN` there and configure required reviewers before publishing.

## Quick start

Run the default comparison:

```sh
./speedns
```

The explicit equivalent is `./speedns run`.

Run a short, reproducible test against UDP resolvers:

```sh
./speedns --protocol udp --sample 25 --type A --seed 42
```

Run every configured transport against all 1,000 bundled names:

```sh
./speedns --full --details
```

Inspect the bundled resolver catalog without running a benchmark:

```sh
./speedns resolvers
```

Show a profile-level transport view for the same resolver/address. This is
useful when comparing the cost of enabling encrypted transports; it includes
the existing score confidence interval and does not replace per-protocol
rankings:

```sh
./speedns --profile-view --protocol udp,tcp,doh,dot,doq --sample 25 --type A
```

## How the comparison works

The complete ranking methodology, scoring denominators, confidence intervals,
interruption behavior, and reproducibility limits are documented in
[`METHODOLOGY.md`](METHODOLOGY.md).

The default run samples 100 names from an embedded, versioned 1,000-name domain list and queries both A and AAAA records. `--full` uses the complete list. Every resolver eligible for the same transport receives the same names, query types, DNS settings, and randomized order.

SpeeDNS reports warm query latency over reused connections and, for encrypted transports, cold first-query latency including connection setup. Results are ranked separately for each transport; a UDP result is not treated as interchangeable with a DoH, DoT, or DoQ result.

The score is lower-is-better. The failure penalty includes transport failures,
timeouts, truncated responses, and DNS resolver errors such as SERVFAIL or
REFUSED:

```text
0.60 × median latency + 0.40 × p95 latency + scoring-failure rate × timeout
```

SpeeDNS keeps three concepts separate: a transport success means that a
validated DNS message was received, a usable response is a normal `NOERROR`
(including NODATA) or `NXDOMAIN` result, and a scored sample is a usable result
that is not divergent from the other resolvers in the same policy group and
was not obtained immediately after a stream reconnect.
Responses such as `SERVFAIL`, `REFUSED`, and other resolver errors are shown in
the results but cannot win latency scoring. This prevents an unhealthy or
blocked resolver from appearing fast merely because it rejects queries
quickly. Valid divergent responses and samples immediately following a stream
reconnect are excluded from the scoring denominator; unusable responses remain
failure-penalized even if they are divergent. See
[`METHODOLOGY.md`](METHODOLOGY.md) for the exact rules.

An endpoint is marked `RECOMMENDED` only when it has at least 20 comparable
samples and at least 99% usable responses. Short runs can show a
`PROVISIONAL` winner, but use a larger sample or `--full` for a more stable
comparison.

Resolvers can have different filtering policies. SpeeDNS compares response
classes only within the same declared policy. Within that group, the largest
plurality is the baseline; an outlier is excluded from comparative latency
scoring. Equal pluralities are reported as ambiguous and all successful
observations in that group are excluded rather than receiving an arbitrary
advantage. The detailed report shows the baseline, class counts, and excluded
observations. This keeps blocking, filtered, `NXDOMAIN`, `NODATA`, `SERVFAIL`,
and `REFUSED` behavior explicit without treating unlike policies as identical.

The human-readable report also shows paired latency effects below the protocol
tables. Within each protocol and policy group, the best-ranked target is the
reference. The effect is the median per-name/type latency difference
(`target - reference`) with a deterministic bootstrap 95% confidence interval.
`NO CLEAR DIFFERENCE` means the interval includes zero, so the measured
difference is not distinguishable from noise. These comparisons explain the
ranking but do not replace the existing score or change rank order. JSON
includes the same information in the additive `paired_effects` section; CSV
keeps its aggregate schema.

## Choosing protocols

Use `--protocol` with one or more comma-separated transports:

```sh
./speedns --protocol udp,tcp,doh,dot,doq
```

The available transports are:

| Name | Transport |
| --- | --- |
| `udp` | Traditional DNS over UDP |
| `tcp` | Traditional DNS over TCP |
| `doh` | DNS over HTTPS using RFC 8484 and HTTP/2 |
| `dot` | DNS over TLS |
| `doq` | Dedicated DNS over QUIC using RFC 9250 |

SpeeDNS does not silently fall back from one protocol to another. The table
shows the complete selected resolver/protocol matrix: an unsupported transport
is shown as `—`, an unavailable transport is `FAILED`, a transport-valid result
that cannot qualify is `INELIGIBLE`, an interrupted target is `INCOMPLETE`, and
a recommendation-eligible result is `QUALIFIED`.

## Default resolvers

Each address is ranked independently. The owner and filtering policy are shown in the terminal report so that unfiltered and protective services can be compared knowingly.

| Address | Owner | Policy | Encrypted hostname |
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

Dedicated DoQ is currently configured for Quad9. SpeeDNS uses TLS 1.3 and
ALPN `doq`, sends an explicit QUIC keepalive at the configured timeout, and
reconnects lazily after a connection or idle-timeout failure. The failed query
is not retried. DoH over HTTP/3 is a separate transport and is not mislabeled
as DoQ.

The bundled resolver profiles use the same strict, versioned YAML model as
custom profiles and are embedded into the binary at build time. SpeeDNS does
not download or read a resolver catalog at runtime.

## Custom resolvers

Add one-off endpoints with repeatable `--resolver NAME=URI` flags. Use `--no-defaults` when you want to test only your own endpoints:

```sh
./speedns --no-defaults \
  --resolver office=udp://10.0.0.53:53 \
  --resolver private-dot=tls://dns.example.net:853 \
  --resolver private-doh=https://dns.example.net/dns-query \
  --resolver private-doq=quic://dns.example.net:853
```

For ownership, policy, multiple addresses, or encrypted endpoints that need a specific TLS name, use a YAML profile:

```sh
./speedns --resolver-file resolvers.yaml
```

See [`resolvers.example.yaml`](resolvers.example.yaml) for the complete schema. A profile can specify ordered `bootstrap_addresses` for DoH, DoT, or DoQ:

```yaml
version: 1
resolvers:
  - id: private
    name: Private DNS
    owner: Example Network
    policy: unfiltered
    addresses:
      - 192.0.2.53
    transports:
      doh:
        url: https://dns.example.net/dns-query
        bootstrap_addresses:
          - 192.0.2.53
```

Bootstrap addresses are connection candidates, not separately ranked resolvers. SpeeDNS retains the configured hostname for HTTPS/TLS certificate validation and tries candidates in order. TLS certificate validation is always enabled.

For a hostname-only custom encrypted endpoint, SpeeDNS uses the operating
system resolver to find the connection address. To make bootstrap deterministic
and avoid that lookup, add `bootstrap_addresses` in a YAML profile; these must
be explicit IPv4 or IPv6 literals and are tried in the order listed. A
`server_name` value is the explicit TLS identity and may intentionally differ
from the endpoint address or DoH URL host, for example when testing a CDN
alias. It changes certificate validation only; it does not change the dial
candidates. Use `--details`, JSON, or CSV to audit the effective TLS name,
identity source, bootstrap mode, configured candidates, and selected dial
address, endpoint URL, effective TLS identity, identity source, and bootstrap
mode/candidates.

Resolver profile files must contain exactly one YAML document. SpeeDNS rejects
additional documents instead of silently ignoring them.

## Bundled domain corpus

The default benchmark uses an embedded, pinned 1,000-domain corpus. SpeeDNS
verifies its entry count, uniqueness, syntax, and SHA-256 checksum locally
before using it. Show the source and integrity metadata with:

```sh
./speedns corpus
```

The corpus is a pinned Tranco snapshot. Its source, list ID, retrieval date,
checksum, and attribution note are shipped with the program; benchmarking does
not download or refresh the list.

## Custom domain lists

Provide one domain per line with `--domains`. Blank lines, comments beginning with `#`, and duplicate names are ignored; a trailing root dot is removed. Unicode names are converted to IDNA ASCII before testing. Names containing whitespace, wildcards, control characters, empty labels, malformed labels, or DNS-overlong names are rejected before any network activity, and custom-list errors include the source line.

```sh
./speedns --domains my-domains.txt --sample 200 --seed 42
```

A custom list replaces the embedded list for that run. SpeeDNS does not download domain names while benchmarking.

### Opt-in cache-miss mode

For a bounded cache-miss experiment, use the separately documented reserved
zone mode:

```sh
./speedns --cache-miss --cache-miss-sample 10 --no-defaults \
  --resolver lab=udp://192.0.2.53:53 --type A
```

This generates 1–20 unique labels below the IANA-reserved `example.com` zone,
caps measured concurrency at two, and records a random nonce in the report.
It cannot be combined with `--domains` or `--full`. Cache-miss results are
kept in their own run and ranking population; they are never mixed with the
normal embedded warm-cache corpus. Read [`CACHE_MISS.md`](CACHE_MISS.md) before
using the mode, especially for ownership, traffic, and abuse limits.

## System resolver baseline

Use `--include-system` to include the resolver configured by the operating system:

```sh
./speedns --include-system
```

This is read-only. On Debian/Linux, SpeeDNS reads `/etc/resolv.conf`, including a local `systemd-resolved` stub when present. On macOS, it discovers active resolver blocks, preserving their scope and interface labels, and falls back to `/etc/resolv.conf`. Separate macOS scopes remain separate targets even when they use the same address.

macOS discovery gives `scutil --dns` a two-second independent timeout. If it
times out or returns no usable nameservers, SpeeDNS falls back to
`/etc/resolv.conf`; a canceled run remains canceled. Loopback entries such as
`127.0.0.53` and `::1` are labeled as local forwarding stubs because their
ultimate upstream is not known to SpeeDNS. Scoped macOS entries are kept
separate when the same address appears in more than one resolver block, since
the scope and interface can change which DNS server answers.

When sharing a report that includes the system resolver, add
`--redact-system`. It keeps the measurements and rankings but replaces local
resolver addresses, identifying labels, selected dial addresses, and matching
error text with redacted values in table, JSON, and CSV output. Redaction is
opt-in; local diagnostics are shown by default.

System resolvers are tested only over transports discoverable from the operating system configuration, normally UDP and TCP.

## Output

Human-readable table output is the default. It shows both transport success and
usable-response rates. Use `--details` for cold latency, MAD jitter, scored
samples, transport failures, resolver-error counts and RCODEs, divergence,
truncation, reconnects, incomplete targets, and the selected connection
address.

For scripts and other tools, use JSON or CSV:

```sh
./speedns --format json --output result.json
./speedns --format csv --output result.csv
./speedns --format json --raw --output result-with-samples.json
```

The versioned JSON contract is published as
[`schema/report-v1.json`](schema/report-v1.json). It describes the current
`schema_version: 1` output, including optional raw samples, profile
comparisons, paired effects, divergence details, and warnings. Consumers
should select their parser and validation rules from the reported schema
version rather than assuming that table or CSV output has the same shape.

CLI-generated JSON reports also include `run.provenance`. It records the
SpeeDNS build version, commit, build date, operating system, architecture,
active interface names, selected protocols, effective timeout and concurrency,
elapsed duration, and the SHA-256 digest plus entry count of the exact
normalized domain sequence used by the run. This makes custom-domain and
cache-miss results auditable without downloading anything at runtime. The
`--redact-system` option replaces interface names with `redacted` along with
other local resolver details; CSV output is unchanged.

### Scheduled live results

The project also runs a scheduled, non-blocking smoke check against one
official endpoint for each transport. Complete runs are validated and
published as compact JSON records and a static `index.html` on the [`results`
branch](https://github.com/crypt0rr/SpeeDNS/tree/results). These checks are
health and interoperability data, not a replacement for a local comparison:
latency depends on the network where each run executes, and a failed run is
retained with its diagnostics instead of being presented as a successful
benchmark. Consumers can validate records with the published
[`live-results-v1.schema.json`](https://github.com/crypt0rr/SpeeDNS/blob/results/live-results-v1.schema.json).

Useful flags include:

```text
--sample N          number of domains to sample
--full              test the complete domain list
--cache-miss        opt in to bounded reserved-zone cache-miss names
--cache-miss-sample N  number of unique cache-miss names (maximum 20)
--seed N            reproduce a domain order
--type A,AAAA       record types to query
--timeout 2s        per-endpoint timeout
--concurrency 4    maximum measured DNS exchanges in flight per protocol
--format table|json|csv
--output PATH       write output to a file
--no-color          disable terminal colors
--redact-system     hide local system resolver details in reports
--profile-view      show same-resolver transport costs and score confidence
--assert EXPR       enforce a benchmark condition (repeatable)
```

In an interactive terminal, progress is shown as one updating status line. Redirected output uses one completion line per protocol, and JSON/CSV runs remain quiet on standard error.

Cache-miss JSON and CSV reports carry the corpus mode, reserved zone, and
per-run nonce. JSON with `--profile-view` additionally includes
`profile_comparisons`; the table view renders the same transport metrics and
confidence intervals below the normal comparisons.

When a benchmark finishes without a comparable result, SpeeDNS still writes the
diagnostic report so you can inspect endpoint failures, resolver errors, and
warnings. The command returns a distinct non-zero status:

- `0` — comparison completed successfully;
- `2` — invalid input or configuration;
- `3` — no comparable DNS results were produced;
- `4` — a requested benchmark assertion failed;
- `130` — interrupted by the user or operating system.

### Assertions for automation

Use repeatable `--assert` flags when a benchmark should act as a CI or
monitoring gate. Numeric assertions are checked for every qualified or
provisional winner in every protocol that produced a ranking:

```sh
./speedns --protocol doh --assert 'usable>=0.99' --assert 'p95<50ms'
./speedns --protocol udp,doh --assert winner=quad9-9999
```

Supported metrics are `usable` and `success` (rates from `0` to `1`) plus
`median`, `p95`, and `score` (milliseconds). Bare latency numbers are treated
as milliseconds; duration suffixes such as `50ms` and `1.5s` are also
accepted. Operators are `>=`, `>`, `<=`, `<`, and `=`. `winner=` accepts a
resolver profile ID or a complete target ID. A tied rank-one result satisfies
the winner assertion. Invalid expressions return status `2`; failed
assertions return status `4` after the normal report has been written. Status
`3` for no comparable results and status `130` for interruption take
precedence.

## Troubleshooting

- If a network blocks traditional DNS, UDP and TCP may show `FAILED` while encrypted transports still work. SpeeDNS reports these failures instead of retrying through another protocol.
- If no resolver is marked recommended, increase `--sample` or use `--full`. A short run may only qualify for a provisional winner.
- If a resolver receives DNS messages but returns `SERVFAIL`, `REFUSED`, or another resolver error, it can have a high transport success rate but a low usable-response rate and will not be recommended.
- Compare resolvers with similar policies when answer behavior matters. Protective, ad-blocking, and unfiltered services may intentionally return different response classes.
- Use `--details` to inspect connection errors, response counters, and RCODEs for a failing endpoint.

## Privacy and platform support

SpeeDNS runs locally on macOS and Debian/Linux, supports IPv4 and IPv6 resolver addresses, and does not modify DNS settings or send telemetry. The domains you test are sent to the resolvers you select, just as they would be for normal DNS lookups.

## Project policies

Contributors can find development setup, test commands, fixture expectations,
and release-file guidance in [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a
security vulnerability privately, follow [`SECURITY.md`](SECURITY.md) rather
than opening a public issue.

## License

SpeeDNS is released under the [MIT License](LICENSE).
