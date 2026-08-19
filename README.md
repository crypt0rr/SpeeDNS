# SpeeDNS

SpeeDNS (`speedns`) is a read-only command-line DNS benchmark. It compares recursive DNS resolvers from your current network over UDP, TCP, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and dedicated DNS-over-QUIC (DoQ), then shows which resolver is fastest for each transport.

SpeeDNS does not change your system DNS settings, requires no root privileges, and sends no telemetry.

## Install

Prebuilt macOS and Debian/Linux binaries and packages are published with each release on the [GitHub Releases page](https://github.com/crypt0rr/SpeeDNS/releases). Choose the archive for your platform and architecture. Releases include:

- macOS Intel (`amd64`) and Apple silicon (`arm64`);
- Linux `amd64` and `arm64` archives;
- Debian packages for Linux `amd64` and `arm64`.

To build from source, install [Go 1.25 or newer](https://go.dev/dl/):

```sh
git clone https://github.com/crypt0rr/SpeeDNS.git
cd SpeeDNS
go build -trimpath -ldflags "-s -w" -o speedns ./cmd/speedns
./speedns version
```

The build is pure Go and has no runtime dependencies.

## Quick start

Run the default comparison:

```sh
./speedns
```

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

## How the comparison works

The default run samples 100 names from an embedded, versioned 1,000-name domain list and queries both A and AAAA records. `--full` uses the complete list. Every resolver eligible for the same transport receives the same names, query types, DNS settings, and randomized order.

SpeeDNS reports warm query latency over reused connections and, for encrypted transports, cold first-query latency including connection setup. Results are ranked separately for each transport; a UDP result is not treated as interchangeable with a DoH, DoT, or DoQ result.

The score is lower-is-better:

```text
0.60 × median latency + 0.40 × p95 latency + failure rate × timeout
```

An endpoint is marked `RECOMMENDED` only when it has at least 20 comparable samples and at least 99% successful responses. Short runs can show a `PROVISIONAL` winner, but use a larger sample or `--full` for a more stable comparison.

Resolvers can have different filtering policies. SpeeDNS shows the policy beside each result and excludes materially divergent responses from comparative latency scoring, so a blocking or filtered answer does not automatically win by responding sooner.

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

SpeeDNS does not silently fall back from one protocol to another. A configured but unavailable transport is shown as `FAIL`; an unsupported transport for a resolver is shown as `—`.

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

Dedicated DoQ is currently configured for Quad9. DoH over HTTP/3 is a separate transport and is not mislabeled as DoQ.

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

## Custom domain lists

Provide one domain per line with `--domains`. Blank lines, comments beginning with `#`, and duplicate names are ignored; names are normalized before testing.

```sh
./speedns --domains my-domains.txt --sample 200 --seed 42
```

A custom list replaces the embedded list for that run. SpeeDNS does not download domain names while benchmarking.

## System resolver baseline

Use `--include-system` to include the resolver configured by the operating system:

```sh
./speedns --include-system
```

This is read-only. On Debian/Linux, SpeeDNS reads `/etc/resolv.conf`, including a local `systemd-resolved` stub when present. On macOS, it discovers active resolver scopes with `scutil --dns` and falls back to `/etc/resolv.conf`.

System resolvers are tested only over transports discoverable from the operating system configuration, normally UDP and TCP.

## Output

Human-readable table output is the default. Use `--details` for cold latency, jitter, scored samples, failures, divergence, truncation, and the selected connection address.

For scripts and other tools, use JSON or CSV:

```sh
./speedns --format json --output result.json
./speedns --format csv --output result.csv
./speedns --format json --raw --output result-with-samples.json
```

Useful flags include:

```text
--sample N          number of domains to sample
--full              test the complete domain list
--seed N            reproduce a domain order
--type A,AAAA       record types to query
--timeout 2s        per-endpoint timeout
--concurrency 4    maximum concurrent endpoint workers
--format table|json|csv
--output PATH       write output to a file
--no-color          disable terminal colors
```

In an interactive terminal, progress is shown as one updating status line. Redirected output uses one completion line per protocol, and JSON/CSV runs remain quiet on standard error.

## Troubleshooting

- If a network blocks traditional DNS, UDP and TCP may show `FAIL` while encrypted transports still work. SpeeDNS reports these failures instead of retrying through another protocol.
- If no resolver is marked recommended, increase `--sample` or use `--full`. A short run may only qualify for a provisional winner.
- Compare resolvers with similar policies when answer behavior matters. Protective, ad-blocking, and unfiltered services may intentionally return different response classes.
- Use `--details` to inspect connection errors and response counters for a failing endpoint.

## Privacy and platform support

SpeeDNS runs locally on macOS and Debian/Linux, supports IPv4 and IPv6 resolver addresses, and does not modify DNS settings or send telemetry. The domains you test are sent to the resolvers you select, just as they would be for normal DNS lookups.

## License

SpeeDNS is released under the [MIT License](LICENSE).
