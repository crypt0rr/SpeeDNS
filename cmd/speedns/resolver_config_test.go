package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// rankFirstEngine stands in for the benchmark engine: every target answers,
// the first one is ranked first on its protocol, and its p95 is p95MS.
func rankFirstEngine(p95MS float64) func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
	return func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		report := benchmark.Report{StartedAt: time.Unix(1, 0), FinishedAt: time.Unix(2, 0), Seed: 1, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1}}
		for index, target := range targets {
			report.Targets = append(report.Targets, benchmark.TargetResult{Target: target, Stats: benchmark.Statistics{
				Total: 30, Successes: 30, UsableResponses: 30, Scored: 30, SuccessRate: 1, UsableRate: 1,
				MedianMS: p95MS, P95MS: p95MS, ScoreMS: p95MS,
			}})
			report.Rankings = append(report.Rankings, benchmark.Ranking{Protocol: target.Protocol, TargetID: target.ID(), Rank: index + 1})
		}
		return report, nil
	}
}

// TestAssertionFailuresUseRedactedTargetIDs covers the second half of #243.
// With --redact-system the report names a system resolver
// system-redacted-1@redacted/udp, but a failing --assert printed its real
// target ID - address included, twice - on stderr, next to the report it was
// supposed to agree with. Both assertion forms that quote a target ID, the
// rank-one threshold and the subject-qualified one, must name it the way the
// report does.
func TestAssertionFailuresUseRedactedTargetIDs(t *testing.T) {
	oldEngine, oldDiscover, oldOwn := runBenchmarkEngine, discoverSystemResolvers, hostOwnAddressesFunc
	t.Cleanup(func() {
		runBenchmarkEngine, discoverSystemResolvers, hostOwnAddressesFunc = oldEngine, oldDiscover, oldOwn
	})
	runBenchmarkEngine = rankFirstEngine(5)
	hostOwnAddressesFunc = func() (map[string]bool, error) { return map[string]bool{}, nil }
	discoverSystemResolvers = func(context.Context) ([]catalog.ResolverProfile, error) {
		return []catalog.ResolverProfile{{
			ID: "system-10-20-30-40", Name: "System DNS", Owner: "configured locally", Policy: "unknown",
			Addresses: []string{"10.20.30.40"}, Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}},
		}}, nil
	}

	for _, test := range []struct {
		assertion string
		want      string
	}{
		{"p95<0.5ms", "p95<0.5ms: udp winner system-redacted-1@redacted/udp has p95=5.000ms"},
		{"System DNS:p95<0.5ms", "System DNS:p95<0.5ms: system-redacted-1@redacted/udp has p95=5.000ms"},
		{"System DNS:median<0.5ms", "System DNS:median<0.5ms: system-redacted-1@redacted/udp has median=5.000ms"},
	} {
		t.Run(test.assertion, func(t *testing.T) {
			config := &cliConfig{
				protocols: "udp", noDefaults: true, includeSystem: true, redactSystem: true,
				domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A", timeout: time.Second,
				concurrency: 1, format: "json", family: "4", assertions: []string{test.assertion},
				output: filepath.Join(t.TempDir(), "report.json"),
			}
			err := runBenchmark(context.Background(), config)
			if !errors.Is(err, ErrAssertionsFailed) || exitCodeForError(err) != 4 {
				t.Fatalf("runBenchmark = %v, want a failed assertion", err)
			}
			message := errorMessage(err)
			if !strings.Contains(message, test.want) {
				t.Fatalf("assertion message = %q, want it to contain %q", message, test.want)
			}
			if strings.Contains(message, "10.20.30.40") || strings.Contains(message, "10-20-30-40") {
				t.Fatalf("assertion message leaks the redacted resolver: %q", message)
			}
			content, readErr := os.ReadFile(config.output)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains(string(content), `"system-redacted-1@redacted/udp"`) {
				t.Fatalf("the report does not use the ID the message quotes: %s", content)
			}
		})
	}

	// Without --redact-system nothing is withheld, so the message keeps the
	// real target ID.
	config := &cliConfig{
		protocols: "udp", noDefaults: true, includeSystem: true,
		domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A", timeout: time.Second,
		concurrency: 1, format: "json", family: "4", assertions: []string{"p95<0.5ms"},
		output: filepath.Join(t.TempDir(), "report.json"),
	}
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(errorMessage(err), "udp winner system-10-20-30-40@10.20.30.40/udp has p95=5.000ms") {
		t.Fatalf("unredacted assertion message = %v", err)
	}
}

// TestRedactedAssertionsDescribeUnscoredSubjects covers the remaining reason
// that names a target: a subject with no scored latency sample.
func TestRedactedAssertionsDescribeUnscoredSubjects(t *testing.T) {
	system := catalog.Target{
		Resolver: catalog.ResolverProfile{ID: "system-10-20-30-40", Name: "System DNS"},
		Protocol: catalog.UDP, Address: "10.20.30.40", Spec: catalog.TransportSpec{Port: 53},
	}
	report := benchmark.Report{Targets: []benchmark.TargetResult{{Target: system, Stats: benchmark.Statistics{Total: 30, Failures: 30, FailureRate: 1}}}}
	checks, err := parseAssertions([]string{"System DNS:p95<50ms"})
	if err != nil {
		t.Fatal(err)
	}
	err = evaluateAssertionsWithOptions(report, checks, assertionOptions{redactSystem: true})
	if !errors.Is(err, ErrAssertionsFailed) || !strings.Contains(err.Error(), "System DNS:p95<50ms: system-redacted-1@redacted/udp has no scored latency samples") {
		t.Fatalf("redacted unscored subject = %v", err)
	}
	if err := evaluateAssertions(report, checks); err == nil || !strings.Contains(err.Error(), "system-10-20-30-40@10.20.30.40/udp has no scored latency samples") {
		t.Fatalf("unredacted unscored subject = %v", err)
	}
}

// TestCredentialedDoHResolverIsRejectedBeforeAnyQuery covers #243 end to end:
// a DoH URL with userinfo used to be accepted, sent as Basic authentication
// and recorded verbatim in endpoint_url. It is now a configuration error from
// either input, raised before the engine runs, and the credentials appear in
// no message.
func TestCredentialedDoHResolverIsRejectedBeforeAnyQuery(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		t.Error("the engine must not run for a rejected resolver")
		return benchmark.Report{}, nil
	}
	resolverFile := filepath.Join(t.TempDir(), "resolvers.yaml")
	contents := "version: 1\nresolvers:\n  - id: private\n    name: Private\n    addresses: [192.0.2.53]\n    transports:\n      doh: {url: \"https://bob:hunter2@doh.example/dns-query\"}\n"
	if err := os.WriteFile(resolverFile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, apply := range map[string]func(*cliConfig){
		"--resolver": func(config *cliConfig) {
			config.resolverFlags = []string{"private=https://alice:s3cret@doh.example/dns-query"}
		},
		"--resolver-file": func(config *cliConfig) { config.resolverFile = resolverFile },
	} {
		t.Run(name, func(t *testing.T) {
			config := &cliConfig{
				protocols: "doh", noDefaults: true, domainFile: cliDomainFile(t), sample: 1, seed: 1,
				queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json", family: "both",
			}
			apply(config)
			err := runBenchmark(context.Background(), config)
			if err == nil || exitCodeForError(err) != 2 || !strings.Contains(err.Error(), "must not include user credentials") {
				t.Fatalf("runBenchmark = %v, want a credentials error", err)
			}
			for _, secret := range []string{"alice", "s3cret", "bob", "hunter2"} {
				if strings.Contains(errorMessage(err), secret) {
					t.Fatalf("error leaks %q: %v", secret, err)
				}
			}
		})
	}
}

// TestSharedBootstrapRowsAreFilteredAndExplained covers #234 end to end. A
// profile with an IPv4 and an IPv6 address whose encrypted transports dial
// bootstrap_addresses used to keep, under --family 6, a DoT row labelled with
// the IPv6 address that dialed IPv4. And under both, each address became its
// own ranked row with an identical dial plan. Now the family filter reaches
// the bootstrap candidates, and the duplicate rows that remain carry a warning
// that says why they match.
func TestSharedBootstrapRowsAreFilteredAndExplained(t *testing.T) {
	oldEngine, oldOwn := runBenchmarkEngine, hostOwnAddressesFunc
	t.Cleanup(func() { runBenchmarkEngine, hostOwnAddressesFunc = oldEngine, oldOwn })
	var measured []catalog.Target
	engine := rankFirstEngine(5)
	runBenchmarkEngine = func(ctx context.Context, targets []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		measured = targets
		return engine(ctx, targets, options)
	}
	hostOwnAddressesFunc = func() (map[string]bool, error) { return map[string]bool{}, nil }
	resolverFile := filepath.Join(t.TempDir(), "resolvers.yaml")
	contents := `version: 1
resolvers:
  - id: dual
    name: Dual
    addresses: [192.0.2.53, "2001:db8::53"]
    transports:
      udp: {}
      dot: {server_name: dns.example, bootstrap_addresses: [192.0.2.53]}
      doh: {url: "https://dns.example/dns-query", bootstrap_addresses: [192.0.2.53, "2001:db8::1"]}
`
	if err := os.WriteFile(resolverFile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, family, protocols string) []string {
		t.Helper()
		config := &cliConfig{
			protocols: protocols, noDefaults: true, resolverFile: resolverFile, domainFile: cliDomainFile(t),
			sample: 1, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json",
			family: family, output: filepath.Join(t.TempDir(), "report.json"),
		}
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(config.output)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal(content, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.Warnings
	}

	warnings := run(t, "6", "udp,doh,dot")
	ids := make([]string, 0, len(measured))
	for _, target := range measured {
		ids = append(ids, target.ID())
		for _, candidate := range target.Spec.BootstrapAddresses {
			if family, _ := catalog.AddressFamilyForAddress(candidate); family != catalog.Family6 {
				t.Fatalf("--family 6 target %s dials %s", target.ID(), candidate)
			}
		}
	}
	if strings.Join(ids, ",") != "dual@2001:db8::53/udp,dual@2001:db8::53/doh" {
		t.Fatalf("--family 6 targets = %v, want the DoT row dropped with its IPv4-only bootstrap", ids)
	}
	if len(warnings) != 0 {
		t.Fatalf("--family 6 leaves one address, so nothing is duplicated: %q", warnings)
	}

	warnings = run(t, "both", "udp,doh,dot")
	want := `resolver "dual" is measured once per address over doh, dot, but those transports dial bootstrap_addresses, so its rows measure the same connection candidates; list one address or remove bootstrap_addresses to avoid duplicate rows`
	if len(measured) != 6 || len(warnings) != 1 || warnings[0] != want {
		t.Fatalf("--family both = %d targets, warnings %q, want %q", len(measured), warnings, want)
	}

	// UDP dials each address itself, so its rows are distinct endpoints.
	if warnings := run(t, "both", "udp"); len(warnings) != 0 {
		t.Fatalf("plain transports raised a shared-bootstrap warning: %q", warnings)
	}
}

// TestSharedBootstrapWarningsReportEachResolverOnce keeps the warning list
// deterministic and short: one line per resolver, its protocols in the
// documented order, and nothing for a single row or a transport without
// bootstrap candidates.
func TestSharedBootstrapWarningsReportEachResolverOnce(t *testing.T) {
	profiles := []catalog.ResolverProfile{
		{ID: "a", Name: "A", Addresses: []string{"192.0.2.1", "192.0.2.2"}, Transports: map[catalog.Protocol]catalog.TransportSpec{
			catalog.DoQ: {ServerName: "a.example", BootstrapAddresses: []string{"192.0.2.9"}},
			catalog.DoH: {URL: "https://a.example/dns-query", BootstrapAddresses: []string{"192.0.2.9"}},
			catalog.DoT: {ServerName: "a.example"},
		}},
		{ID: "b", Name: "B", Addresses: []string{"192.0.2.3"}, Transports: map[catalog.Protocol]catalog.TransportSpec{
			catalog.DoT: {ServerName: "b.example", BootstrapAddresses: []string{"192.0.2.8"}},
		}},
	}
	warnings := sharedBootstrapWarnings(catalog.Expand(profiles, nil))
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0].String(), `resolver "a" is measured once per address over doh, doq,`) {
		t.Fatalf("warnings = %#v", warnings)
	}
	if warnings[0].Targeted() {
		t.Fatal("the warning describes a resolver's configuration, not one endpoint")
	}
	if got := sharedBootstrapWarnings(nil); len(got) != 0 {
		t.Fatalf("no targets = %#v", got)
	}
}

// TestFamilyFilterNamesItselfWhenItEmptiesAProtocol keeps the error honest
// when --family, not --protocol, is why nothing is left to measure. A DoT
// transport whose bootstrap candidates are all IPv4 is dropped under
// --family 6; with only DoT selected the run used to fail with the generic
// "no resolver supports the selected protocol(s)", which named neither the
// flag nor the field responsible.
func TestFamilyFilterNamesItselfWhenItEmptiesAProtocol(t *testing.T) {
	oldEngine, oldOwn := runBenchmarkEngine, hostOwnAddressesFunc
	t.Cleanup(func() { runBenchmarkEngine, hostOwnAddressesFunc = oldEngine, oldOwn })
	hostOwnAddressesFunc = func() (map[string]bool, error) { return map[string]bool{}, nil }
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		t.Error("the engine must not run when nothing is selected")
		return benchmark.Report{}, nil
	}
	resolverFile := filepath.Join(t.TempDir(), "resolvers.yaml")
	contents := `version: 1
resolvers:
  - id: pinned
    name: Pinned
    addresses: ["2001:db8::53"]
    transports:
      udp: {}
      dot: {server_name: dns.example, bootstrap_addresses: [192.0.2.53]}
`
	if err := os.WriteFile(resolverFile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(protocols string) error {
		return runBenchmark(context.Background(), &cliConfig{
			protocols: protocols, noDefaults: true, resolverFile: resolverFile, domainFile: cliDomainFile(t),
			sample: 1, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json", family: "6",
		})
	}
	err := run("dot")
	want := "no resolver supports the selected protocol(s) under --family 6, which also drops a doh, dot or doq transport whose bootstrap_addresses are all outside that family"
	if err == nil || exitCodeForError(err) != 2 || err.Error() != want {
		t.Fatalf("--family 6 --protocol dot = %v, want %q", err, want)
	}
	// A protocol no profile declares at all is still the plain selection
	// error: the family filter removed nothing that could have answered.
	if err := run("doq"); err == nil || exitCodeForError(err) != 2 || err.Error() != "no resolver supports the selected protocol(s)" {
		t.Fatalf("--protocol doq = %v, want the generic selection error", err)
	}
}
