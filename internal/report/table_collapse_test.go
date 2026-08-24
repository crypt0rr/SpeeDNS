package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

func ipv6CollapseReport() benchmark.Report {
	usableIPv4 := reportTarget("v4", catalog.UDP, 2, true)
	failedIPv6A := reportTarget("v6-a", catalog.UDP, 0, false)
	failedIPv6A.Target.Address = "2001:db8::1"
	failedIPv6A.Stats = benchmark.Statistics{Total: 4, Failures: 4}
	failedIPv6B := reportTarget("v6-b", catalog.UDP, 0, false)
	failedIPv6B.Target.Address = "2001:db8::2"
	failedIPv6B.Stats = benchmark.Statistics{Total: 4, Failures: 4}
	failedIPv6DoH := reportTarget("v6-doh", catalog.DoH, 0, false)
	failedIPv6DoH.Target.Address = "2001:db8::3"
	failedIPv6DoH.Stats = benchmark.Statistics{Total: 4, Failures: 4}
	return benchmark.Report{
		Seed: 42, SampleSize: 2, Queries: 2, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{usableIPv4, failedIPv6A, failedIPv6B, failedIPv6DoH},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: usableIPv4.Target.ID(), Rank: 1}},
	}
}

func TestComparisonTableCollapsesFullyUnavailableIPv6Rows(t *testing.T) {
	run := ipv6CollapseReport()

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := table.String()
	for _, hiddenAddress := range []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"} {
		if strings.Contains(text, hiddenAddress) {
			t.Fatalf("default table listed collapsed IPv6 endpoint %q: %s", hiddenAddress, text)
		}
	}
	if !strings.Contains(text, "  2 IPv6 endpoints hidden: no usable IPv6 path detected (--details lists them)") {
		t.Fatalf("default table missing collapsed UDP summary: %s", text)
	}
	if !strings.Contains(text, "  1 IPv6 endpoint hidden: no usable IPv6 path detected (--details lists them)") {
		t.Fatalf("default table missing collapsed DoH summary: %s", text)
	}
	if strings.Contains(text, "no targets") {
		t.Fatalf("fully collapsed protocol reported no targets: %s", text)
	}
	if !strings.Contains(text, "192.0.2.v4") {
		t.Fatalf("default table dropped the IPv4 comparison row: %s", text)
	}

	var details bytes.Buffer
	if err := WriteTableWithOptions(&details, run, TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	detailText := details.String()
	for _, listedAddress := range []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"} {
		if !strings.Contains(detailText, listedAddress) {
			t.Fatalf("detailed table hid IPv6 endpoint %q: %s", listedAddress, detailText)
		}
	}
	if strings.Contains(detailText, "hidden:") {
		t.Fatalf("detailed table collapsed IPv6 rows: %s", detailText)
	}

	if err := WriteTableWithOptions(contentFailWriter{needle: "IPv6 endpoints hidden"}, run, TableOptions{}); err == nil {
		t.Fatal("collapsed IPv6 summary writer failure was not returned")
	}
}

func TestComparisonTableKeepsPartialIPv6Failures(t *testing.T) {
	usableIPv4 := reportTarget("v4", catalog.UDP, 2, true)
	failedIPv6 := reportTarget("v6-a", catalog.UDP, 0, false)
	failedIPv6.Target.Address = "2001:db8::1"
	failedIPv6.Stats = benchmark.Statistics{Total: 4, Failures: 4}
	usableIPv6 := reportTarget("v6-b", catalog.UDP, 2, false)
	usableIPv6.Target.Address = "2001:db8::2"
	run := benchmark.Report{
		Seed: 42, SampleSize: 2, Queries: 2, QueryTypes: []uint16{1},
		Targets:  []benchmark.TargetResult{usableIPv4, failedIPv6, usableIPv6},
		Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: usableIPv4.Target.ID(), Rank: 1}},
	}

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := table.String()
	for _, listedAddress := range []string{"2001:db8::1", "2001:db8::2"} {
		if !strings.Contains(text, listedAddress) {
			t.Fatalf("partial IPv6 failure hid endpoint %q: %s", listedAddress, text)
		}
	}
	if strings.Contains(text, "hidden:") {
		t.Fatalf("partial IPv6 failure was collapsed: %s", text)
	}
}

func pairedPolicyReport(effects []benchmark.PairedEffect, targets []benchmark.TargetResult) benchmark.Report {
	return benchmark.Report{
		Seed: 42, SampleSize: 2, Queries: 2, QueryTypes: []uint16{1},
		Targets: targets, PairedEffects: effects,
	}
}

func TestPairedEffectsOmitTargetsAloneInTheirProtocolGroup(t *testing.T) {
	first := reportTarget("paired-first", catalog.UDP, 2, true)
	second := reportTarget("paired-second", catalog.UDP, 2, false)
	lonelyPolicy := reportTarget("paired-filtered", catalog.UDP, 2, false)
	lonelyPolicy.Target.Resolver.Policy = "filtered"
	lonelyProtocol := reportTarget("paired-tcp", catalog.TCP, 2, false)
	// A second protocol with one measured target, so the summary line exercises
	// its plural form as well as the singular one below.
	lonelyDoH := reportTarget("paired-doh", catalog.DoH, 2, false)
	effects := []benchmark.PairedEffect{
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: first.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 2, Reference: true},
		{Protocol: catalog.UDP, Policy: "unfiltered", TargetID: second.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 2, MedianDeltaMS: 1, CILowMS: 0.5, CIHighMS: 1.5},
		// A different policy string no longer isolates a target: it is compared
		// against the protocol's reference like any other member.
		{Protocol: catalog.UDP, Policy: "filtered", TargetID: lonelyPolicy.Target.ID(), ReferenceTargetID: first.Target.ID(), Samples: 2, MedianDeltaMS: 2, CILowMS: 1, CIHighMS: 3},
		{Protocol: catalog.TCP, Policy: "unfiltered", TargetID: lonelyProtocol.Target.ID(), ReferenceTargetID: lonelyProtocol.Target.ID(), Samples: 2, Reference: true},
		{Protocol: catalog.DoH, Policy: "unfiltered", TargetID: lonelyDoH.Target.ID(), ReferenceTargetID: lonelyDoH.Target.ID(), Samples: 2, Reference: true},
	}
	run := pairedPolicyReport(effects, []benchmark.TargetResult{first, second, lonelyPolicy, lonelyProtocol, lonelyDoH})

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := table.String()
	if !strings.Contains(text, "  omitted 2 targets alone in their protocol group (--details lists them)") {
		t.Fatalf("paired table missing singleton summary: %s", text)
	}
	pairedBlock := text[strings.Index(text, "Paired latency effects"):]
	for _, omittedAddress := range []string{"192.0.2.paired-tcp", "192.0.2.paired-doh"} {
		if strings.Contains(pairedBlock, omittedAddress) {
			t.Fatalf("paired table kept a row alone in its protocol group %q: %s", omittedAddress, pairedBlock)
		}
	}
	for _, keptAddress := range []string{"192.0.2.paired-second", "192.0.2.paired-filtered"} {
		if !strings.Contains(pairedBlock, keptAddress) {
			t.Fatalf("paired table dropped a comparable row %q: %s", keptAddress, pairedBlock)
		}
	}

	var details bytes.Buffer
	if err := WriteTableWithOptions(&details, run, TableOptions{Details: true}); err != nil {
		t.Fatal(err)
	}
	detailText := details.String()
	detailBlock := detailText[strings.Index(detailText, "Paired latency effects"):]
	for _, listedAddress := range []string{"192.0.2.paired-filtered", "192.0.2.paired-tcp", "192.0.2.paired-doh", "192.0.2.paired-second"} {
		if !strings.Contains(detailBlock, listedAddress) {
			t.Fatalf("detailed paired table hid %q: %s", listedAddress, detailBlock)
		}
	}
	if strings.Contains(detailBlock, "--details lists them") {
		t.Fatalf("detailed paired table omitted singleton rows: %s", detailBlock)
	}

	var jsonOutput bytes.Buffer
	if err := WriteJSON(&jsonOutput, run, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{lonelyPolicy.Target.ID(), lonelyProtocol.Target.ID()} {
		if !strings.Contains(jsonOutput.String(), expected) {
			t.Fatalf("paired JSON dropped %q: %s", expected, jsonOutput.String())
		}
	}

	if err := WriteTableWithOptions(contentFailWriter{needle: "protocol group"}, run, TableOptions{}); err == nil {
		t.Fatal("singleton paired summary writer failure was not returned")
	}
}

func TestPairedEffectsWithOnlySingletonGroupsRenderSummaryOnly(t *testing.T) {
	lonelyPolicy := reportTarget("paired-filtered", catalog.UDP, 2, false)
	lonelyPolicy.Target.Resolver.Policy = "filtered"
	run := pairedPolicyReport([]benchmark.PairedEffect{
		{Protocol: catalog.UDP, Policy: "filtered", TargetID: lonelyPolicy.Target.ID(), ReferenceTargetID: lonelyPolicy.Target.ID(), Samples: 2, Reference: true},
	}, []benchmark.TargetResult{lonelyPolicy})

	var table bytes.Buffer
	if err := WriteTableWithOptions(&table, run, TableOptions{}); err != nil {
		t.Fatal(err)
	}
	text := table.String()
	pairedBlock := text[strings.Index(text, "Paired latency effects"):]
	if !strings.Contains(pairedBlock, "  omitted 1 target alone in its protocol group (--details lists them)") {
		t.Fatalf("single singleton summary missing: %s", pairedBlock)
	}
	if strings.Contains(pairedBlock, "Interpretation") {
		t.Fatalf("empty paired table was still rendered: %s", pairedBlock)
	}
}
