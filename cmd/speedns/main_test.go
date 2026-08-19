package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/data"
	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

type cliErrorWriter struct{}

func (cliErrorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func cliDomainFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("example.com\nexample.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliConfigForTest(t *testing.T) *cliConfig {
	return &cliConfig{
		protocols: "udp", resolverFlags: []string{"lab=udp://127.0.0.1:53"}, noDefaults: true,
		domainFile: cliDomainFile(t), sample: 1, seed: 7, queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json",
	}
}

func fakeCLIReport() benchmark.Report {
	target := catalog.Target{Resolver: catalog.ResolverProfile{ID: "lab", Name: "Lab", Owner: "Owner", Policy: "unfiltered"}, Protocol: catalog.UDP, Address: "127.0.0.1", Spec: catalog.TransportSpec{Port: 53}}
	result := benchmark.TargetResult{Target: target, Stats: benchmark.Statistics{Total: 1, Successes: 1, Scored: 1, SuccessRate: 1, MedianMS: 1, P95MS: 1, ScoreMS: 1}}
	return benchmark.Report{StartedAt: time.Unix(1, 0), FinishedAt: time.Unix(2, 0), Seed: 7, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1}, Targets: []benchmark.TargetResult{result}, Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: target.ID(), Rank: 1}}}
}

func TestMainAndCommands(t *testing.T) {
	oldArgs := os.Args
	oldExit := exit
	t.Cleanup(func() { os.Args = oldArgs; exit = oldExit })
	exitCode := -1
	exit = func(code int) { exitCode = code }
	os.Args = []string{"speedns", "version"}
	main()
	if exitCode != -1 {
		t.Fatalf("successful main called exit(%d)", exitCode)
	}
	os.Args = []string{"speedns", "--format", "invalid"}
	main()
	if exitCode != 2 {
		t.Fatalf("failed main exit code = %d", exitCode)
	}
	os.Args = []string{"speedns"}

	versionCommand := newVersionCommand()
	var versionOutput bytes.Buffer
	versionCommand.SetOut(&versionOutput)
	versionCommand.SetArgs(nil)
	if err := versionCommand.Execute(); err != nil || !strings.Contains(versionOutput.String(), "speedns") {
		t.Fatalf("version command = %v/%q", err, versionOutput.String())
	}
	resolversCommand := newResolversCommand()
	var resolverOutput bytes.Buffer
	resolversCommand.SetOut(&resolverOutput)
	resolversCommand.SetArgs(nil)
	if err := resolversCommand.Execute(); err != nil || !strings.Contains(resolverOutput.String(), "Google") || !strings.Contains(resolverOutput.String(), "doq") {
		t.Fatalf("resolvers command = %v/%q", err, resolverOutput.String())
	}
	corpusCommand := newCorpusCommand()
	var corpusOutput bytes.Buffer
	corpusCommand.SetOut(&corpusOutput)
	corpusCommand.SetArgs(nil)
	if err := corpusCommand.Execute(); err != nil || !strings.Contains(corpusOutput.String(), "List ID:") || !strings.Contains(corpusOutput.String(), "Entries: 1000") || !strings.Contains(corpusOutput.String(), "SHA-256:") {
		t.Fatalf("corpus command = %v/%q", err, corpusOutput.String())
	}
	oldVerifyCorpus := verifyCorpusFunc
	verifyCorpusFunc = func() (data.CorpusMetadata, error) { return data.CorpusMetadata{}, errors.New("corpus fixture failed") }
	t.Cleanup(func() { verifyCorpusFunc = oldVerifyCorpus })
	if err := newCorpusCommand().Execute(); err == nil || !strings.Contains(err.Error(), "corpus fixture failed") {
		t.Fatalf("corpus command error = %v", err)
	}
	root := newRootCommand()
	if root.Use != "speedns" || root.Flags().Lookup("protocol") == nil || root.Flags().Lookup("redact-system") == nil || root.Commands() == nil {
		t.Fatal("root command was not configured")
	}
}

func TestExitCodeForError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", want: 0},
		{name: "invalid", err: errors.New("invalid configuration"), want: 2},
		{name: "no comparable", err: benchmark.ErrNoComparableResults, want: 3},
		{name: "canceled", err: context.Canceled, want: 130},
		{name: "deadline", err: context.DeadlineExceeded, want: 130},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeForError(tc.err); got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCLIParsersAndOutputHelpers(t *testing.T) {
	protocols, err := parseProtocols(" UDP,udp, TCP, doh, dot, doq ")
	if err != nil || len(protocols) != 5 {
		t.Fatalf("protocol parser = %#v/%v", protocols, err)
	}
	for _, value := range []string{"", "unknown"} {
		if _, err := parseProtocols(value); err == nil {
			t.Fatalf("expected protocol parser error for %q", value)
		}
	}
	types, err := parseQueryTypes(" A,aaaa,1,65000 ")
	if err != nil || len(types) != 3 || types[0] != 1 || types[1] != 28 || types[2] != 65000 {
		t.Fatalf("query type parser = %#v/%v", types, err)
	}
	for _, value := range []string{"", "ANY", "garbage", "65536"} {
		if _, err := parseQueryTypes(value); err == nil {
			t.Fatalf("expected query type parser error for %q", value)
		}
	}

	for _, path := range []string{"", " ", "-"} {
		writer, closeWriter, err := outputWriter(path)
		if err != nil || writer != os.Stdout {
			t.Fatalf("stdout writer for %q = %#v/%v", path, writer, err)
		}
		closeWriter()
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "output.txt")
	writer, closeWriter, err := outputWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "hello"); err != nil {
		t.Fatal(err)
	}
	closeWriter()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "hello" {
		t.Fatalf("file output = %q/%v", content, err)
	}
	if _, _, err := outputWriter(dir); err == nil {
		t.Fatal("expected output directory creation error")
	}
	values := []string{"z", "a", "a", "m"}
	sortStrings(values)
	if strings.Join(values, ",") != "a,a,m,z" {
		t.Fatalf("sorted values = %#v", values)
	}
	values = nil
	sortStrings(values)
}

func TestProgressRendererHandlesConcurrentCompletionStyles(t *testing.T) {
	targets := []catalog.Target{
		{Protocol: catalog.UDP, Address: "192.0.2.1"},
		{Protocol: catalog.TCP, Address: "192.0.2.2"},
		{Protocol: catalog.DoQ, Address: "192.0.2.3"},
	}
	selected := []catalog.Protocol{catalog.DoQ, catalog.UDP, catalog.TCP, catalog.DoH}

	var logOutput bytes.Buffer
	logProgress := newProgressRenderer(&logOutput, false, selected, targets)
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Completed: 1, Total: 1, Target: targets[2]})
	logProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Completed: 1, Total: 1, Target: targets[0]})
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Completed: 1, Total: 1, Target: targets[2]})
	logProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Completed: 1, Total: 1, Target: targets[1]})
	if got, want := logOutput.String(), "tested doq 1/1 targets\ntested udp 1/1 targets\ntested tcp 1/1 targets\n"; got != want {
		t.Fatalf("non-TTY progress = %q, want %q", got, want)
	}
	if strings.Contains(logOutput.String(), "192.0.2.") {
		t.Fatalf("non-TTY progress leaked target addresses: %q", logOutput.String())
	}

	var ttyOutput bytes.Buffer
	ttyProgress := newProgressRenderer(&ttyOutput, true, selected, targets)
	ttyProgress.lastLineWidth = 200
	ttyProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Completed: 1, Total: 1, Target: targets[2]})
	ttyProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Completed: 1, Total: 1, Target: targets[0]})
	ttyProgress.Finish()
	if !strings.Contains(ttyOutput.String(), "testing | udp 1/1 | tcp 0/1 | doq 1/1") {
		t.Fatalf("TTY progress did not use canonical order: %q", ttyOutput.String())
	}
	if !strings.HasSuffix(ttyOutput.String(), "\n") {
		t.Fatalf("TTY progress was not terminated before the report: %q", ttyOutput.String())
	}

	var fallbackOutput bytes.Buffer
	fallbackProgress := newProgressRenderer(&fallbackOutput, false, []catalog.Protocol{catalog.UDP}, nil)
	fallbackProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Completed: 1, Total: 1})
	if fallbackOutput.String() != "tested udp 1/1 targets\n" {
		t.Fatalf("fallback progress = %q", fallbackOutput.String())
	}
}

func TestTableColorDetectionHonorsTTYAndOverrides(t *testing.T) {
	oldDetector := terminalDetector
	t.Cleanup(func() { terminalDetector = oldDetector })
	terminalDetector = func(*os.File) bool { return true }
	if !tableColorEnabled(&cliConfig{}) {
		t.Fatal("expected color for an interactive default table")
	}
	if tableColorEnabled(&cliConfig{noColor: true}) {
		t.Fatal("--no-color did not disable color")
	}
	if tableColorEnabled(&cliConfig{output: "result.txt"}) {
		t.Fatal("file output should not receive terminal color")
	}
}

func TestLoadProfilesAllSourcesAndErrors(t *testing.T) {
	defaultProfiles, err := loadProfiles(context.Background(), &cliConfig{})
	if err != nil || len(defaultProfiles) != 10 {
		t.Fatalf("default profiles = %d/%v", len(defaultProfiles), err)
	}
	if _, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true}); err == nil {
		t.Fatal("expected empty profile selection error")
	}
	if _, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, resolverFile: filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Fatal("expected resolver file open error")
	}
	dir := t.TempDir()
	validPath := filepath.Join(dir, "resolvers.yaml")
	validYAML := "version: 1\nresolvers:\n  - id: local\n    name: Local\n    owner: Test\n    policy: unfiltered\n    addresses: [127.0.0.1]\n    transports:\n      udp:\n        port: 53\n"
	if err := os.WriteFile(validPath, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	profiles, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, resolverFile: validPath, resolverFlags: []string{"extra=tcp://127.0.0.2:5300"}})
	if err != nil || len(profiles) != 2 {
		t.Fatalf("custom profiles = %#v/%v", profiles, err)
	}
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("version: 2\nresolvers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, resolverFile: badPath}); err == nil {
		t.Fatal("expected invalid resolver YAML error")
	}
	if _, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, resolverFlags: []string{"bad"}}); err == nil {
		t.Fatal("expected invalid resolver flag error")
	}
	oldDiscover := discoverSystemResolvers
	t.Cleanup(func() { discoverSystemResolvers = oldDiscover })
	discoverSystemResolvers = func(context.Context) ([]catalog.ResolverProfile, error) {
		return []catalog.ResolverProfile{{ID: "system", Name: "System", Scope: "corp.example", Interface: "utun0", Addresses: []string{"127.0.0.1"}, Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}}}}, nil
	}
	profiles, err = loadProfiles(context.Background(), &cliConfig{noDefaults: true, includeSystem: true})
	if err != nil || len(profiles) != 1 || profiles[0].ID != "system" || profiles[0].Scope != "corp.example" || profiles[0].Interface != "utun0" {
		t.Fatalf("system profiles = %#v/%v", profiles, err)
	}
	discoverSystemResolvers = func(context.Context) ([]catalog.ResolverProfile, error) {
		return nil, errors.New("system discovery failed")
	}
	if _, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, includeSystem: true}); err == nil {
		t.Fatal("expected system discovery error")
	}
}

func TestRunBenchmarkValidationAndSelection(t *testing.T) {
	path := cliDomainFile(t)
	base := func() *cliConfig {
		return &cliConfig{protocols: "udp", resolverFlags: []string{"lab=udp://127.0.0.1:53"}, noDefaults: true, domainFile: path, sample: 1, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json"}
	}
	cases := []struct {
		name  string
		apply func(*cliConfig)
	}{
		{"format", func(c *cliConfig) { c.format = "xml" }},
		{"sample", func(c *cliConfig) { c.sample = 0 }},
		{"timeout", func(c *cliConfig) { c.timeout = 0 }},
		{"concurrency", func(c *cliConfig) { c.concurrency = 0 }},
		{"protocol", func(c *cliConfig) { c.protocols = "bad" }},
		{"types", func(c *cliConfig) { c.queryTypes = "ANY" }},
		{"domains", func(c *cliConfig) { c.domainFile = filepath.Join(t.TempDir(), "missing") }},
		{"resolver", func(c *cliConfig) { c.resolverFlags = []string{"bad"} }},
	}
	oldEngine := runBenchmarkEngine
	oldLoad := loadProfilesFunc
	t.Cleanup(func() { runBenchmarkEngine = oldEngine; loadProfilesFunc = oldLoad })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := base()
			tc.apply(config)
			if err := runBenchmark(context.Background(), config); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
	loadProfilesFunc = func(context.Context, *cliConfig) ([]catalog.ResolverProfile, error) {
		return []catalog.ResolverProfile{{ID: "bad", Name: "", Addresses: []string{"127.0.0.1"}}}, nil
	}
	if err := runBenchmark(context.Background(), base()); err == nil {
		t.Fatal("expected catalog validation error")
	}
	loadProfilesFunc = loadProfiles
	noSupport := base()
	noSupport.protocols = "doq"
	if err := runBenchmark(context.Background(), noSupport); err == nil || !strings.Contains(err.Error(), "no resolver supports") {
		t.Fatalf("unsupported target error = %v", err)
	}
	full := base()
	full.full = true
	full.sample = 0
	if err := runBenchmark(context.Background(), full); err != nil {
		t.Fatalf("full mode should pass sample validation: %v", err)
	}
}

func TestRunBenchmarkFormatsAndRuntimeErrors(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldLoad := loadProfilesFunc
	oldTable, oldJSON, oldCSV := writeTableReport, writeJSONReport, writeCSVReport
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		loadProfilesFunc = oldLoad
		writeTableReport, writeJSONReport, writeCSVReport = oldTable, oldJSON, oldCSV
	})
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		if options.OnProgress != nil && len(targets) > 0 {
			options.OnProgress(benchmark.Progress{Protocol: targets[0].Protocol, Completed: 1, Total: 1, Target: targets[0]})
		}
		return fakeCLIReport(), nil
	}
	for _, format := range []string{"table", "JSON", "csv"} {
		config := cliConfigForTest(t)
		config.format = format
		config.output = filepath.Join(t.TempDir(), format+".out")
		config.details = format == "table"
		config.raw = format == "JSON"
		config.redactSystem = format != "table"
		if format == "table" {
			config.seed = 0
		}
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatalf("format %s: %v", format, err)
		}
		content, err := os.ReadFile(config.output)
		if err != nil || len(content) == 0 {
			t.Fatalf("format %s output = %q/%v", format, content, err)
		}
	}
	config := cliConfigForTest(t)
	config.output = t.TempDir()
	if err := runBenchmark(context.Background(), config); err == nil {
		t.Fatal("expected output writer error")
	}

	writeJSONReport = func(io.Writer, benchmark.Report, bool) error { return errors.New("report write failed") }
	config = cliConfigForTest(t)
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "report write failed") {
		t.Fatalf("report writer error = %v", err)
	}
	writeJSONReport = oldJSON

	for _, runErr := range []error{context.Canceled, context.DeadlineExceeded} {
		runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
			return fakeCLIReport(), runErr
		}
		config = cliConfigForTest(t)
		config.output = filepath.Join(t.TempDir(), "interrupted.json")
		if err := runBenchmark(context.Background(), config); !errors.Is(err, runErr) {
			t.Fatalf("interrupted error = %v, want %v", err, runErr)
		}
	}
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return benchmark.Report{}, errors.New("engine failed")
	}
	if err := runBenchmark(context.Background(), cliConfigForTest(t)); err == nil || !strings.Contains(err.Error(), "engine failed") {
		t.Fatalf("zero-finished engine error = %v", err)
	}
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), errors.New("engine failed")
	}
	if err := runBenchmark(context.Background(), cliConfigForTest(t)); err == nil || !strings.Contains(err.Error(), "engine failed") {
		t.Fatalf("non-context engine error = %v", err)
	}
}

func TestRunBenchmarkEmitsNoComparableReports(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return benchmark.Report{
			StartedAt: time.Unix(1, 0), FinishedAt: time.Unix(2, 0), Seed: 42, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
			Targets: []benchmark.TargetResult{{
				Target: catalog.Target{Resolver: catalog.ResolverProfile{ID: "dead", Name: "Dead", Owner: "Test owner", Policy: "unfiltered"}, Protocol: catalog.UDP, Address: "192.0.2.1", Spec: catalog.TransportSpec{Port: 53}},
				Stats:  benchmark.Statistics{Total: 1, Failures: 1, SuccessRate: 0, FailureRate: 1}, OpenError: "connection refused",
			}},
			Warnings: []string{"Dead 192.0.2.1/udp could not open a session: connection refused"},
		}, benchmark.ErrNoComparableResults
	}
	for _, format := range []string{"table", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			config := cliConfigForTest(t)
			config.format = format
			config.output = filepath.Join(t.TempDir(), format+"-no-comparable.out")
			config.details = format == "table"
			err := runBenchmark(context.Background(), config)
			if !errors.Is(err, benchmark.ErrNoComparableResults) {
				t.Fatalf("run error = %v, want no-comparable status", err)
			}
			content, readErr := os.ReadFile(config.output)
			if readErr != nil || len(content) == 0 {
				t.Fatalf("diagnostic %s output = %q/%v", format, content, readErr)
			}
			text := string(content)
			for _, expected := range []string{"192.0.2.1", "connection refused"} {
				if !strings.Contains(text, expected) {
					t.Fatalf("diagnostic %s output missing %q: %s", format, expected, text)
				}
			}
		})
	}
}

func TestCobraOutputErrorsAreIgnoredBySimpleCommands(t *testing.T) {
	version := newVersionCommand()
	version.SetOut(cliErrorWriter{})
	version.SetArgs(nil)
	if err := version.Execute(); err != nil {
		t.Fatal(err)
	}
	resolvers := newResolversCommand()
	resolvers.SetOut(cliErrorWriter{})
	resolvers.SetArgs(nil)
	if err := resolvers.Execute(); err != nil {
		t.Fatal(err)
	}
	_ = newRootCommand()
}
