package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/crypt0rr/SpeeDNS/data"
	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/report"
	"github.com/crypt0rr/SpeeDNS/internal/systemdns"
	"github.com/crypt0rr/SpeeDNS/internal/textwidth"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"golang.org/x/text/width"
)

type cliErrorWriter struct{}

func (cliErrorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

var originalInterfaceAddressesFunc = interfaceAddressesFunc

type fakeNetAddr struct{}

func (fakeNetAddr) Network() string { return "fake" }
func (fakeNetAddr) String() string  { return "fake" }

type fakeOutputFile struct {
	bytes.Buffer
	name     string
	syncErr  error
	closeErr error
}

func (f *fakeOutputFile) Sync() error  { return f.syncErr }
func (f *fakeOutputFile) Close() error { return f.closeErr }
func (f *fakeOutputFile) Name() string { return f.name }

type progressSignalWriter struct {
	bytes.Buffer
	signal chan struct{}
	once   sync.Once
}

type progressFailWriter struct {
	data   []byte
	failAt int
	writes int
}

func (w *progressFailWriter) Write(value []byte) (int, error) {
	w.writes++
	if w.failAt > 0 && w.writes == w.failAt {
		return 0, errors.New("progress write failed")
	}
	w.data = append(w.data, value...)
	return len(value), nil
}

func (w *progressSignalWriter) Write(value []byte) (int, error) {
	n, err := w.Buffer.Write(value)
	w.once.Do(func() { close(w.signal) })
	return n, err
}

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
		domainFile: cliDomainFile(t), sample: 1, seed: 7, queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json", family: "4",
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
	for _, tc := range []struct {
		shell  string
		marker string
	}{
		{shell: "bash", marker: "__start_speedns"},
		{shell: "zsh", marker: "#compdef speedns"},
		{shell: "fish", marker: "complete -c speedns"},
		{shell: "powershell", marker: "Register-ArgumentCompleter"},
	} {
		t.Run("completion-"+tc.shell, func(t *testing.T) {
			root := newRootCommand()
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetArgs([]string{"completion", tc.shell})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), tc.marker) {
				t.Fatalf("completion output for %s missing %q", tc.shell, tc.marker)
			}
		})
	}
	invalidCompletion := newRootCommand()
	invalidCompletion.SetArgs([]string{"completion", "csh"})
	if err := invalidCompletion.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported shell") {
		t.Fatalf("invalid completion shell error = %v", err)
	}
	root := newRootCommand()
	if root.Use != "speedns" || root.Flags().Lookup("protocol") == nil || root.Flags().Lookup("redact-system") == nil || root.Flags().Lookup("assert") == nil || root.Flags().Lookup("family") == nil || root.Flags().Lookup("dnssec") == nil || root.Commands() == nil {
		t.Fatal("root command was not configured")
	}
	// The full subcommand set is pinned so that adding or removing one is a
	// deliberate test change rather than a silent change to the CLI surface.
	names := make([]string, 0, len(root.Commands()))
	commands := make(map[string]*cobra.Command, len(root.Commands()))
	for _, command := range root.Commands() {
		names = append(names, command.Name())
		commands[command.Name()] = command
	}
	sort.Strings(names)
	if got, want := strings.Join(names, ","), "completion,corpus,resolvers,run,version"; got != want {
		t.Fatalf("root subcommands = %q, want %q", got, want)
	}
	runCommand := commands["run"]
	if runCommand == nil || runCommand.Flags().Lookup("protocol") == nil {
		t.Fatal("explicit run command was not configured")
	}
	invalidRun := newRunCommand(&cliConfig{})
	invalidRun.SetArgs([]string{"--format", "invalid"})
	if err := invalidRun.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("invalid explicit run error = %v", err)
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
		{name: "assertion failed", err: ErrAssertionsFailed, want: 4},
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
		writer, finalize, err := outputWriter(path)
		if err != nil || writer != os.Stdout {
			t.Fatalf("stdout writer for %q = %#v/%v", path, writer, err)
		}
		if err := finalize(true); err != nil {
			t.Fatalf("stdout finalize for %q = %v", path, err)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "output.txt")
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "hello" {
		t.Fatalf("file output = %q/%v", content, err)
	}
	if _, _, err := outputWriter(dir); err == nil {
		t.Fatal("expected output directory creation error")
	}
	oldPath := filepath.Join(dir, "old.txt")
	if err := os.WriteFile(oldPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, finalize, err = outputWriter(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "discarded"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(false); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(oldPath)
	if err != nil || string(content) != "keep" {
		t.Fatalf("discarded output changed destination = %q/%v", content, err)
	}
	values := []string{"z", "a", "a", "m"}
	sort.Strings(values)
	if strings.Join(values, ",") != "a,a,m,z" {
		t.Fatalf("sorted values = %#v", values)
	}
	values = nil
	sort.Strings(values)
}

func TestActiveInterfaceNamesAreBestEffortAndSorted(t *testing.T) {
	oldList := listProvenanceInterfacesFunc
	t.Cleanup(func() { listProvenanceInterfacesFunc = oldList })
	listProvenanceInterfacesFunc = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "zeta", Flags: net.FlagUp},
			{Name: "down", Flags: 0},
			{Name: "alpha", Flags: net.FlagUp},
			{Name: "alpha", Flags: net.FlagUp},
		}, nil
	}
	if got := activeInterfaceNames(); strings.Join(got, ",") != "alpha,zeta" {
		t.Fatalf("interface names = %#v", got)
	}
	listProvenanceInterfacesFunc = func() ([]net.Interface, error) { return nil, errors.New("interfaces unavailable") }
	if got := activeInterfaceNames(); got != nil {
		t.Fatalf("failed interface discovery = %#v, want nil", got)
	}
}

// The progress renderer used to carry its own displayWidth helper. The shared
// package replaced it, so the widths it reports must still match exactly.
func TestDisplayWidthUsesTerminalCells(t *testing.T) {
	if got := textwidth.Display("ascii"); got != 5 {
		t.Fatalf("ASCII display width = %d", got)
	}
	if got := textwidth.Display("e\u0301"); got != 1 {
		t.Fatalf("combining display width = %d", got)
	}
	if got := textwidth.Display("東京"); got != 4 {
		t.Fatalf("wide display width = %d", got)
	}
}

// legacyDisplayWidth is the helper the progress renderer carried before the
// measurement moved into internal/textwidth. The shared function must agree
// with it on everything a progress line can contain.
func legacyDisplayWidth(value string) int {
	result := 0
	for _, character := range value {
		if unicode.Is(unicode.Mn, character) || unicode.Is(unicode.Me, character) {
			continue
		}
		switch width.LookupRune(character).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			result += 2
		default:
			result++
		}
	}
	return result
}

func TestDisplayWidthMatchesPreviousProgressBehaviour(t *testing.T) {
	values := []string{
		"",
		"testing | udp measuring 3/10 | elapsed 00:07 | " + progressSpinner[0],
		"tested doh 2/2 targets",
		"e\u0301clair.example",
		"東京.example",
		"\uff21\uff22\uff23",
		"resolver.example 192.0.2.53",
	}
	for _, value := range values {
		if got, want := textwidth.Display(value), legacyDisplayWidth(value); got != want {
			t.Fatalf("display width of %q = %d, want %d", value, got, want)
		}
	}
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
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	logProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesTotal: 2})
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 2, ExchangesTotal: 2})
	logProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesTotal: 2})
	logProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 2, ExchangesTotal: 2})
	logProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Phase: benchmark.ProgressPreparing, TargetsCompleted: 0, TargetsTotal: 1})
	logProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesTotal: 2})
	logProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 1, ExchangesTotal: 2})
	want := "progress doq: preparing 0/1 targets\nprogress udp: preparing 0/1 targets\nprogress doq: preparing 1/1 targets\nprogress doq: measuring 0/2 exchanges\nprogress doq: measuring 2/2 exchanges\ntested doq 1/1 targets\nprogress udp: preparing 1/1 targets\nprogress udp: measuring 0/2 exchanges\nprogress udp: measuring 2/2 exchanges\ntested udp 1/1 targets\nprogress tcp: preparing 0/1 targets\nprogress tcp: preparing 1/1 targets\nprogress tcp: measuring 0/2 exchanges\nprogress tcp: measuring 1/2 exchanges\ntested tcp 1/1 targets\n"
	if got := logOutput.String(); got != want {
		t.Fatalf("non-TTY progress = %q, want %q", got, want)
	}
	if strings.Contains(logOutput.String(), "192.0.2.") {
		t.Fatalf("non-TTY progress leaked target addresses: %q", logOutput.String())
	}
	beforeStale := logOutput.String()
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 1, ExchangesTotal: 2})
	if got := logOutput.String(); got != beforeStale {
		t.Fatalf("stale progress phase was rendered after completion: %q", got)
	}
	logProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 2, ExchangesTotal: 2})
	if got := logOutput.String(); got != beforeStale {
		t.Fatalf("duplicate progress phase was rendered: %q", got)
	}

	var ttyOutput bytes.Buffer
	ttyProgress := newProgressRenderer(&ttyOutput, true, selected, targets)
	ttyProgress.refreshInterval = time.Hour
	ttyProgress.Start()
	ttyProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	ttyProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsCompleted: 1, TargetsTotal: 1})
	base := ttyProgress.started
	ttyProgress.lastLineWidth = 200
	ttyProgress.renderAt(base.Add(2 * time.Second))
	ttyProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 1, ExchangesTotal: 2})
	ttyProgress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 2, ExchangesTotal: 2})
	ttyProgress.Finish()
	if !strings.Contains(ttyOutput.String(), "testing | udp queued | tcp queued | doq queued") {
		t.Fatalf("TTY progress did not use canonical order: %q", ttyOutput.String())
	}
	if !strings.Contains(ttyOutput.String(), "testing | udp preparing 1/1 | tcp queued | doq preparing 0/1") {
		t.Fatalf("TTY progress did not use canonical order: %q", ttyOutput.String())
	}
	if !strings.Contains(ttyOutput.String(), "elapsed 00:02") || !strings.Contains(ttyOutput.String(), "\\") {
		t.Fatalf("TTY progress did not render elapsed spinner refresh: %q", ttyOutput.String())
	}
	if !strings.HasSuffix(ttyOutput.String(), "\n") {
		t.Fatalf("TTY progress was not terminated before the report: %q", ttyOutput.String())
	}
	ttyProgress.Finish()

	var fallbackOutput bytes.Buffer
	fallbackProgress := newProgressRenderer(&fallbackOutput, false, []catalog.Protocol{catalog.UDP}, nil)
	fallbackProgress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1})
	if fallbackOutput.String() != "tested udp 1/1 targets\n" {
		t.Fatalf("fallback progress = %q", fallbackOutput.String())
	}
}

func TestProgressRendererHandlesConcurrentUpdates(t *testing.T) {
	var output bytes.Buffer
	progress := newProgressRenderer(&output, false, []catalog.Protocol{catalog.UDP}, []catalog.Target{{Protocol: catalog.UDP}})
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			progress.Update(benchmark.Progress{
				Protocol:           catalog.UDP,
				Phase:              benchmark.ProgressMeasuring,
				TargetsCompleted:   1,
				TargetsTotal:       1,
				ExchangesCompleted: index,
				ExchangesTotal:     32,
			})
		}(index)
	}
	workers.Wait()
	progress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 32, ExchangesTotal: 32})
	if !strings.Contains(output.String(), "progress udp: measuring") || !strings.Contains(output.String(), "tested udp 1/1 targets") {
		t.Fatalf("concurrent progress output = %q", output.String())
	}
}

func TestNonInteractiveProgressReportsMilestones(t *testing.T) {
	var output bytes.Buffer
	progress := newProgressRenderer(&output, false, []catalog.Protocol{catalog.UDP}, []catalog.Target{{Protocol: catalog.UDP, Address: "192.0.2.1"}})
	progress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	for exchange := 0; exchange <= 20; exchange++ {
		progress.Update(benchmark.Progress{
			Protocol:           catalog.UDP,
			Phase:              benchmark.ProgressMeasuring,
			TargetsCompleted:   1,
			TargetsTotal:       1,
			ExchangesCompleted: exchange,
			ExchangesTotal:     20,
		})
	}
	progress.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 20, ExchangesTotal: 20})

	want := "progress udp: preparing 0/1 targets\n" +
		"progress udp: preparing 1/1 targets\n" +
		"progress udp: measuring 0/20 exchanges\n" +
		"progress udp: measuring 5/20 exchanges\n" +
		"progress udp: measuring 10/20 exchanges\n" +
		"progress udp: measuring 15/20 exchanges\n" +
		"progress udp: measuring 20/20 exchanges\n" +
		"tested udp 1/1 targets\n"
	if got := output.String(); got != want {
		t.Fatalf("milestone progress = %q, want %q", got, want)
	}
	if strings.Contains(output.String(), "192.0.2.") || strings.Contains(output.String(), "elapsed") {
		t.Fatalf("milestone progress leaked an address or an ETA: %q", output.String())
	}
}

func TestNonInteractiveProgressReportsFinalStateForSmallAndEmptyTotals(t *testing.T) {
	var small bytes.Buffer
	smallProgress := newProgressRenderer(&small, false, []catalog.Protocol{catalog.TCP}, []catalog.Target{{Protocol: catalog.TCP}})
	smallProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	smallProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesTotal: 2})
	smallProgress.Update(benchmark.Progress{Protocol: catalog.TCP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 2, ExchangesTotal: 2})
	wantSmall := "progress tcp: preparing 0/1 targets\n" +
		"progress tcp: preparing 1/1 targets\n" +
		"progress tcp: measuring 0/2 exchanges\n" +
		"progress tcp: measuring 2/2 exchanges\n" +
		"tested tcp 1/1 targets\n"
	if got := small.String(); got != wantSmall {
		t.Fatalf("small-total progress = %q, want %q", got, wantSmall)
	}

	var empty bytes.Buffer
	emptyProgress := newProgressRenderer(&empty, false, []catalog.Protocol{catalog.DoH}, nil)
	emptyProgress.Update(benchmark.Progress{Protocol: catalog.DoH, Phase: benchmark.ProgressMeasuring})
	emptyProgress.Update(benchmark.Progress{Protocol: catalog.DoH, Phase: benchmark.ProgressMeasuring})
	emptyProgress.Update(benchmark.Progress{Protocol: catalog.DoH, Phase: benchmark.ProgressComplete})
	wantEmpty := "progress doh: measuring 0/0 exchanges\ntested doh 0/0 targets\n"
	if got := empty.String(); got != wantEmpty {
		t.Fatalf("zero-total progress = %q, want %q", got, wantEmpty)
	}

	var unknown bytes.Buffer
	unknownProgress := newProgressRenderer(&unknown, false, []catalog.Protocol{catalog.DoT}, nil)
	unknownProgress.Update(benchmark.Progress{Protocol: catalog.DoT, Phase: benchmark.ProgressPhase("unknown")})
	if unknown.Len() != 0 {
		t.Fatalf("unknown progress phase = %q", unknown.String())
	}
}

func TestProgressRendererKeepsDependencyDiagnosticsReadable(t *testing.T) {
	var output bytes.Buffer
	progress := newProgressRenderer(&output, true, []catalog.Protocol{catalog.DoQ}, []catalog.Target{{Protocol: catalog.DoQ}})
	progress.refreshInterval = time.Hour
	progress.Start()
	progress.Update(benchmark.Progress{Protocol: catalog.DoQ, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	if _, err := progress.Write([]byte("2026/08/21 warning from transport\n")); err != nil {
		t.Fatal(err)
	}
	progress.Finish()

	text := output.String()
	if !strings.Contains(text, "warning from transport\n") {
		t.Fatalf("diagnostic was not emitted: %q", text)
	}
	if !strings.Contains(text, "\r2026/08/21 warning from transport\n\rtesting") {
		t.Fatalf("diagnostic did not interrupt and restore progress cleanly: %q", text)
	}
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("progress output was not terminated: %q", text)
	}
}

func TestProgressRendererWriteErrorPaths(t *testing.T) {
	var raw bytes.Buffer
	nonInteractive := newProgressRenderer(&raw, false, []catalog.Protocol{catalog.UDP}, nil)
	if _, err := nonInteractive.Write([]byte("raw diagnostic")); err != nil {
		t.Fatal(err)
	}
	if raw.String() != "raw diagnostic" {
		t.Fatalf("non-interactive diagnostic = %q", raw.String())
	}

	finished := newProgressRenderer(&raw, true, []catalog.Protocol{catalog.UDP}, nil)
	finished.finished = true
	if _, err := finished.Write([]byte("finished diagnostic")); err != nil {
		t.Fatal(err)
	}

	noLine := newProgressRenderer(&raw, true, []catalog.Protocol{catalog.UDP}, nil)
	if _, err := noLine.Write([]byte("not rendered")); err != nil {
		t.Fatal(err)
	}

	clearError := newProgressRenderer(&cliErrorWriter{}, true, []catalog.Protocol{catalog.UDP}, nil)
	clearError.rendered = true
	clearError.lastLineWidth = 5
	if _, err := clearError.Write([]byte("diagnostic")); err == nil {
		t.Fatal("expected progress-line clear error")
	}

	diagnosticErrorWriter := &progressFailWriter{failAt: 2}
	diagnosticError := newProgressRenderer(diagnosticErrorWriter, true, []catalog.Protocol{catalog.UDP}, nil)
	diagnosticError.rendered = true
	diagnosticError.lastLineWidth = 5
	if _, err := diagnosticError.Write([]byte("diagnostic\n")); err == nil {
		t.Fatal("expected diagnostic write error")
	}

	newlineErrorWriter := &progressFailWriter{failAt: 3}
	newlineError := newProgressRenderer(newlineErrorWriter, true, []catalog.Protocol{catalog.UDP}, nil)
	newlineError.rendered = true
	newlineError.lastLineWidth = 5
	if _, err := newlineError.Write([]byte("diagnostic")); err == nil {
		t.Fatal("expected diagnostic newline error")
	}
}

func TestProgressRendererLifecycleAndTimingEdges(t *testing.T) {
	finished := newProgressRenderer(io.Discard, false, []catalog.Protocol{catalog.UDP}, nil)
	finished.Finish()
	finished.Start()
	finished.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	finished.renderAt(time.Now())

	var interactiveOutput bytes.Buffer
	interactive := newProgressRenderer(&interactiveOutput, true, []catalog.Protocol{catalog.UDP}, []catalog.Target{{Protocol: catalog.UDP}})
	interactive.renderAt(time.Unix(10, 0))
	interactive.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
	interactive.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 1, ExchangesTotal: 1})
	interactive.Update(benchmark.Progress{Protocol: catalog.UDP, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 1, ExchangesTotal: 1})
	interactive.Finish()
	interactive.renderAt(time.Unix(11, 0))

	var refreshOutput progressSignalWriter
	refreshOutput.signal = make(chan struct{})
	live := newProgressRenderer(&refreshOutput, true, []catalog.Protocol{catalog.UDP}, []catalog.Target{{Protocol: catalog.UDP}})
	live.started = time.Now()
	stop := make(chan struct{})
	done := make(chan struct{})
	go live.refreshLoop(stop, done, time.Millisecond)
	select {
	case <-refreshOutput.signal:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("live progress refresh did not render")
	}
	close(stop)
	<-done

	defaultStop := make(chan struct{})
	defaultDone := make(chan struct{})
	go live.refreshLoop(defaultStop, defaultDone, 0)
	close(defaultStop)
	<-defaultDone

	skip := newProgressRenderer(io.Discard, true, []catalog.Protocol{catalog.UDP}, []catalog.Target{{Protocol: catalog.UDP}})
	skip.finished = true
	skipStop := make(chan struct{})
	skipDone := make(chan struct{})
	go skip.refreshLoop(skipStop, skipDone, time.Millisecond)
	time.Sleep(3 * time.Millisecond)
	close(skipStop)
	<-skipDone

	var unknown bytes.Buffer
	unknownProgress := newProgressRenderer(&unknown, false, nil, nil)
	unknownProgress.Update(benchmark.Progress{Protocol: catalog.DoH, Phase: benchmark.ProgressPhase("unknown")})
	if unknown.Len() != 0 {
		t.Fatalf("unknown progress phase output = %q", unknown.String())
	}
	if got := progressElapsed(time.Time{}, time.Now()); got != "00:00" {
		t.Fatalf("zero progress elapsed = %q", got)
	}
	if got := progressElapsed(time.Unix(2, 0), time.Unix(1, 0)); got != "00:00" {
		t.Fatalf("reverse progress elapsed = %q", got)
	}
	if got := progressElapsed(time.Unix(0, 0), time.Unix(3600+62, 0)); got != "01:01:02" {
		t.Fatalf("long progress elapsed = %q", got)
	}
	_, _ = originalInterfaceAddressesFunc(net.Interface{})
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

func TestDetectAddressFamilies(t *testing.T) {
	oldInterfaces := listNetworkInterfacesFunc
	oldAddresses := interfaceAddressesFunc
	t.Cleanup(func() {
		listNetworkInterfacesFunc = oldInterfaces
		interfaceAddressesFunc = oldAddresses
	})
	listNetworkInterfacesFunc = func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "down", Flags: 0},
			{Name: "up", Flags: net.FlagUp},
		}, nil
	}
	interfaceAddressesFunc = func(iface net.Interface) ([]net.Addr, error) {
		if iface.Name == "down" {
			return nil, errors.New("down interface should not be inspected")
		}
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.10")},
			&net.IPNet{IP: net.ParseIP("2001:db8::10")},
			&net.IPAddr{IP: net.ParseIP("127.0.0.1")},
			fakeNetAddr{},
		}, nil
	}
	available, err := detectAddressFamilies()
	if err != nil || !available[catalog.Family4] || !available[catalog.Family6] {
		t.Fatalf("detected families = %#v/%v", available, err)
	}
	for _, address := range []net.Addr{&net.IPNet{}, &net.IPAddr{}, fakeNetAddr{}, nil} {
		if ip, ok := interfaceAddressIP(address); ok || ip != nil {
			t.Fatalf("invalid interface address = %#v/%v", ip, ok)
		}
	}
	listNetworkInterfacesFunc = func() ([]net.Interface, error) { return nil, errors.New("interfaces unavailable") }
	if _, err := detectAddressFamilies(); err == nil || !strings.Contains(err.Error(), "inspect network interfaces") {
		t.Fatalf("interface discovery error = %v", err)
	}
	listNetworkInterfacesFunc = func() ([]net.Interface, error) { return []net.Interface{{Name: "up", Flags: net.FlagUp}}, nil }
	interfaceAddressesFunc = func(net.Interface) ([]net.Addr, error) { return nil, errors.New("addresses unavailable") }
	if _, err := detectAddressFamilies(); err == nil || !strings.Contains(err.Error(), "inspect addresses") {
		t.Fatalf("address discovery error = %v", err)
	}
}

func TestDetectAddressFamiliesIgnoresUniqueLocalIPv6(t *testing.T) {
	oldInterfaces := listNetworkInterfacesFunc
	oldAddresses := interfaceAddressesFunc
	t.Cleanup(func() {
		listNetworkInterfacesFunc = oldInterfaces
		interfaceAddressesFunc = oldAddresses
	})
	listNetworkInterfacesFunc = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "up", Flags: net.FlagUp}}, nil
	}
	var addresses []net.Addr
	interfaceAddressesFunc = func(net.Interface) ([]net.Addr, error) { return addresses, nil }

	// RFC 1918 IPv4 counts because NAT is a real path to the Internet, while
	// unique-local IPv6 (fc00::/7) is not evidence of a public IPv6 route even
	// though net.IP.IsGlobalUnicast reports true for it.
	addresses = []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.10")},
		&net.IPNet{IP: net.ParseIP("fd47:a90b:1d35:4f2d::1")},
		&net.IPNet{IP: net.ParseIP("fd7a:115c:a1e0::6a36:ec14")},
		&net.IPNet{IP: net.ParseIP("fe80::1")},
		&net.IPAddr{IP: net.ParseIP("::1")},
		&net.IPAddr{IP: net.ParseIP("127.0.0.1")},
		&net.IPNet{IP: net.ParseIP("169.254.1.1")},
	}
	available, err := detectAddressFamilies()
	if err != nil || !available[catalog.Family4] || available[catalog.Family6] {
		t.Fatalf("ULA-only host families = %#v/%v", available, err)
	}

	addresses = append(addresses, &net.IPNet{IP: net.ParseIP("2606:4700:4700::1111")})
	available, err = detectAddressFamilies()
	if err != nil || !available[catalog.Family4] || !available[catalog.Family6] {
		t.Fatalf("global-unicast host families = %#v/%v", available, err)
	}
}

func TestRunBenchmarkAutoFamilyKeepsExplicitResolvers(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldDetector := detectAddressFamiliesFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		detectAddressFamiliesFunc = oldDetector
	})
	var captured []catalog.Target
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		captured = append([]catalog.Target(nil), targets...)
		return fakeCLIReport(), nil
	}
	detectAddressFamiliesFunc = func() (map[catalog.AddressFamily]bool, error) {
		return map[catalog.AddressFamily]bool{catalog.Family4: true}, nil
	}
	newConfig := func(family string) *cliConfig {
		return &cliConfig{
			protocols: "udp", resolverFlags: []string{"mine=udp://[fd00::1]:53"}, noDefaults: true,
			domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A", timeout: time.Second,
			concurrency: 1, format: "json", family: family, output: filepath.Join(t.TempDir(), family+".json"),
		}
	}
	if err := runBenchmark(context.Background(), newConfig("auto")); err != nil {
		t.Fatalf("auto run with explicit ULA resolver = %v", err)
	}
	if len(captured) != 1 || captured[0].Address != "fd00::1" {
		t.Fatalf("explicit ULA resolver dropped by --family auto: %#v", captured)
	}
	if err := runBenchmark(context.Background(), newConfig("4")); err == nil || !strings.Contains(err.Error(), "no resolver addresses match") {
		t.Fatalf("explicit --family 4 should still filter explicit resolvers: %v", err)
	}
}

func TestRunBenchmarkAutoFamilyWarnsAboutDroppedCatalogAddresses(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldDetector := detectAddressFamiliesFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		detectAddressFamiliesFunc = oldDetector
	})
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}
	for _, test := range []struct {
		name      string
		available map[catalog.AddressFamily]bool
		want      string
		absent    string
	}{
		{name: "v4only", available: map[catalog.AddressFamily]bool{catalog.Family4: true}, want: "--family auto detected IPv4 on local interfaces and dropped"},
		{name: "v6only", available: map[catalog.AddressFamily]bool{catalog.Family6: true}, want: "--family auto detected IPv6 on local interfaces and dropped"},
		{name: "both", available: map[catalog.AddressFamily]bool{catalog.Family4: true, catalog.Family6: true}, absent: "--family auto detected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			detectAddressFamiliesFunc = func() (map[catalog.AddressFamily]bool, error) { return test.available, nil }
			config := &cliConfig{
				protocols: "udp", domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A",
				timeout: time.Second, concurrency: 1, format: "json", family: "auto",
				output: filepath.Join(t.TempDir(), "auto.json"),
			}
			if err := runBenchmark(context.Background(), config); err != nil {
				t.Fatalf("auto run = %v", err)
			}
			content, err := os.ReadFile(config.output)
			if err != nil {
				t.Fatal(err)
			}
			if test.want != "" && !strings.Contains(string(content), test.want) {
				t.Fatalf("missing auto-family warning %q in %s", test.want, content)
			}
			if test.absent != "" && strings.Contains(string(content), test.absent) {
				t.Fatalf("unexpected auto-family warning in %s", content)
			}
		})
	}
}

func TestLoadProfilesAllSourcesAndErrors(t *testing.T) {
	defaultProfiles, err := loadProfiles(context.Background(), &cliConfig{})
	if err != nil || len(defaultProfiles.bundled()) != 10 || len(defaultProfiles.explicit()) != 0 || len(defaultProfiles.all()) != 10 {
		t.Fatalf("default profiles = %#v/%v", defaultProfiles, err)
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
	if err != nil || len(profiles.bundled()) != 0 || len(profiles.explicit()) != 2 {
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
	if err != nil || len(profiles.explicit()) != 1 || profiles.explicit()[0].ID != "system" || profiles.explicit()[0].Scope != "corp.example" || profiles.explicit()[0].Interface != "utun0" {
		t.Fatalf("system profiles = %#v/%v", profiles, err)
	}
	discoverSystemResolvers = func(context.Context) ([]catalog.ResolverProfile, error) {
		return nil, errors.New("system discovery failed")
	}
	if _, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, includeSystem: true}); err == nil {
		t.Fatal("expected system discovery error")
	}
}

// Discovery can fail for reasons the rest of the run does not depend on, such
// as an unsupported platform. That must not discard the resolvers the user
// selected explicitly.
func TestLoadProfilesWarnsWhenSystemDiscoveryFails(t *testing.T) {
	oldDiscover := discoverSystemResolvers
	oldWarningWriter := warningWriterFunc
	t.Cleanup(func() {
		discoverSystemResolvers = oldDiscover
		warningWriterFunc = oldWarningWriter
	})
	if oldWarningWriter() != os.Stderr {
		t.Fatal("warnings must default to stderr")
	}
	discoverSystemResolvers = func(context.Context) ([]catalog.ResolverProfile, error) {
		return nil, &systemdns.UnsupportedPlatformError{OS: "windows"}
	}
	var warnings bytes.Buffer
	warningWriterFunc = func() io.Writer { return &warnings }

	selection, err := loadProfiles(context.Background(), &cliConfig{noDefaults: true, includeSystem: true, resolverFlags: []string{"lab=udp://127.0.0.1:5300"}})
	profiles := selection.all()
	if err != nil || len(profiles) != 1 || profiles[0].ID != "custom-lab" {
		t.Fatalf("profiles with failed system discovery = %#v/%v", profiles, err)
	}
	if !strings.Contains(warnings.String(), "system resolver discovery failed") || !strings.Contains(warnings.String(), "windows") {
		t.Fatalf("discovery warning = %q", warnings.String())
	}
}

func TestRunBenchmarkValidationAndSelection(t *testing.T) {
	path := cliDomainFile(t)
	base := func() *cliConfig {
		return &cliConfig{protocols: "udp", resolverFlags: []string{"lab=udp://127.0.0.1:53"}, noDefaults: true, domainFile: path, sample: 1, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1, format: "json", family: "4"}
	}
	cases := []struct {
		name  string
		apply func(*cliConfig)
	}{
		{"format", func(c *cliConfig) { c.format = "xml" }},
		{"profile csv", func(c *cliConfig) { c.format = "csv"; c.profileView = true }},
		{"sample", func(c *cliConfig) { c.sample = 0 }},
		{"timeout", func(c *cliConfig) { c.timeout = 0 }},
		{"concurrency", func(c *cliConfig) { c.concurrency = 0 }},
		{"family", func(c *cliConfig) { c.family = "5" }},
		{"protocol", func(c *cliConfig) { c.protocols = "bad" }},
		{"types", func(c *cliConfig) { c.queryTypes = "ANY" }},
		{"assertion", func(c *cliConfig) { c.assertions = []string{"bad"} }},
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
	loadProfilesFunc = func(context.Context, *cliConfig) (profileSelection, error) {
		return profileSelection{profiles: []catalog.ResolverProfile{{ID: "bad", Name: "", Addresses: []string{"127.0.0.1"}}}}, nil
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

func TestRunBenchmarkRejectsUnknownAssertionWinner(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		result := benchmark.TargetResult{Target: targets[0], Stats: benchmark.Statistics{Total: 1, Successes: 1, Scored: 1, SuccessRate: 1, UsableRate: 1, MedianMS: 1, P95MS: 1, ScoreMS: 1}}
		return benchmark.Report{
			StartedAt: time.Unix(1, 0), FinishedAt: time.Unix(2, 0), Seed: 7, SampleSize: 1, Queries: 1, QueryTypes: []uint16{1},
			Targets:  []benchmark.TargetResult{result},
			Rankings: []benchmark.Ranking{{Protocol: catalog.UDP, TargetID: targets[0].ID(), Rank: 1}},
		}, nil
	}

	unknown := cliConfigForTest(t)
	unknown.output = filepath.Join(t.TempDir(), "unknown.json")
	unknown.assertions = []string{"winner=custom-labb"}
	err := runBenchmark(context.Background(), unknown)
	if err == nil || !strings.Contains(err.Error(), "no selected resolver matches") {
		t.Fatalf("unknown winner error = %v", err)
	}
	if code := exitCodeForError(err); code != 2 {
		t.Fatalf("unknown winner exit code = %d, want 2 (invalid input) rather than 4", code)
	}
	if _, statErr := os.Stat(unknown.output); !os.IsNotExist(statErr) {
		t.Fatalf("unknown winner must fail before the report is written: %v", statErr)
	}

	for _, winner := range []string{"custom-lab", "custom-lab@127.0.0.1/udp"} {
		known := cliConfigForTest(t)
		known.output = filepath.Join(t.TempDir(), "known.json")
		known.assertions = []string{"winner=" + winner}
		if err := runBenchmark(context.Background(), known); err != nil {
			t.Fatalf("winner=%s run = %v", winner, err)
		}
	}
}

func TestRunBenchmarkFamilySelection(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldDetector := detectAddressFamiliesFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		detectAddressFamiliesFunc = oldDetector
	})
	var captured []catalog.Target
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		captured = append([]catalog.Target(nil), targets...)
		return fakeCLIReport(), nil
	}
	for _, test := range []struct {
		family string
		count  int
	}{
		{family: "4", count: 1},
		{family: "6", count: 1},
		{family: "both", count: 2},
	} {
		config := &cliConfig{
			protocols: "udp", resolverFlags: []string{"v4=udp://192.0.2.53:53", "v6=udp://[2001:db8::53]:53"},
			noDefaults: true, domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A", timeout: time.Second,
			concurrency: 1, format: "json", family: test.family, output: filepath.Join(t.TempDir(), test.family+".json"),
		}
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatalf("family %s run = %v", test.family, err)
		}
		if len(captured) != test.count {
			t.Fatalf("family %s targets = %d, want %d (%#v)", test.family, len(captured), test.count, captured)
		}
	}

	config := &cliConfig{
		protocols: "udp", resolverFlags: []string{"v4=udp://192.0.2.53:53"}, noDefaults: true,
		domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1,
		format: "json", family: "6", output: filepath.Join(t.TempDir(), "empty.json"),
	}
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "no resolver addresses match") {
		t.Fatalf("empty family selection error = %v", err)
	}

	detectAddressFamiliesFunc = func() (map[catalog.AddressFamily]bool, error) {
		return nil, errors.New("family detector failed")
	}
	config = &cliConfig{
		protocols: "udp", resolverFlags: []string{"v4=udp://192.0.2.53:53"}, noDefaults: true,
		domainFile: cliDomainFile(t), sample: 1, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1,
		format: "json", family: "auto", output: filepath.Join(t.TempDir(), "detector.json"),
	}
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "family detector failed") {
		t.Fatalf("family detector error = %v", err)
	}
	detectAddressFamiliesFunc = oldDetector
	config.resolverFlags = []string{"hostname=udp://dns.example:53"}
	config.family = "4"
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "not an IP literal") {
		t.Fatalf("hostname family error = %v", err)
	}

	oldLoad := loadProfilesFunc
	t.Cleanup(func() { loadProfilesFunc = oldLoad })
	loadProfilesFunc = func(context.Context, *cliConfig) (profileSelection, error) {
		// explicitFrom past the end makes this a bundled profile, so the
		// filter that prunes the catalog is the one that reports the error.
		return profileSelection{profiles: []catalog.ResolverProfile{{
			ID: "hostname", Name: "Hostname", Owner: "Test", Policy: "unfiltered",
			Addresses:  []string{"dns.example"},
			Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}},
		}}, explicitFrom: 1}, nil
	}
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "not an IP literal") {
		t.Fatalf("bundled hostname family error = %v", err)
	}
}

func TestRunBenchmarkCacheMissSafetyAndMetadata(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldNonce := newCacheMissNonceFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		newCacheMissNonceFunc = oldNonce
	})
	var captured benchmark.Options
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		captured = options
		return fakeCLIReport(), nil
	}
	newCacheMissNonceFunc = func() (string, error) { return "0123456789abcdef", nil }
	config := &cliConfig{
		protocols: "udp", resolverFlags: []string{"lab=udp://127.0.0.1:53"}, noDefaults: true,
		cacheMiss: true, cacheMissSample: 2, sample: 100, seed: 7, queryTypes: "A", timeout: time.Second,
		concurrency: 4, format: "json", profileView: true, family: "4", output: filepath.Join(t.TempDir(), "cache.json"),
	}
	if err := runBenchmark(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(captured.Domains) != 2 || !strings.HasPrefix(captured.Domains[0], "speedns-0123456789abcdef-") || captured.Concurrency != 2 {
		t.Fatalf("cache-miss engine options = %#v", captured)
	}
	content, err := os.ReadFile(config.output)
	if err != nil || !strings.Contains(string(content), "\"corpus_mode\": \"cache-miss\"") || !strings.Contains(string(content), "cache-miss mode capped concurrency at 2") || !strings.Contains(string(content), "\"profile_comparisons\"") || !strings.Contains(string(content), "\"corpus_entries\": 2") || !strings.Contains(string(content), "\"corpus_sha256\"") || !strings.Contains(string(content), "\"protocols\"") {
		t.Fatalf("cache-miss report = %q/%v", content, err)
	}

	config.domainFile = cliDomainFile(t)
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "cannot be combined with --domains") {
		t.Fatalf("cache-miss domain combination error = %v", err)
	}
	config.domainFile = ""
	config.full = true
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "cannot be combined with --full") {
		t.Fatalf("cache-miss full combination error = %v", err)
	}
	config.full = false
	config.cacheMissSample = 0
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "cache-miss sample") {
		t.Fatalf("cache-miss sample error = %v", err)
	}
	config.cacheMissSample = 2
	newCacheMissNonceFunc = func() (string, error) { return "", errors.New("nonce fixture failed") }
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "nonce fixture failed") {
		t.Fatalf("cache-miss nonce error = %v", err)
	}
}

func TestRunBenchmarkFormatsAndRuntimeErrors(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldLoad := loadProfilesFunc
	oldTable, oldJSON, oldCSV, oldOutputWriter := writeTableReport, writeJSONReport, writeCSVReport, outputWriterFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		loadProfilesFunc = oldLoad
		writeTableReport, writeJSONReport, writeCSVReport = oldTable, oldJSON, oldCSV
		outputWriterFunc = oldOutputWriter
	})
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		if options.OnProgress != nil && len(targets) > 0 {
			options.OnProgress(benchmark.Progress{Protocol: targets[0].Protocol, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1})
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

	writeJSONReport = func(io.Writer, benchmark.Report, bool, report.JSONOptions) error {
		return errors.New("report write failed")
	}
	config = cliConfigForTest(t)
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "report write failed") {
		t.Fatalf("report writer error = %v", err)
	}
	writeJSONReport = oldJSON
	outputWriterFunc = func(string) (io.Writer, outputFinalizer, error) {
		return io.Discard, func(bool) error { return errors.New("finalize failed") }, nil
	}
	if err := runBenchmark(context.Background(), cliConfigForTest(t)); err == nil || !strings.Contains(err.Error(), "finalize failed") {
		t.Fatalf("finalizer error = %v", err)
	}
	writeJSONReport = func(io.Writer, benchmark.Report, bool, report.JSONOptions) error {
		return errors.New("report write failed")
	}
	if err := runBenchmark(context.Background(), cliConfigForTest(t)); err == nil || !strings.Contains(err.Error(), "report write failed") || !strings.Contains(err.Error(), "finalize failed") {
		t.Fatalf("combined report/finalizer error = %v", err)
	}
	writeJSONReport = oldJSON
	outputWriterFunc = oldOutputWriter

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

func TestRunBenchmarkProgressUsesStderrAndMachineFormatsStaySilent(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldDetector := terminalDetector
	oldProgressWriter := progressWriterFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		terminalDetector = oldDetector
		progressWriterFunc = oldProgressWriter
	})
	terminalDetector = func(*os.File) bool { return false }
	var stderr bytes.Buffer
	progressWriterFunc = func() io.Writer { return &stderr }
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		if options.OnProgress != nil {
			options.OnProgress(benchmark.Progress{Protocol: targets[0].Protocol, Phase: benchmark.ProgressPreparing, TargetsTotal: 1})
			options.OnProgress(benchmark.Progress{Protocol: targets[0].Protocol, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 1, TargetsTotal: 1, ExchangesTotal: 1})
			options.OnProgress(benchmark.Progress{Protocol: targets[0].Protocol, Phase: benchmark.ProgressComplete, TargetsCompleted: 1, TargetsTotal: 1, ExchangesCompleted: 1, ExchangesTotal: 1})
		}
		return fakeCLIReport(), nil
	}

	tableConfig := cliConfigForTest(t)
	tableConfig.format = "table"
	tableConfig.output = filepath.Join(t.TempDir(), "table.out")
	if err := runBenchmark(context.Background(), tableConfig); err != nil {
		t.Fatalf("table benchmark = %v", err)
	}
	if got := stderr.String(); got != "progress udp: preparing 0/1 targets\nprogress udp: preparing 1/1 targets\nprogress udp: measuring 0/1 exchanges\nprogress udp: measuring 1/1 exchanges\ntested udp 1/1 targets\n" {
		t.Fatalf("table progress stderr = %q", got)
	}
	reportBytes, err := os.ReadFile(tableConfig.output)
	if err != nil || strings.Contains(string(reportBytes), "progress udp") {
		t.Fatalf("table report stream = %q/%v", reportBytes, err)
	}

	for _, format := range []string{"json", "csv"} {
		stderr.Reset()
		config := cliConfigForTest(t)
		config.format = format
		config.output = filepath.Join(t.TempDir(), format+".out")
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatalf("%s benchmark = %v", format, err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("%s progress stderr = %q, want silent", format, stderr.String())
		}
	}
}

func TestRunBenchmarkSuppressesDependencyLogsForMachineFormats(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldLogWriter := log.Writer()
	var stderr bytes.Buffer
	log.SetOutput(&stderr)
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		log.SetOutput(oldLogWriter)
	})
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		log.Print("transport diagnostic")
		return fakeCLIReport(), nil
	}

	for _, format := range []string{"json", "csv"} {
		config := cliConfigForTest(t)
		config.format = format
		config.output = filepath.Join(t.TempDir(), format+".out")
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatalf("%s benchmark = %v", format, err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("%s dependency logs leaked to stderr: %q", format, stderr.String())
		}
	}
}

func TestOutputWriterErrorPaths(t *testing.T) {
	oldStat := statOutputPath
	oldCreate := createTempOutputFile
	oldRemove := removeOutputFile
	oldRename := renameOutputFile
	t.Cleanup(func() {
		statOutputPath = oldStat
		createTempOutputFile = oldCreate
		removeOutputFile = oldRemove
		renameOutputFile = oldRename
	})

	statOutputPath = func(string) (os.FileInfo, error) { return nil, errors.New("stat failed") }
	if _, _, err := outputWriter("stat-target"); err == nil || !strings.Contains(err.Error(), "stat failed") {
		t.Fatalf("stat output error = %v", err)
	}
	statOutputPath = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return nil, errors.New("create failed") }
	if _, _, err := outputWriter("create-target"); err == nil || !strings.Contains(err.Error(), "create failed") {
		t.Fatalf("create output error = %v", err)
	}

	newFile := func() *fakeOutputFile { return &fakeOutputFile{name: "temporary"} }
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return newFile(), nil }
	removeOutputFile = func(string) error { return nil }
	renameOutputFile = func(string, string) error { return nil }
	file := &fakeOutputFile{name: "discard-close", closeErr: errors.New("close failed")}
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return file, nil }
	writer, finalize, err := outputWriter("discard-close-target")
	if err != nil || writer != file {
		t.Fatalf("discard-close writer = %#v/%v", writer, err)
	}
	if err := finalize(false); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("discard close error = %v", err)
	}

	file = &fakeOutputFile{name: "discard-remove"}
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return file, nil }
	removeOutputFile = func(string) error { return errors.New("remove failed") }
	_, finalize, err = outputWriter("discard-remove-target")
	if err != nil {
		t.Fatal(err)
	}
	if err := finalize(false); err == nil || !strings.Contains(err.Error(), "remove failed") {
		t.Fatalf("discard remove error = %v", err)
	}

	removeOutputFile = func(string) error { return nil }
	file = &fakeOutputFile{name: "sync-fail", syncErr: errors.New("sync failed")}
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return file, nil }
	_, finalize, err = outputWriter("sync-target")
	if err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err == nil || !strings.Contains(err.Error(), "sync failed") {
		t.Fatalf("sync error = %v", err)
	}

	file = &fakeOutputFile{name: "close-fail", closeErr: errors.New("close failed")}
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return file, nil }
	_, finalize, err = outputWriter("close-target")
	if err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("commit close error = %v", err)
	}

	file = &fakeOutputFile{name: "rename-fail"}
	createTempOutputFile = func(string, string) (outputFileHandle, error) { return file, nil }
	renameOutputFile = func(string, string) error { return errors.New("rename failed") }
	_, finalize, err = outputWriter("rename-target")
	if err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err == nil || !strings.Contains(err.Error(), "rename failed") {
		t.Fatalf("rename error = %v", err)
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
			Warnings: []benchmark.Warning{benchmark.TargetWarning(
				catalog.Target{Resolver: catalog.ResolverProfile{ID: "dead", Name: "Dead", Owner: "Test owner", Policy: "unfiltered"}, Protocol: catalog.UDP, Address: "192.0.2.1", Spec: catalog.TransportSpec{Port: 53}},
				"could not open a session: connection refused",
			)},
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

func TestRunBenchmarkEmitsReportBeforeAssertionFailure(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}
	config := cliConfigForTest(t)
	config.assertions = []string{"p95<0.5ms"}
	config.output = filepath.Join(t.TempDir(), "assertion-failure.json")
	err := runBenchmark(context.Background(), config)
	if !errors.Is(err, ErrAssertionsFailed) || !strings.Contains(err.Error(), "p95<0.5ms") {
		t.Fatalf("assertion error = %v", err)
	}
	content, readErr := os.ReadFile(config.output)
	if readErr != nil || len(content) == 0 || !strings.Contains(string(content), "\"results\"") {
		t.Fatalf("report was not emitted before assertion failure: %q/%v", content, readErr)
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
	root := newRootCommand()
	root.SetOut(cliErrorWriter{})
	root.SetErr(cliErrorWriter{})
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("root command must ignore output write errors: %v", err)
	}
}

func TestOutputWriterWritesNonRegularDestinationsInPlace(t *testing.T) {
	writer, finalize, err := outputWriter(os.DevNull)
	if err != nil {
		t.Fatalf("device writer = %v", err)
	}
	if _, err := io.WriteString(writer, "discarded report"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("device finalize = %v", err)
	}
	info, err := os.Stat(os.DevNull)
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		t.Fatalf("%s was replaced: %v/%v", os.DevNull, info, err)
	}

	// Discarding a non-regular destination cannot restore it, but it must
	// still close the destination without reporting an error.
	writer, finalize, err = outputWriter(os.DevNull)
	if err != nil {
		t.Fatalf("device discard writer = %v", err)
	}
	if _, err := io.WriteString(writer, "partial"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(false); err != nil {
		t.Fatalf("device discard finalize = %v", err)
	}
}

func TestOutputWriterFallsBackWhenTemporaryFilesAreRejected(t *testing.T) {
	oldCreate := createTempOutputFile
	oldOpen := openOutputFile
	t.Cleanup(func() {
		createTempOutputFile = oldCreate
		openOutputFile = oldOpen
	})
	createTempOutputFile = func(string, string) (outputFileHandle, error) {
		return nil, fmt.Errorf("open .report.speedns-1: %w", os.ErrPermission)
	}

	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatalf("fallback writer = %v", err)
	}
	if _, err := io.WriteString(writer, "fresh"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("fallback finalize = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "fresh" {
		t.Fatalf("fallback output = %q/%v", content, err)
	}

	openOutputFile = func(string) (outputFileHandle, error) { return nil, errors.New("open failed") }
	if _, _, err := outputWriter(path); err == nil || !strings.Contains(err.Error(), "open failed") {
		t.Fatalf("direct open error = %v", err)
	}

	file := &fakeOutputFile{name: "direct-sync", syncErr: errors.New("sync failed")}
	openOutputFile = func(string) (outputFileHandle, error) { return file, nil }
	if _, finalize, err = outputWriter(path); err != nil {
		t.Fatal(err)
	} else if err := finalize(true); err == nil || !strings.Contains(err.Error(), "sync failed") {
		t.Fatalf("direct sync error = %v", err)
	}

	file = &fakeOutputFile{name: "direct-close", closeErr: errors.New("close failed")}
	openOutputFile = func(string) (outputFileHandle, error) { return file, nil }
	if _, finalize, err = outputWriter(path); err != nil {
		t.Fatal(err)
	} else if err := finalize(true); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("direct commit close error = %v", err)
	}

	if _, finalize, err = outputWriter(path); err != nil {
		t.Fatal(err)
	} else if err := finalize(false); err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("direct discard close error = %v", err)
	}

	// A directory destination keeps its dedicated error instead of being
	// written in place.
	if _, _, err := outputWriter(t.TempDir()); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory destination error = %v", err)
	}
}

func TestRunBenchmarkWarnsWhenSampleTruncatesCacheMissCorpus(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldNonce := newCacheMissNonceFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		newCacheMissNonceFunc = oldNonce
	})
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		measured := options.Sample
		if measured > len(options.Domains) {
			measured = len(options.Domains)
		}
		report := fakeCLIReport()
		report.SampleSize = measured
		report.Queries = measured * len(options.QueryTypes)
		return report, nil
	}
	newCacheMissNonceFunc = func() (string, error) { return "0123456789abcdef", nil }
	config := &cliConfig{
		protocols: "udp", resolverFlags: []string{"lab=udp://127.0.0.1:53"}, noDefaults: true,
		cacheMiss: true, cacheMissSample: 20, sample: 5, seed: 7, queryTypes: "A", timeout: time.Second,
		concurrency: 1, format: "json", family: "4", output: filepath.Join(t.TempDir(), "cache.json"),
	}
	if err := runBenchmark(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(config.output)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"effective sample of 5 truncated the generated cache-miss corpus of 20 names",
		"\"sample_size\": 5",
		"\"corpus_entries\": 20",
	} {
		if !strings.Contains(string(content), expected) {
			t.Fatalf("cache-miss truncation report missing %q: %s", expected, content)
		}
	}

	config.sample = 20
	config.output = filepath.Join(t.TempDir(), "full.json")
	if err := runBenchmark(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(config.output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "truncated the generated cache-miss corpus") {
		t.Fatalf("unexpected truncation warning: %s", content)
	}
}

func TestParseQueryTypesRejectsZoneTransferAndPseudoTypes(t *testing.T) {
	rejected := []struct {
		name     string
		input    string
		wantKind string
	}{
		{name: "axfr", input: "AXFR", wantKind: "unsafe"},
		{name: "axfr numeric", input: "252", wantKind: "unsafe"},
		{name: "ixfr", input: "IXFR", wantKind: "unsafe"},
		{name: "ixfr numeric", input: "251", wantKind: "unsafe"},
		{name: "any", input: "ANY", wantKind: "unsafe"},
		{name: "any numeric", input: "255", wantKind: "unsafe"},
		{name: "maila", input: "MAILA", wantKind: "unsafe"},
		{name: "mailb", input: "MAILB", wantKind: "unsafe"},
		{name: "opt", input: "OPT", wantKind: "invalid"},
		{name: "opt numeric", input: "41", wantKind: "invalid"},
		{name: "tsig", input: "TSIG", wantKind: "invalid"},
		{name: "tkey", input: "TKEY", wantKind: "invalid"},
		{name: "lowercase", input: "axfr", wantKind: "unsafe"},
		{name: "trailing member of a list", input: "A,AAAA,AXFR", wantKind: "unsafe"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			types, err := parseQueryTypes(tc.input)
			if err == nil {
				t.Fatalf("parseQueryTypes(%q) = %#v, want error", tc.input, types)
			}
			if !strings.HasPrefix(err.Error(), tc.wantKind+" DNS query type ") {
				t.Fatalf("parseQueryTypes(%q) error = %q, want %s classification", tc.input, err, tc.wantKind)
			}
		})
	}

	if _, err := parseQueryTypes("nonsense"); err == nil || !strings.HasPrefix(err.Error(), "unknown DNS query type ") {
		t.Fatalf("unknown type error = %v, want unknown classification", err)
	}

	accepted := []struct {
		name  string
		input string
		want  uint16
	}{
		{name: "a", input: "A", want: dns.TypeA},
		{name: "aaaa", input: "aaaa", want: dns.TypeAAAA},
		{name: "mx", input: "MX", want: dns.TypeMX},
		{name: "txt", input: "TXT", want: dns.TypeTXT},
		{name: "srv", input: "SRV", want: dns.TypeSRV},
		{name: "ns", input: "NS", want: dns.TypeNS},
		{name: "soa", input: "SOA", want: dns.TypeSOA},
		{name: "ptr", input: "PTR", want: dns.TypePTR},
		{name: "caa", input: "CAA", want: dns.TypeCAA},
		{name: "tlsa", input: "TLSA", want: dns.TypeTLSA},
		{name: "https", input: "HTTPS", want: dns.TypeHTTPS},
		{name: "svcb", input: "SVCB", want: dns.TypeSVCB},
		{name: "unusual numeric", input: "65000", want: 65000},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			types, err := parseQueryTypes(tc.input)
			if err != nil {
				t.Fatalf("parseQueryTypes(%q) = %v, want success", tc.input, err)
			}
			if len(types) != 1 || types[0] != tc.want {
				t.Fatalf("parseQueryTypes(%q) = %#v, want [%d]", tc.input, types, tc.want)
			}
		})
	}
}

// TestCacheMissWarnsWhenMoreThanOneProtocolIsMeasured pins the disclosure that
// only the first measured protocol group observes a genuine cache miss: every
// group replays the same generated names against the same resolver cache.
func TestCacheMissWarnsWhenMoreThanOneProtocolIsMeasured(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldNonce := newCacheMissNonceFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		newCacheMissNonceFunc = oldNonce
	})
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}
	newCacheMissNonceFunc = func() (string, error) { return "0123456789abcdef", nil }
	const warning = "only the first measured protocol (udp) observes a true cache miss"

	multi := &cliConfig{
		protocols: "udp,tcp", resolverFlags: []string{"lab=udp://127.0.0.1:53", "labtcp=tcp://127.0.0.1:53"},
		noDefaults: true, cacheMiss: true, cacheMissSample: 2, sample: 100, seed: 7, queryTypes: "A",
		timeout: time.Second, concurrency: 1, format: "json", family: "4",
		output: filepath.Join(t.TempDir(), "multi.json"),
	}
	if err := runBenchmark(context.Background(), multi); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(multi.output)
	if err != nil || !strings.Contains(string(content), warning) || !strings.Contains(string(content), "later protocols (tcp) run against an already warm resolver cache") {
		t.Fatalf("multi-protocol cache-miss report = %q/%v", content, err)
	}

	single := *multi
	single.protocols = "udp"
	single.resolverFlags = []string{"lab=udp://127.0.0.1:53"}
	single.output = filepath.Join(t.TempDir(), "single.json")
	if err := runBenchmark(context.Background(), &single); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(single.output)
	if err != nil || strings.Contains(string(content), "observes a true cache miss") {
		t.Fatalf("single-protocol cache-miss report = %q/%v", content, err)
	}

	warm := *multi
	warm.cacheMiss = false
	warm.domainFile = cliDomainFile(t)
	warm.output = filepath.Join(t.TempDir(), "warm.json")
	if err := runBenchmark(context.Background(), &warm); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(warm.output)
	if err != nil || strings.Contains(string(content), "observes a true cache miss") {
		t.Fatalf("warm-cache report = %q/%v", content, err)
	}
}

// TestValidateNormalizationReachesSelectedProfiles guards the split introduced
// for --family auto. catalog.Validate normalizes profiles in place, so the
// bundled and explicit views must share one backing array; handing Validate a
// copy silently dropped the scalar trims while map and slice writes still
// propagated, which made the loss easy to miss.
func TestValidateNormalizationReachesSelectedProfiles(t *testing.T) {
	selection := profileSelection{
		profiles: []catalog.ResolverProfile{{
			ID: "  spaced-id  ", Name: "  Spaced Name  ", Owner: "  Owner  ",
			Policy: "  unfiltered  ", Scope: "  scope  ", Interface: "  eth0  ",
			Addresses:  []string{"192.0.2.1"},
			Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {}},
		}},
		explicitFrom: 0,
	}
	if err := catalog.Validate(selection.all()); err != nil {
		t.Fatal(err)
	}
	got := selection.explicit()[0]
	if got.ID != "spaced-id" || got.Name != "Spaced Name" || got.Owner != "Owner" ||
		got.Policy != "unfiltered" || got.Scope != "scope" || got.Interface != "eth0" {
		t.Fatalf("normalization did not reach the selected profile: %#v", got)
	}
	if got.Transports[catalog.UDP].Port != 53 {
		t.Fatalf("default port did not reach the selected profile: %d", got.Transports[catalog.UDP].Port)
	}
}

// TestDuplicateProfileIDsAcrossGroupsAreRejected pins that validation still
// sees bundled and explicit profiles as one set, so a custom resolver cannot
// silently shadow a bundled identifier.
func TestDuplicateProfileIDsAcrossGroupsAreRejected(t *testing.T) {
	profile := func(id string) catalog.ResolverProfile {
		return catalog.ResolverProfile{
			ID: id, Name: id, Addresses: []string{"192.0.2.1"},
			Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}},
		}
	}
	selection := profileSelection{
		profiles:     []catalog.ResolverProfile{profile("shared"), profile("shared")},
		explicitFrom: 1,
	}
	if err := catalog.Validate(selection.all()); err == nil {
		t.Fatal("expected a duplicate resolver id across bundled and explicit profiles to be rejected")
	}
}

type failingCloser struct{}

func (failingCloser) Close() error { return errors.New("probe close failed") }

func TestOutputWriterMatchesOrdinaryFileMode(t *testing.T) {
	directory := t.TempDir()
	reference := filepath.Join(directory, "reference")
	referenceFile, err := os.OpenFile(reference, os.O_WRONLY|os.O_CREATE|os.O_EXCL, ordinaryFileMode)
	if err != nil {
		t.Fatal(err)
	}
	if err := referenceFile.Close(); err != nil {
		t.Fatal(err)
	}
	referenceInfo, err := os.Stat(reference)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(directory, "report.json")
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != referenceInfo.Mode().Perm() {
		t.Fatalf("--output mode = %v, want the ordinary creation mode %v", info.Mode().Perm(), referenceInfo.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "{}\n" {
		t.Fatalf("output contents = %q/%v", string(contents), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("output directory holds %d entries, want the report and the reference only", len(entries))
	}
}

func TestOutputWriterKeepsReportWhenPermissionsCannotBeSet(t *testing.T) {
	oldProbe := createOutputProbeFile
	oldChmod := chmodOutputFile
	t.Cleanup(func() {
		createOutputProbeFile = oldProbe
		chmodOutputFile = oldChmod
	})

	directory := t.TempDir()
	createOutputProbeFile = func(string) (io.Closer, error) { return nil, errors.New("probe failed") }
	unprobed := filepath.Join(directory, "unprobed.json")
	writer, finalize, err := outputWriter(unprobed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("failed probe blocked the report: %v", err)
	}
	if _, err := os.Stat(unprobed); err != nil {
		t.Fatal(err)
	}

	createOutputProbeFile = func(string) (io.Closer, error) { return failingCloser{}, nil }
	if mode, ok := probeOrdinaryFileMode(filepath.Join(directory, "absent")); ok {
		t.Fatalf("unusable probe reported mode %v", mode)
	}

	createOutputProbeFile = oldProbe
	chmodOutputFile = func(string, fs.FileMode) error { return errors.New("chmod failed") }
	unchanged := filepath.Join(directory, "unchanged.json")
	writer, finalize, err = outputWriter(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("failed permission change blocked the report: %v", err)
	}
	contents, err := os.ReadFile(unchanged)
	if err != nil || string(contents) != "{}\n" {
		t.Fatalf("output contents = %q/%v", string(contents), err)
	}
}

func TestErrorMessageRendersInterruptionInPlainLanguage(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "canceled", err: context.Canceled, want: "interrupted"},
		{name: "wrapped cancel", err: fmt.Errorf("run benchmark: %w", context.Canceled), want: "interrupted"},
		{name: "deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded.Error()},
		{name: "configuration", err: errors.New("unsupported output format"), want: "unsupported output format"},
		{name: "assertions", err: ErrAssertionsFailed, want: ErrAssertionsFailed.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorMessage(tc.err); got != tc.want {
				t.Fatalf("errorMessage = %q, want %q", got, tc.want)
			}
			if strings.Contains(errorMessage(tc.err), "context canceled") {
				t.Fatalf("errorMessage leaked context plumbing: %q", errorMessage(tc.err))
			}
		})
	}
	if code := exitCodeForError(context.Canceled); code != 130 {
		t.Fatalf("interruption exit code = %d, want 130", code)
	}
}

func TestInterruptContextReleasesSignalsAfterTheFirst(t *testing.T) {
	oldNotify, oldStop := notifySignals, stopSignals
	t.Cleanup(func() { notifySignals = oldNotify; stopSignals = oldStop })
	channels := make(chan chan<- os.Signal, 2)
	var registered []os.Signal
	var released atomic.Int64
	notifySignals = func(channel chan<- os.Signal, signals ...os.Signal) {
		registered = append([]os.Signal(nil), signals...)
		channels <- channel
	}
	stopSignals = func(chan<- os.Signal) { released.Add(1) }

	runContext, stop := interruptContext(context.Background())
	defer stop()
	channel := <-channels
	if len(registered) != 2 || registered[0] != os.Interrupt || registered[1] != syscall.SIGTERM {
		t.Fatalf("registered signals = %#v", registered)
	}
	channel <- os.Interrupt
	<-runContext.Done()
	if !errors.Is(runContext.Err(), context.Canceled) {
		t.Fatalf("interrupted run error = %v", runContext.Err())
	}
	if released.Load() != 1 {
		t.Fatalf("signal registration released %d times, want the default restored once", released.Load())
	}
	if code := exitCodeForError(runContext.Err()); code != 130 {
		t.Fatalf("interrupted exit code = %d, want 130", code)
	}

	quiet, quietStop := interruptContext(context.Background())
	<-channels
	quietStop()
	<-quiet.Done()
	if !errors.Is(quiet.Err(), context.Canceled) {
		t.Fatalf("clean shutdown error = %v", quiet.Err())
	}
}

func TestDNSSECFlagIsOptInAndReachesTheBenchmark(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	var requested []bool
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		requested = append(requested, options.DNSSEC)
		return fakeCLIReport(), nil
	}
	config := cliConfigForTest(t)
	config.output = filepath.Join(t.TempDir(), "default.json")
	if err := runBenchmark(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	config = cliConfigForTest(t)
	config.dnssec = true
	config.output = filepath.Join(t.TempDir(), "dnssec.json")
	if err := runBenchmark(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(requested) != 2 || requested[0] || !requested[1] {
		t.Fatalf("DNSSEC option per run = %v, want [false true]", requested)
	}
	if got := newRootCommand().Flags().Lookup("dnssec").DefValue; got != "false" {
		t.Fatalf("--dnssec default = %q, want \"false\"", got)
	}
}

// TestSkipInvalidDomainsDisclosesWhatItDropped covers the opt-in path end to
// end: the run succeeds on a partly invalid list, the report says how many
// entries were dropped and why, and the recorded corpus describes the names
// that were measured rather than the file as written.
func TestSkipInvalidDomainsDisclosesWhatItDropped(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}
	path := filepath.Join(t.TempDir(), "mixed.txt")
	if err := os.WriteFile(path, []byte("example.com\nexa mple.com\n*.bad\nexample.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := &cliConfig{
		protocols: "udp", resolverFlags: []string{"lab=udp://127.0.0.1:53"}, noDefaults: true,
		domainFile: path, skipInvalid: true, sample: 10, seed: 1, queryTypes: "A",
		timeout: time.Second, concurrency: 1, format: "json", family: "4",
		output: filepath.Join(t.TempDir(), "skip.json"),
	}
	if err := runBenchmark(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(config.output)
	if err != nil {
		t.Fatal(err)
	}
	report := string(content)
	if !strings.Contains(report, "dropped 2 unusable entries") {
		t.Fatalf("report does not disclose the skipped entries: %s", report)
	}
	if !strings.Contains(report, "whitespace is not allowed") || !strings.Contains(report, "wildcards are not allowed") {
		t.Fatalf("report does not say why entries were skipped: %s", report)
	}
	if !strings.Contains(report, `"corpus_entries": 2`) {
		t.Fatalf("provenance does not describe the measured corpus: %s", report)
	}

	// The same list without the opt-in must still fail.
	strict := *config
	strict.skipInvalid = false
	strict.output = filepath.Join(t.TempDir(), "strict.json")
	if err := runBenchmark(context.Background(), &strict); err == nil ||
		!strings.Contains(err.Error(), "invalid domain names") {
		t.Fatalf("strict load error = %v", err)
	}

	// Generated cache-miss names are always valid, so the combination is a
	// configuration mistake rather than a no-op.
	cacheMiss := *config
	cacheMiss.domainFile = ""
	cacheMiss.cacheMiss = true
	cacheMiss.cacheMissSample = 2
	if err := runBenchmark(context.Background(), &cacheMiss); err == nil ||
		!strings.Contains(err.Error(), "cannot be combined with --cache-miss") {
		t.Fatalf("cache-miss combination error = %v", err)
	}
}
