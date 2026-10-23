package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	"github.com/crypt0rr/SpeeDNS/internal/compare"
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

type fakeOutputPathInfo struct {
	mode  fs.FileMode
	isDir bool
}

func (fakeOutputPathInfo) Name() string        { return "output" }
func (fakeOutputPathInfo) Size() int64         { return 0 }
func (f fakeOutputPathInfo) Mode() fs.FileMode { return f.mode }
func (fakeOutputPathInfo) ModTime() time.Time  { return time.Time{} }
func (f fakeOutputPathInfo) IsDir() bool       { return f.isDir }
func (fakeOutputPathInfo) Sys() any            { return nil }

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
	// UsableResponses is set because the engine only scores a sample it also
	// counted as usable (internal/benchmark/benchmark.go:978,991); a fixture
	// with Scored > 0 and UsableResponses == 0 describes a state Run cannot
	// produce, and reads as a dead transport to anything checking reachability.
	result := benchmark.TargetResult{Target: target, Stats: benchmark.Statistics{Total: 1, Successes: 1, UsableResponses: 1, Scored: 1, SuccessRate: 1, UsableRate: 1, MedianMS: 1, P95MS: 1, ScoreMS: 1}}
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
	if got, want := strings.Join(names, ","), "completion,corpus,diff,resolvers,run,version"; got != want {
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
		{name: "runs not comparable", err: compare.ErrRunsNotComparable, want: 3},
		// A gate that compared nothing could not evaluate, so it shares the
		// refusal's status rather than passing or claiming a failure.
		{name: "nothing compared", err: fmt.Errorf("%w: 0 endpoint(s) compared", compare.ErrNothingCompared), want: 3},
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

func TestOutputWriterRejectsSymlinkDestinations(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hasReferent bool
		isDirectory bool
	}{
		{name: "to existing file", hasReferent: true},
		{name: "to directory", isDirectory: true},
		{name: "dangling"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			link := filepath.Join(directory, "report.json")
			referent := filepath.Join(directory, "referent.json")
			const original = "keep this referent"
			if tc.hasReferent {
				if err := os.WriteFile(referent, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.isDirectory {
				if err := os.Mkdir(referent, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(filepath.Base(referent), link); err != nil {
				if errors.Is(err, os.ErrPermission) {
					t.Skipf("creating symlinks is unavailable: %v", err)
				}
				t.Fatalf("create output symlink: %v", err)
			}

			if _, _, err := outputWriter(link); err == nil || !strings.Contains(err.Error(), "output path is a symlink") {
				t.Fatalf("symlink destination error = %v", err)
			}
			linkInfo, err := os.Lstat(link)
			if err != nil || linkInfo.Mode()&fs.ModeSymlink == 0 {
				t.Fatalf("output symlink was changed: %v/%v", linkInfo, err)
			}
			if target, err := os.Readlink(link); err != nil || target != filepath.Base(referent) {
				t.Fatalf("output symlink target = %q/%v", target, err)
			}
			switch {
			case tc.hasReferent:
				content, err := os.ReadFile(referent)
				if err != nil || string(content) != original {
					t.Fatalf("symlink referent = %q/%v", content, err)
				}
			case tc.isDirectory:
				if entries, err := os.ReadDir(referent); err != nil || len(entries) != 0 {
					t.Fatalf("symlinked directory gained entries: %v/%v", entries, err)
				}
			default:
				if _, err := os.Stat(referent); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dangling symlink referent unexpectedly exists: %v", err)
				}
			}
			// The preflight applies the same rule before a run starts.
			if err := preflightOutput(link); err == nil || !strings.Contains(err.Error(), "output path is a symlink") {
				t.Fatalf("symlink destination preflight error = %v", err)
			}
		})
	}
}

// TestDescriptorForOutputPathMapsOnlyCanonicalAliases pins the spellings that
// are written to an open descriptor instead of being opened, and the
// descriptor each one names: /dev/stdout is 1 and /dev/stderr is 2, exactly as
// a report on standard output or standard error would be written, and the
// numbered forms name their number. Anything else that happens to be a
// symlink stays rejected, so the matcher must not accept near misses such as
// relative, unclean or padded forms, or a number no descriptor can have.
func TestDescriptorForOutputPathMapsOnlyCanonicalAliases(t *testing.T) {
	for _, tc := range []struct {
		path       string
		descriptor int
		want       bool
	}{
		{path: "/dev/stdout", descriptor: 1, want: true},
		{path: "/dev/stderr", descriptor: 2, want: true},
		{path: "/dev/fd/0", descriptor: 0, want: true},
		{path: "/dev/fd/1", descriptor: 1, want: true},
		{path: "/dev/fd/63", descriptor: 63, want: true},
		{path: "/dev/fd/2147483647", descriptor: 2147483647, want: true},
		{path: "/proc/self/fd/1", descriptor: 1, want: true},
		{path: "/proc/self/fd/12", descriptor: 12, want: true},
		{path: "/proc/thread-self/fd/2", descriptor: 2, want: true},
		{path: "/dev/stdin"},
		{path: "/dev/stdout/"},
		{path: "/dev/./stdout"},
		{path: "dev/stdout"},
		{path: "/dev/fd"},
		{path: "/dev/fd/"},
		{path: "/dev/fd/-1"},
		{path: "/dev/fd/1x"},
		{path: "/dev/fd/2147483648"},
		{path: "/dev/fd/4294967297"},
		{path: "/dev/fd/99999999999999999999"},
		{path: "/proc/1/fd/1"},
		{path: "/proc/thread-self/fd/01"},
		{path: "proc/self/fd/1"},
		{path: "/tmp/output.json"},
		{path: "/proc/self/fd/./1"},
		{path: "/proc/self/fd/1/2"},
		{path: "/proc/self/fd/+1"},
		{path: "/proc/self/fd/01"},
		{path: "/proc/self/fd/not-a-number"},
	} {
		// The aliases are POSIX paths, so on a platform with another
		// separator nothing may match, including the canonical spellings.
		want := tc.want && filepath.Separator == '/'
		descriptor, got := descriptorForOutputPath(filepath.FromSlash(tc.path))
		if got != want || (want && descriptor != tc.descriptor) {
			t.Errorf("descriptorForOutputPath(%q) = %d, %v, want %d, %v", tc.path, descriptor, got, tc.descriptor, want)
		}
	}
}

func TestRunBenchmarkRejectsSymlinkOutput(t *testing.T) {
	engineCalls := countEngineCalls(t)

	directory := t.TempDir()
	referent := filepath.Join(directory, "referent.json")
	const original = "keep this report"
	if err := os.WriteFile(referent, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "report.json")
	if err := os.Symlink(filepath.Base(referent), link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("creating symlinks is unavailable: %v", err)
		}
		t.Fatalf("create output symlink: %v", err)
	}

	config := cliConfigForTest(t)
	config.output = link
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "output path is a symlink") {
		t.Fatalf("run output symlink error = %v", err)
	}
	if *engineCalls != 0 {
		t.Fatalf("a refused symlink destination still ran the benchmark %d time(s)", *engineCalls)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil || linkInfo.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("run changed output symlink: %v/%v", linkInfo, err)
	}
	if target, err := os.Readlink(link); err != nil || target != filepath.Base(referent) {
		t.Fatalf("run output symlink target = %q/%v", target, err)
	}
	content, err := os.ReadFile(referent)
	if err != nil || string(content) != original {
		t.Fatalf("run symlink referent = %q/%v", content, err)
	}
}

// TestOutputRefusesSocketsBeforeTheRun pins that a socket is never accepted
// as a destination. Opening one by name fails on every supported system
// (ENXIO on Linux, EOPNOTSUPP on macOS and the BSDs), so accepting it, through
// a symlink or directly, would let the whole benchmark run and then replace
// its exit status with 2 when the report could not be opened. Synthetic stat
// results cover both spellings on every platform.
func TestOutputRefusesSocketsBeforeTheRun(t *testing.T) {
	oldStat, oldLstat := statOutputPath, lstatOutputPath
	t.Cleanup(func() { statOutputPath, lstatOutputPath = oldStat, oldLstat })
	socket := fakeOutputPathInfo{mode: fs.ModeSocket | 0o755}
	for _, tc := range []struct {
		name  string
		lstat fakeOutputPathInfo
		wants string
	}{
		{name: "symlink to a socket", lstat: fakeOutputPathInfo{mode: fs.ModeSymlink | 0o777}, wants: "output path is a symlink"},
		{name: "socket", lstat: socket, wants: "output path is a socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engineCalls := countEngineCalls(t)
			lstatOutputPath = func(string) (os.FileInfo, error) { return tc.lstat, nil }
			statOutputPath = func(string) (os.FileInfo, error) { return socket, nil }
			path := filepath.Join(t.TempDir(), "report.json")
			if _, _, err := outputWriter(path); err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("writer error = %v, want %q", err, tc.wants)
			}
			if err := preflightOutput(path); err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("preflight error = %v, want %q", err, tc.wants)
			}
			config := cliConfigForTest(t)
			config.output = path
			err := runBenchmark(context.Background(), config)
			if err == nil || !strings.Contains(err.Error(), tc.wants) || exitCodeForError(err) != 2 {
				t.Fatalf("run error = %v (exit %d), want %q with status 2", err, exitCodeForError(err), tc.wants)
			}
			if *engineCalls != 0 {
				t.Fatalf("the benchmark ran %d time(s) for a socket destination", *engineCalls)
			}
		})
	}
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

// TestProgressShowsTheColdBarrierAndTheDNSSECPhase covers the two stretches
// that used to look stuck: the cold-probe barrier, during which no target can
// finish preparing, and the opt-in DNSSEC probes after measurement. Cold
// progress folds into the preparation milestones, so a redirected log still
// prints at most five preparing lines, and the prepared count keeps its
// meaning once warm sessions open.
func TestProgressShowsTheColdBarrierAndTheDNSSECPhase(t *testing.T) {
	targets := []catalog.Target{{Protocol: catalog.UDP, Address: "192.0.2.1"}, {Protocol: catalog.UDP, Address: "192.0.2.2"}}
	events := []benchmark.Progress{
		{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 2, ColdCompleted: 1},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsTotal: 2, ColdCompleted: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsCompleted: 1, TargetsTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressPreparing, TargetsCompleted: 2, TargetsTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 2, TargetsTotal: 2, ExchangesTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressMeasuring, TargetsCompleted: 2, TargetsTotal: 2, ExchangesCompleted: 2, ExchangesTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressDNSSEC, TargetsCompleted: 2, TargetsTotal: 2, ExchangesCompleted: 2, ExchangesTotal: 2, DNSSECTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressDNSSEC, TargetsCompleted: 2, TargetsTotal: 2, ExchangesCompleted: 2, ExchangesTotal: 2, DNSSECCompleted: 1, DNSSECTotal: 2},
		{Protocol: catalog.UDP, Phase: benchmark.ProgressComplete, TargetsCompleted: 2, TargetsTotal: 2, ExchangesCompleted: 2, ExchangesTotal: 2},
	}

	var logOutput bytes.Buffer
	logProgress := newProgressRenderer(&logOutput, false, []catalog.Protocol{catalog.UDP}, targets)
	for _, event := range events {
		logProgress.Update(event)
	}
	want := "progress udp: preparing 0/2 targets\n" +
		"progress udp: preparing 0/2 targets (cold probes 1/2)\n" +
		"progress udp: preparing 0/2 targets (cold probes 2/2)\n" +
		"progress udp: preparing 1/2 targets\n" +
		"progress udp: preparing 2/2 targets\n" +
		"progress udp: measuring 0/2 exchanges\n" +
		"progress udp: measuring 2/2 exchanges\n" +
		"progress udp: dnssec probes 0/2 targets\n" +
		"progress udp: dnssec probes 1/2 targets\n" +
		"tested udp 2/2 targets\n"
	if got := logOutput.String(); got != want {
		t.Fatalf("non-TTY progress = %q, want %q", got, want)
	}

	var tty bytes.Buffer
	ttyProgress := newProgressRenderer(&tty, true, []catalog.Protocol{catalog.UDP}, targets)
	ttyProgress.refreshInterval = time.Hour
	ttyProgress.Start()
	lines := make([]string, 0, len(events))
	for _, event := range events {
		ttyProgress.Update(event)
		lines = append(lines, tty.String())
		tty.Reset()
	}
	ttyProgress.Finish()
	for index, want := range map[int]string{
		1: "udp preparing 0/2 (cold probes 1/2)",
		3: "udp preparing 1/2 |",
		8: "udp dnssec probes 1/2",
	} {
		if !strings.Contains(lines[index], want) {
			t.Fatalf("TTY line after event %d = %q, want %q", index, lines[index], want)
		}
	}
	if strings.Contains(lines[3], "cold") {
		t.Fatalf("cold progress outlived the cold barrier: %q", lines[3])
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
		result := benchmark.TargetResult{Target: targets[0], Stats: benchmark.Statistics{Total: 1, Successes: 1, UsableResponses: 1, Scored: 1, SuccessRate: 1, UsableRate: 1, MedianMS: 1, P95MS: 1, ScoreMS: 1}}
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
	// The preflight refuses this before the run; the post-run refusal is
	// pinned by TestRunBenchmarkReportsADestinationThatBreaksDuringTheRun.
	config := cliConfigForTest(t)
	config.output = t.TempDir()
	if err := runBenchmark(context.Background(), config); err == nil || !strings.Contains(err.Error(), "output path is a directory") {
		t.Fatalf("directory destination error = %v", err)
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
	oldLstat := lstatOutputPath
	oldOpen := openOutputFile
	oldCreate := createTempOutputFile
	oldRemove := removeOutputFile
	oldRename := renameOutputFile
	t.Cleanup(func() {
		statOutputPath = oldStat
		lstatOutputPath = oldLstat
		openOutputFile = oldOpen
		createTempOutputFile = oldCreate
		removeOutputFile = oldRemove
		renameOutputFile = oldRename
	})

	lstatOutputPath = func(string) (os.FileInfo, error) { return nil, errors.New("lstat failed") }
	if _, _, err := outputWriter("stat-target"); err == nil || !strings.Contains(err.Error(), "lstat failed") {
		t.Fatalf("inspect output error = %v", err)
	}
	lstatOutputPath = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
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

// fakeOutputDescriptor is an open descriptor as openOutputDescriptor returns
// one, with a scripted fstat result and access mode. It counts how often it is
// closed, which for a real handle closes only the duplicate of the descriptor.
type fakeOutputDescriptor struct {
	fakeOutputFile
	info     fs.FileInfo
	statErr  error
	readOnly bool
	closes   int
}

func (f *fakeOutputDescriptor) Stat() (fs.FileInfo, error) { return f.info, f.statErr }

func (f *fakeOutputDescriptor) Close() error {
	f.closes++
	return f.fakeOutputFile.Close()
}

// scriptOutputDescriptors makes openOutputDescriptor record the descriptor it
// is asked for and hand out what open returns, so no test writes to its own
// standard output or standard error. An alias must never be inspected by path:
// on macOS /dev/fd/N is no link, a closed descriptor has no entry, and a socket
// cannot be opened by name. The path seams therefore fail the test if called.
func scriptOutputDescriptors(t *testing.T, open func() (*fakeOutputDescriptor, error)) *[]int {
	t.Helper()
	if filepath.Separator != '/' {
		t.Skip("descriptor aliases are POSIX paths, which never match here")
	}
	oldOpen, oldStat, oldLstat := openOutputDescriptor, statOutputPath, lstatOutputPath
	t.Cleanup(func() { openOutputDescriptor, statOutputPath, lstatOutputPath = oldOpen, oldStat, oldLstat })
	byPath := func(path string) (os.FileInfo, error) {
		t.Errorf("descriptor alias %s was inspected by path", path)
		return nil, errors.New("inspected by path")
	}
	statOutputPath, lstatOutputPath = byPath, byPath
	requested := new([]int)
	openOutputDescriptor = func(descriptor int, _ string) (outputDescriptorHandle, bool, error) {
		*requested = append(*requested, descriptor)
		handle, err := open()
		if err != nil {
			return nil, false, err
		}
		return handle, !handle.readOnly, nil
	}
	return requested
}

// TestOutputWriterWritesToTheDescriptorAnAliasNames pins how a descriptor
// alias is written since #228: to the descriptor it names, never by opening
// the path again. Reopening /dev/stdout truncated a log the shell had opened
// for appending, and a socket, which is standard output under systemd's
// StandardOutput=journal, cannot be opened by name at all. /dev/stdout and
// /dev/stderr name descriptors 1 and 2. Every open descriptor that is not a
// directory takes the report, and only a regular file is flushed. The handle
// is a duplicate, so the preflight and both finalizer outcomes close it.
func TestOutputWriterWritesToTheDescriptorAnAliasNames(t *testing.T) {
	for _, tc := range []struct {
		path       string
		descriptor int
		mode       fs.FileMode
		wantSync   bool
	}{
		{path: "/dev/stdout", descriptor: 1, mode: fs.ModeSocket | 0o777},
		{path: "/dev/stderr", descriptor: 2, mode: fs.ModeDevice | fs.ModeCharDevice | 0o620},
		{path: "/dev/fd/7", descriptor: 7, mode: fs.ModeNamedPipe | 0o600},
		{path: "/proc/self/fd/9", descriptor: 9, mode: 0o644, wantSync: true},
		{path: "/proc/thread-self/fd/3", descriptor: 3, mode: 0o600, wantSync: true},
	} {
		t.Run(tc.path, func(t *testing.T) {
			handle := &fakeOutputDescriptor{
				fakeOutputFile: fakeOutputFile{name: tc.path, syncErr: errors.New("sync called")},
				info:           fakeOutputPathInfo{mode: tc.mode},
			}
			requested := scriptOutputDescriptors(t, func() (*fakeOutputDescriptor, error) { return handle, nil })
			if err := preflightOutput(tc.path); err != nil {
				t.Fatalf("preflight = %v", err)
			}
			if handle.closes != 1 || handle.Len() != 0 {
				t.Fatalf("preflight closed its duplicate %d time(s) and wrote %q", handle.closes, handle.String())
			}
			writer, finalize, err := outputWriter(tc.path)
			if err != nil || writer != handle {
				t.Fatalf("writer = %#v/%v", writer, err)
			}
			if _, err := io.WriteString(writer, "report"); err != nil {
				t.Fatal(err)
			}
			if err := finalize(true); (err != nil) != tc.wantSync {
				t.Fatalf("commit = %v, want a sync %v", err, tc.wantSync)
			}
			if handle.closes != 2 || handle.String() != "report" {
				t.Fatalf("after commit: %d close(s), %q written", handle.closes, handle.String())
			}
			if _, finalize, err = outputWriter(tc.path); err != nil {
				t.Fatal(err)
			}
			if err := finalize(false); err != nil || handle.closes != 3 {
				t.Fatalf("discard = %v after %d close(s)", err, handle.closes)
			}
			if want := []int{tc.descriptor, tc.descriptor, tc.descriptor}; !slices.Equal(*requested, want) {
				t.Fatalf("descriptors requested = %v, want %v", *requested, want)
			}
		})
	}
}

// TestOutputRefusesAnUnusableDescriptorBeforeTheRun pins the descriptors an
// alias cannot be written to: a closed one, one that fstat cannot describe, a
// directory, and one open for reading only. Each must fail before the first
// query with status 2, and the writer must refuse it the same way if it
// changes during the run. A duplicate that was made is closed again.
func TestOutputRefusesAnUnusableDescriptorBeforeTheRun(t *testing.T) {
	const path = "/dev/fd/5"
	for _, tc := range []struct {
		name   string
		opened *fakeOutputDescriptor
		wants  string
	}{
		{name: "closed", wants: "inspect output path: dup /dev/fd/5: "},
		{
			name:   "fstat fails",
			opened: &fakeOutputDescriptor{statErr: &os.PathError{Op: "stat", Path: path, Err: syscall.EIO}},
			wants:  "inspect output path: stat /dev/fd/5: ",
		},
		{
			// A directory descriptor is always open for reading only, and is
			// still named as a directory.
			name:   "directory",
			opened: &fakeOutputDescriptor{info: fakeOutputPathInfo{mode: fs.ModeDir | 0o755, isDir: true}, readOnly: true},
			wants:  "output path is a directory: /dev/fd/5",
		},
		{
			name:   "open for reading only",
			opened: &fakeOutputDescriptor{info: fakeOutputPathInfo{mode: 0o644}, readOnly: true},
			wants:  "output path is a descriptor not open for writing: /dev/fd/5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scriptOutputDescriptors(t, func() (*fakeOutputDescriptor, error) {
				if tc.opened == nil {
					return nil, &os.PathError{Op: "dup", Path: path, Err: syscall.EBADF}
				}
				return tc.opened, nil
			})
			engineCalls := countEngineCalls(t)
			if err := preflightOutput(path); err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("preflight = %v, want %q", err, tc.wants)
			}
			if _, _, err := outputWriter(path); err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("writer = %v, want %q", err, tc.wants)
			}
			config := cliConfigForTest(t)
			config.output = path
			err := runBenchmark(context.Background(), config)
			if err == nil || !strings.Contains(err.Error(), tc.wants) || exitCodeForError(err) != 2 {
				t.Fatalf("run = %v (exit %d), want %q with status 2", err, exitCodeForError(err), tc.wants)
			}
			if *engineCalls != 0 {
				t.Fatalf("the benchmark ran %d time(s) for an unusable descriptor", *engineCalls)
			}
			if tc.opened != nil && tc.opened.closes != 3 {
				t.Fatalf("the duplicate was closed %d time(s), want 3", tc.opened.closes)
			}
		})
	}
}

// TestRunBenchmarkWritesToASocketOnStandardOutput is the systemd case behind
// #228. Under StandardOutput=journal standard output is a Unix socket, so the
// preflight accepted --output /dev/stdout and reopening it after the whole run
// failed with ENXIO. Written to descriptor 1 itself, the run exits 0 with its
// report on the socket.
func TestRunBenchmarkWritesToASocketOnStandardOutput(t *testing.T) {
	socket := &fakeOutputDescriptor{
		fakeOutputFile: fakeOutputFile{name: "/dev/stdout"},
		info:           fakeOutputPathInfo{mode: fs.ModeSocket | 0o777},
	}
	requested := scriptOutputDescriptors(t, func() (*fakeOutputDescriptor, error) { return socket, nil })
	engineCalls := countEngineCalls(t)
	config := cliConfigForTest(t)
	config.output = "/dev/stdout"
	if err := runBenchmark(context.Background(), config); err != nil || *engineCalls != 1 {
		t.Fatalf("run to a socket on standard output = %v after %d engine call(s)", err, *engineCalls)
	}
	if !strings.Contains(socket.String(), "\"results\"") {
		t.Fatalf("socket received %q", socket.String())
	}
	if !slices.Equal(*requested, []int{1, 1}) || socket.closes != 2 {
		t.Fatalf("descriptors requested = %v, closed %d time(s)", *requested, socket.closes)
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

// countEngineCalls replaces the benchmark engine with a stub that returns the
// fake report and counts how often the CLI asked it to measure.
func countEngineCalls(t *testing.T) *int {
	t.Helper()
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	calls := new(int)
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		*calls++
		return fakeCLIReport(), nil
	}
	return calls
}

// failingWriteOutputFile is a destination whose writes fail. It deliberately
// has no ReadFrom method, so io.Copy has to reach Write.
type failingWriteOutputFile struct{}

func (failingWriteOutputFile) Write([]byte) (int, error) { return 0, errors.New("write failed") }
func (failingWriteOutputFile) Sync() error               { return nil }
func (failingWriteOutputFile) Close() error              { return nil }
func (failingWriteOutputFile) Name() string              { return "failing-write" }

// TestRunBenchmarkRejectsAnUnusableOutputBeforeMeasuring pins #229: the
// destination used to be inspected only after the benchmark, so a mistyped
// --output cost a whole run and replaced its exit status with 2. Every
// destination outputWriter would refuse must now fail before the engine runs,
// without creating anything at the destination.
func TestRunBenchmarkRejectsAnUnusableOutputBeforeMeasuring(t *testing.T) {
	engineCalls := countEngineCalls(t)
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular.json")
	if err := os.WriteFile(regular, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	type unusable struct {
		name, output, wants string
	}
	cases := []unusable{
		{name: "missing parent directory", output: filepath.Join(directory, "missing", "run.json"), wants: "create temporary output file"},
		{name: "parent is a file", output: filepath.Join(regular, "run.json"), wants: "not a directory"},
		{name: "directory", output: directory, wants: "output path is a directory"},
	}
	for _, link := range []struct{ name, referent string }{
		{name: "symlink to a file", referent: "regular.json"},
		{name: "symlink to a directory", referent: "."},
		{name: "dangling symlink", referent: "absent.json"},
	} {
		path := filepath.Join(directory, strings.ReplaceAll(link.name, " ", "-"))
		if err := os.Symlink(link.referent, path); err != nil {
			t.Logf("skipping %s: %v", link.name, err)
			continue
		}
		cases = append(cases, unusable{name: link.name, output: path, wants: "output path is a symlink"})
	}
	// Permission checks do not bind root, and directory modes do not bind
	// anyone on Windows, so these cases run only where they can fail.
	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		readOnly := filepath.Join(directory, "read-only.json")
		if err := os.WriteFile(readOnly, []byte("keep"), 0o444); err != nil {
			t.Fatal(err)
		}
		locked := filepath.Join(directory, "locked")
		if err := os.Mkdir(locked, 0o555); err != nil {
			t.Fatal(err)
		}
		cases = append(cases,
			unusable{name: "read-only file", output: readOnly, wants: "output path is not writable"},
			unusable{name: "new file in a read-only directory", output: filepath.Join(locked, "run.json"), wants: "create temporary output file"},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			config := cliConfigForTest(t)
			config.output = tc.output
			err = runBenchmark(context.Background(), config)
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("run error = %v, want %q", err, tc.wants)
			}
			if code := exitCodeForError(err); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if *engineCalls != 0 {
				t.Fatalf("the benchmark ran %d time(s) for an unusable destination", *engineCalls)
			}
			after, err := os.ReadDir(directory)
			if err != nil || len(after) != len(before) {
				t.Fatalf("the preflight left entries behind: %v -> %v (%v)", before, after, err)
			}
		})
	}
	if content, err := os.ReadFile(regular); err != nil || string(content) != "keep" {
		t.Fatalf("a refused destination changed a file = %q/%v", content, err)
	}
}

// TestRunBenchmarkPreflightAcceptsInPlaceDestinations pins the other half of
// #229: the documented destinations that are written in place must still be
// accepted before the run, because the preflight never opens or truncates
// them and never asks their directory for a temporary file.
func TestRunBenchmarkPreflightAcceptsInPlaceDestinations(t *testing.T) {
	for _, path := range []string{"", " ", "-", os.DevNull} {
		if err := preflightOutput(path); err != nil {
			t.Fatalf("preflightOutput(%q) = %v", path, err)
		}
	}

	engineCalls := countEngineCalls(t)
	config := cliConfigForTest(t)
	config.output = os.DevNull
	if err := runBenchmark(context.Background(), config); err != nil || *engineCalls != 1 {
		t.Fatalf("run to %s = %v after %d engine call(s)", os.DevNull, err, *engineCalls)
	}

	// An existing writable file in a directory that rejects new entries is
	// written in place, so the preflight must not probe that directory. A
	// failing temporary-file seam makes the check independent of the user.
	oldCreate := createTempOutputFile
	t.Cleanup(func() { createTempOutputFile = oldCreate })
	createTempOutputFile = func(string, string) (outputFileHandle, error) {
		return nil, fmt.Errorf("open .report.speedns-1: %w", os.ErrPermission)
	}
	existing := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(existing, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	config = cliConfigForTest(t)
	config.output = existing
	if err := runBenchmark(context.Background(), config); err != nil || *engineCalls != 2 {
		t.Fatalf("run to an existing file in a locked directory = %v after %d engine call(s)", err, *engineCalls)
	}
	if content, err := os.ReadFile(existing); err != nil || !strings.Contains(string(content), "\"results\"") {
		t.Fatalf("in-place report = %q/%v", content, err)
	}
}

// TestPreflightOutputRemovesItsProbe pins that probing a new destination
// leaves nothing behind: the directory holds no report and no temporary file
// until the run has finished.
func TestPreflightOutputRemovesItsProbe(t *testing.T) {
	directory := t.TempDir()
	if err := preflightOutput(filepath.Join(directory, "report.json")); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("the preflight probe was left behind: %v/%v", entries, err)
	}
}

// TestRunBenchmarkReportsADestinationThatBreaksDuringTheRun keeps the post-run
// check authoritative. The preflight is advisory, so a destination that turns
// unusable while the benchmark runs must still be refused when the report is
// written.
func TestRunBenchmarkReportsADestinationThatBreaksDuringTheRun(t *testing.T) {
	config := cliConfigForTest(t)
	config.output = filepath.Join(t.TempDir(), "report.json")
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	calls := 0
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		calls++
		if err := os.Mkdir(config.output, 0o700); err != nil {
			t.Error(err)
		}
		return fakeCLIReport(), nil
	}
	err := runBenchmark(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "output path is a directory") || calls != 1 {
		t.Fatalf("run error = %v after %d engine call(s), want the post-run directory error", err, calls)
	}
}

// TestOutputWriterRefusesAFileTheCallerCannotWrite matches a shell
// redirection, which fails on a read-only file for an ordinary user. Renaming
// over the file would instead replace it regardless of the permissions that
// say it must not change.
func TestOutputWriterRefusesAFileTheCallerCannotWrite(t *testing.T) {
	// A synthetic regular file that cannot be opened covers the refusal for
	// every user, root included.
	oldLstat := lstatOutputPath
	t.Cleanup(func() { lstatOutputPath = oldLstat })
	lstatOutputPath = func(string) (os.FileInfo, error) { return fakeOutputPathInfo{mode: 0o644}, nil }
	missing := filepath.Join(t.TempDir(), "vanished.json")
	if _, _, err := outputWriter(missing); err == nil || !strings.Contains(err.Error(), "output path is not writable") {
		t.Fatalf("unopenable regular file error = %v", err)
	}
	lstatOutputPath = oldLstat

	if os.Geteuid() == 0 {
		t.Skip("root may write a read-only file, as a shell redirection run by root may")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("keep"), 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	for name, check := range map[string]func() error{
		"writer":    func() error { _, _, err := outputWriter(path); return err },
		"preflight": func() error { return preflightOutput(path) },
	} {
		if err := check(); err == nil || !strings.Contains(err.Error(), "output path is not writable") {
			t.Fatalf("%s error for a read-only file = %v", name, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("read-only file changed mode: %v/%v", info, err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "keep" {
		t.Fatalf("read-only file changed = %q/%v", content, err)
	}
}

// TestOutputLinkCountTreatsSyntheticInfoAsOneLink keeps a FileInfo that did
// not come from the operating system on the ordinary replacement path.
func TestOutputLinkCountTreatsSyntheticInfoAsOneLink(t *testing.T) {
	if got := outputLinkCount(fakeOutputPathInfo{mode: 0o644}); got != 1 {
		t.Fatalf("outputLinkCount(synthetic) = %d, want 1", got)
	}
}

// TestOutputWriterWritesInPlaceWhenTheRenameHitsAMountPoint pins the
// documented promise that a destination which cannot be replaced atomically is
// written in place. A single-file bind mount, common in containers, refuses
// the rename with EBUSY (EXDEV on some filesystems), and the finished report
// used to be deleted along with the temporary file.
func TestOutputWriterWritesInPlaceWhenTheRenameHitsAMountPoint(t *testing.T) {
	oldRename := renameOutputFile
	t.Cleanup(func() { renameOutputFile = oldRename })
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EXDEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "report.json")
			if err := os.WriteFile(path, []byte("a previous report longer than the new one"), 0o640); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			renames := 0
			renameOutputFile = func(oldPath, newPath string) error {
				renames++
				return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: errno}
			}
			writer, finalize, err := outputWriter(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(writer, "new report"); err != nil {
				t.Fatal(err)
			}
			if err := finalize(true); err != nil {
				t.Fatalf("finalize after %v = %v", errno, err)
			}
			if content, err := os.ReadFile(path); err != nil || string(content) != "new report" {
				t.Fatalf("destination after %v = %q/%v", errno, content, err)
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || renames != 1 {
				t.Fatalf("destination was not written in place: %v -> %v (%v, %d rename(s))", before, after, err, renames)
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 {
				t.Fatalf("the temporary file was left behind: %v/%v", entries, err)
			}
		})
	}
}

// TestOutputWriterCopiesIntoAWriteOnlyMountPoint pins that the in-place
// fallback after a refused rename works for a destination its owner may write
// but not read. The destination's mode is applied to the temporary file for
// the rename, so with 0200 neither the copy nor the owner of a kept report
// could read the finished report afterwards. Root reads it either way, so
// only an ordinary user can see the difference.
func TestOutputWriterCopiesIntoAWriteOnlyMountPoint(t *testing.T) {
	oldRename, oldOpen := renameOutputFile, openOutputFile
	t.Cleanup(func() { renameOutputFile, openOutputFile = oldRename, oldOpen })
	renameOutputFile = func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EBUSY}
	}
	for _, tc := range []struct {
		name      string
		copyFails bool
	}{
		{name: "copied into place"},
		{name: "kept when the copy fails", copyFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "report.json")
			if err := os.WriteFile(path, []byte("a previous report"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o200); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			openOutputFile = oldOpen
			writer, finalize, err := outputWriter(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(writer, "new report"); err != nil {
				t.Fatal(err)
			}
			if tc.copyFails {
				openOutputFile = func(string) (outputFileHandle, error) { return nil, errors.New("open failed") }
			}
			err = finalize(true)
			if tc.copyFails {
				entries, readErr := os.ReadDir(directory)
				if err == nil || readErr != nil || len(entries) != 2 {
					t.Fatalf("failed copy = %v, entries %v/%v", err, entries, readErr)
				}
				for _, entry := range entries {
					kept := filepath.Join(directory, entry.Name())
					if kept == path {
						continue
					}
					if content, err := os.ReadFile(kept); err != nil || string(content) != "new report" {
						t.Fatalf("the kept report cannot be read by its owner: %q/%v", content, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("fallback into a write-only destination = %v", err)
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
				t.Fatalf("destination was not written in place: %v -> %v (%v)", before, after, err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if content, err := os.ReadFile(path); err != nil || string(content) != "new report" {
				t.Fatalf("destination = %q/%v", content, err)
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 {
				t.Fatalf("the temporary file was left behind: %v/%v", entries, err)
			}
		})
	}
}

// TestOutputWriterReportsAFailedInPlaceFallback covers every way the in-place
// copy after a refused rename can fail. Each failure is reported with the
// rename error that caused the fallback. The copy may already have truncated
// the destination, so the temporary file, then the only complete report, is
// kept and named in the error instead of being deleted with the finished run.
func TestOutputWriterReportsAFailedInPlaceFallback(t *testing.T) {
	oldRename, oldOpen := renameOutputFile, openOutputFile
	t.Cleanup(func() { renameOutputFile, openOutputFile = oldRename, oldOpen })
	busy := func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EBUSY}
	}
	for _, tc := range []struct {
		name   string
		rename func(string, string) error
		open   func(string) (outputFileHandle, error)
		wants  string
	}{
		{
			name: "temporary file vanished",
			rename: func(oldPath, newPath string) error {
				_ = os.Remove(oldPath)
				return busy(oldPath, newPath)
			},
			open:  oldOpen,
			wants: "reopen temporary output file",
		},
		{
			name:  "destination cannot be opened",
			open:  func(string) (outputFileHandle, error) { return nil, errors.New("open failed") },
			wants: "open output file: open failed",
		},
		{
			name:  "copy fails",
			open:  func(string) (outputFileHandle, error) { return failingWriteOutputFile{}, nil },
			wants: "copy output file: write failed",
		},
		{
			name: "flush fails",
			open: func(string) (outputFileHandle, error) {
				return &fakeOutputFile{syncErr: errors.New("sync failed")}, nil
			},
			wants: "flush output file: sync failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			renameOutputFile = busy
			if tc.rename != nil {
				renameOutputFile = tc.rename
			}
			openOutputFile = oldOpen
			directory := t.TempDir()
			writer, finalize, err := outputWriter(filepath.Join(directory, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(writer, "finished report"); err != nil {
				t.Fatal(err)
			}
			openOutputFile = tc.open
			err = finalize(true)
			if err == nil || !strings.Contains(err.Error(), tc.wants) ||
				!strings.Contains(err.Error(), "replace output file: rename") {
				t.Fatalf("fallback error = %v, want %q after the rename error", err, tc.wants)
			}
			entries, readErr := os.ReadDir(directory)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.rename != nil {
				// Nothing is left to keep once the temporary file is gone,
				// so the error must not point at it.
				if len(entries) != 0 || strings.Contains(err.Error(), "kept at") {
					t.Fatalf("a vanished temporary file was reported as kept: %v (%v)", err, entries)
				}
				return
			}
			if len(entries) != 1 {
				t.Fatalf("the finished report was not kept: %v", entries)
			}
			kept := filepath.Join(directory, entries[0].Name())
			if !strings.HasSuffix(err.Error(), "the complete report is kept at "+kept) {
				t.Fatalf("fallback error = %v, want it to name %s", err, kept)
			}
			if content, err := os.ReadFile(kept); err != nil || string(content) != "finished report" {
				t.Fatalf("kept report = %q/%v", content, err)
			}
		})
	}
}

// TestOutputWriterSyncsTheDirectoryAfterARename pins that a replacement is
// made durable, not only atomic, and that a platform which cannot sync a
// directory still gets its report. Nothing is synced when no rename happened.
func TestOutputWriterSyncsTheDirectoryAfterARename(t *testing.T) {
	oldSync, oldRename := syncOutputDirectory, renameOutputFile
	t.Cleanup(func() { syncOutputDirectory, renameOutputFile = oldSync, oldRename })
	var synced []string
	syncOutputDirectory = func(directory string) error {
		synced = append(synced, directory)
		return errors.New("directory sync unsupported")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	commit := func(commit bool) error {
		t.Helper()
		writer, finalize, err := outputWriter(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, "report"); err != nil {
			t.Fatal(err)
		}
		return finalize(commit)
	}
	if err := commit(true); err != nil {
		t.Fatalf("a failed directory sync must not fail the run: %v", err)
	}
	// The writer takes the directory from the cleaned destination path, so a
	// TMPDIR spelled with a ".." segment must not make the same directory
	// look different here.
	if want := filepath.Dir(path); len(synced) != 1 || synced[0] != want {
		t.Fatalf("synced directories = %q, want [%q]", synced, want)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "report" {
		t.Fatalf("report = %q/%v", content, err)
	}

	if err := commit(false); err != nil {
		t.Fatal(err)
	}
	renameOutputFile = func(string, string) error { return errors.New("rename failed") }
	if err := commit(true); err == nil {
		t.Fatal("expected the rename error")
	}
	renameOutputFile = func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EBUSY}
	}
	if err := commit(true); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 {
		t.Fatalf("a run without a rename synced %q", synced[1:])
	}

	if err := oldSync(filepath.Join(directory, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("syncing a missing directory = %v", err)
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

// TestCacheMissDefaultSampleRaisesNoOversizeWarning runs the real engine,
// because the stubbed engines above cannot see the warning it adds. The
// generated corpus holds at most 20 names and the default --sample is 100, so
// every documented cache-miss invocation used to carry "requested sample of
// 100 domains exceeds the normalized corpus size". Clamping the engine's
// sample must not change what is measured or recorded: sample_size and the
// corpus fields stay exactly what an unclamped run reported.
func TestCacheMissDefaultSampleRaisesNoOversizeWarning(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeNameError)
		_ = writer.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })

	oldEngine := runBenchmarkEngine
	oldNonce := newCacheMissNonceFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		newCacheMissNonceFunc = oldNonce
	})
	var captured benchmark.Options
	runBenchmarkEngine = func(ctx context.Context, targets []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		captured = options
		return benchmark.Run(ctx, targets, options)
	}
	newCacheMissNonceFunc = func() (string, error) { return "0123456789abcdef", nil }

	for _, sample := range []int{benchmark.DefaultSample, 30} {
		config := &cliConfig{
			protocols: "udp", resolverFlags: []string{"lab=udp://" + conn.LocalAddr().String()}, noDefaults: true,
			cacheMiss: true, cacheMissSample: 10, sample: sample, seed: 7, queryTypes: "A", timeout: time.Second,
			concurrency: 4, format: "json", family: "4", output: filepath.Join(t.TempDir(), "cache.json"),
		}
		// A loopback resolver is measured but never ranked, so this run has
		// nothing comparable; the report is still written and is what matters.
		if err := runBenchmark(context.Background(), config); !errors.Is(err, benchmark.ErrNoComparableResults) {
			t.Fatalf("--sample %d: run error = %v", sample, err)
		}
		if captured.Sample != 10 {
			t.Fatalf("--sample %d reached the engine as %d, want the 10-name corpus", sample, captured.Sample)
		}
		content, err := os.ReadFile(config.output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "requested sample") || strings.Contains(string(content), "truncated the generated cache-miss corpus") {
			t.Fatalf("--sample %d raised a sample warning on a full cache-miss corpus: %s", sample, content)
		}
		for _, expected := range []string{"\"sample_size\": 10", "\"queries_per_target\": 10", "\"corpus_entries\": 10"} {
			if !strings.Contains(string(content), expected) {
				t.Fatalf("--sample %d report missing %q: %s", sample, expected, content)
			}
		}
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

// TestCacheMissMeasuresEachResolverExactlyOnce pins the #108 fix. A resolver
// holds one cache across every transport and address it offers, so measuring it
// twice makes the second measurement a warm read of a name the first already
// cached. Cache-miss mode therefore keeps one endpoint per resolver and says
// which endpoints it dropped.
func TestCacheMissMeasuresEachResolverExactlyOnce(t *testing.T) {
	oldEngine := runBenchmarkEngine
	oldNonce := newCacheMissNonceFunc
	t.Cleanup(func() {
		runBenchmarkEngine = oldEngine
		newCacheMissNonceFunc = oldNonce
	})
	var measured []catalog.Target
	var options benchmark.Options
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, opts benchmark.Options) (benchmark.Report, error) {
		measured = targets
		options = opts
		return fakeCLIReport(), nil
	}
	newCacheMissNonceFunc = func() (string, error) { return "0123456789abcdef", nil }

	// One resolver offering two transports on two addresses: all four endpoints
	// reach the same cache, so three of them would measure a warm read.
	resolverFile := filepath.Join(t.TempDir(), "resolvers.yaml")
	if err := os.WriteFile(resolverFile, []byte(`version: 1
resolvers:
  - id: lab
    name: Lab
    owner: Lab
    policy: unfiltered
    addresses:
      - 127.0.0.1
      - 127.0.0.2
    transports:
      udp:
        port: 53
      tcp:
        port: 53
`), 0o644); err != nil {
		t.Fatal(err)
	}
	multi := &cliConfig{
		protocols: "udp,tcp", resolverFile: resolverFile,
		noDefaults: true, cacheMiss: true, cacheMissSample: 2, sample: 100, seed: 7, queryTypes: "A",
		timeout: time.Second, concurrency: 1, format: "json", family: "4",
		output: filepath.Join(t.TempDir(), "multi.json"),
	}
	if err := runBenchmark(context.Background(), multi); err != nil {
		t.Fatal(err)
	}
	if len(measured) != 1 || measured[0].Protocol != catalog.UDP {
		t.Fatalf("cache-miss measured %d targets (%#v), want one udp endpoint", len(measured), measured)
	}
	if !options.CacheMiss {
		t.Fatal("the engine was not told this is a cache-miss run")
	}
	content, err := os.ReadFile(multi.output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "dropped 3 endpoint(s) that share a cache") {
		t.Fatalf("the dropped endpoint was not disclosed: %s", content)
	}

	// Two independent resolvers do not share a cache, so neither is dropped.
	independent := *multi
	independent.protocols = "udp"
	independent.resolverFile = ""
	independent.resolverFlags = []string{"a=udp://127.0.0.1:53", "b=udp://127.0.0.2:53"}
	independent.output = filepath.Join(t.TempDir(), "independent.json")
	if err := runBenchmark(context.Background(), &independent); err != nil {
		t.Fatal(err)
	}
	if len(measured) != 2 {
		t.Fatalf("two independent resolvers measured %d targets", len(measured))
	}
	content, err = os.ReadFile(independent.output)
	if err != nil || strings.Contains(string(content), "share a cache") {
		t.Fatalf("independent resolvers must not be dropped: %q/%v", content, err)
	}

	// A warm-cache run is untouched: both transports of one resolver are kept.
	warm := *multi
	warm.cacheMiss = false
	warm.domainFile = cliDomainFile(t)
	warm.output = filepath.Join(t.TempDir(), "warm.json")
	if err := runBenchmark(context.Background(), &warm); err != nil {
		t.Fatal(err)
	}
	if len(measured) != 4 {
		t.Fatalf("warm-cache run measured %d targets, want all four endpoints", len(measured))
	}
	if options.CacheMiss {
		t.Fatal("a warm-cache run must not set the cache-miss option")
	}
}

// runCacheMissFixture runs one cache-miss benchmark against a stub engine and
// returns the endpoints the engine was asked to measure and the JSON report.
// Only the selection is under test, so the engine never touches a network.
func runCacheMissFixture(t *testing.T, config cliConfig) ([]catalog.Target, string) {
	t.Helper()
	oldEngine, oldNonce := runBenchmarkEngine, newCacheMissNonceFunc
	defer func() { runBenchmarkEngine, newCacheMissNonceFunc = oldEngine, oldNonce }()
	var measured []catalog.Target
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		measured = append([]catalog.Target(nil), targets...)
		return fakeCLIReport(), nil
	}
	newCacheMissNonceFunc = func() (string, error) { return "0123456789abcdef", nil }
	config.cacheMiss, config.cacheMissSample, config.sample, config.seed = true, 2, 100, 7
	config.queryTypes, config.timeout, config.concurrency, config.format = "A", time.Second, 1, "json"
	config.output = filepath.Join(t.TempDir(), "cache-miss.json")
	if err := runBenchmark(context.Background(), &config); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(config.output)
	if err != nil {
		t.Fatal(err)
	}
	return measured, string(content)
}

func measuredIDs(targets []catalog.Target) []string {
	ids := make([]string, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.ID())
	}
	return ids
}

func writeResolverFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolvers.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nresolvers:\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCacheMissCollapsesProfilesThatReachOneServer pins #238 (a). A resolver
// is not a profile: two --resolver flags at one server are two profiles, and
// so are the bundled Google pair that both answer as dns.google. Keying on the
// profile ID measured each of them with the same generated names, so all but
// the first measured a warm read with no warning. Profiles that share an
// address or a TLS identity are now one cache, measured once, and every
// endpoint that was folded into it is named in the warning.
func TestCacheMissCollapsesProfilesThatReachOneServer(t *testing.T) {
	sharedDoH := writeResolverFixture(t, `  - id: doh-a
    name: DoH A
    owner: Lab
    policy: unfiltered
    addresses: ["192.0.2.1"]
    transports:
      doh:
        url: https://doh.example.test/dns-query
  - id: doh-b
    name: DoH B
    owner: Lab
    policy: family filter
    addresses: ["192.0.2.2"]
    transports:
      doh:
        url: https://DOH.Example.Test./family-filter
`)
	unrelated := writeResolverFixture(t, `  - id: lab-a
    name: Lab A
    owner: Lab
    policy: unfiltered
    addresses: ["192.0.2.1"]
    transports:
      dot:
        server_name: a.example.test
  - id: lab-b
    name: Lab B
    owner: Lab
    policy: unfiltered
    addresses: ["192.0.2.2"]
    transports:
      dot:
        server_name: b.example.test
`)
	for _, test := range []struct {
		name     string
		config   cliConfig
		measured []string
		dropped  []string
	}{
		{
			// The first resolver named is the one measured, even though DoH
			// precedes DoT in the documented protocol order: the profile is
			// chosen before its transport.
			name: "two resolver flags at one host",
			config: cliConfig{
				protocols: "doh,dot", noDefaults: true, family: "both",
				resolverFlags: []string{"private-dot=tls://dns.example.test:853", "private-doh=https://dns.example.test/dns-query"},
			},
			measured: []string{"custom-private-dot@dns.example.test/dot"},
			dropped:  []string{"custom-private-doh@dns.example.test/doh"},
		},
		{
			// One address is one server whatever port it is reached on.
			name: "one address on two ports",
			config: cliConfig{
				protocols: "udp", noDefaults: true, family: "4",
				resolverFlags: []string{"first=udp://127.0.0.1:53", "second=udp://127.0.0.1:5353"},
			},
			measured: []string{"custom-first@127.0.0.1/udp"},
			dropped:  []string{"custom-second@127.0.0.1/udp"},
		},
		{
			// Both answer as dns.google, so google-8844 is the same cache.
			// The list is in catalog.Expand order, which both lists keep.
			name:     "bundled google pair",
			config:   cliConfig{protocols: "udp", family: "4"},
			measured: []string{"cloudflare-1111@1.1.1.1/udp", "cloudflare-1112@1.1.1.2/udp", "dns4eu-11100@86.54.11.100/udp", "dns4eu-1112@86.54.11.12/udp", "dns4eu-1113@86.54.11.13/udp", "dns4eu-111@86.54.11.1/udp", "google-8888@8.8.8.8/udp", "quad9-99910@9.9.9.10/udp", "quad9-9999@9.9.9.9/udp"},
			dropped:  []string{"google-8844@8.8.4.4/udp"},
		},
		{
			// Different addresses and paths, one DoH host: case and a trailing
			// dot do not make it a different server.
			name:     "doh-only profiles sharing a host",
			config:   cliConfig{protocols: "doh", noDefaults: true, family: "4", resolverFile: sharedDoH},
			measured: []string{"doh-a@192.0.2.1/doh"},
			dropped:  []string{"doh-b@192.0.2.2/doh"},
		},
		{
			// Sibling names under one parent are not one server; nothing beyond
			// an identical endpoint is inferred.
			name:     "unrelated profiles",
			config:   cliConfig{protocols: "dot", noDefaults: true, family: "4", resolverFile: unrelated},
			measured: []string{"lab-a@192.0.2.1/dot", "lab-b@192.0.2.2/dot"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			measured, content := runCacheMissFixture(t, test.config)
			if got := measuredIDs(measured); !slices.Equal(got, test.measured) {
				t.Fatalf("cache-miss measured %q, want %q", got, test.measured)
			}
			if len(test.dropped) == 0 {
				if strings.Contains(content, "share a cache") {
					t.Fatalf("unrelated profiles were collapsed: %s", content)
				}
				return
			}
			want := fmt.Sprintf("dropped %d endpoint(s) that share a cache with one already selected: %s",
				len(test.dropped), strings.Join(test.dropped, ", "))
			if !strings.Contains(content, want) {
				t.Fatalf("warning %q missing from %s", want, content)
			}
		})
	}

	// A warm-cache run is untouched: every bundled endpoint is measured,
	// google-8844 included, and nothing is reported as sharing a cache.
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	var measured []catalog.Target
	runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
		measured = append([]catalog.Target(nil), targets...)
		return fakeCLIReport(), nil
	}
	warm := &cliConfig{
		protocols: "udp", family: "4", domainFile: cliDomainFile(t), sample: 1, seed: 7, queryTypes: "A",
		timeout: time.Second, concurrency: 1, format: "json", output: filepath.Join(t.TempDir(), "warm.json"),
	}
	if err := runBenchmark(context.Background(), warm); err != nil {
		t.Fatal(err)
	}
	profiles, err := catalog.FilterProfilesByFamily(catalog.DefaultResolvers(), catalog.Family4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := measuredIDs(measured), measuredIDs(catalog.Expand(profiles, []catalog.Protocol{catalog.UDP})); !slices.Equal(got, want) {
		t.Fatalf("warm-cache run measured %q, want every bundled endpoint %q", got, want)
	}
	content, err := os.ReadFile(warm.output)
	if err != nil || strings.Contains(string(content), "share a cache") {
		t.Fatalf("a warm-cache run must not drop endpoints: %q/%v", content, err)
	}
}

// TestCacheMissKeepsEachProfilesDeclaredFirstAddress pins #238 (b). The kept
// endpoint used to be the lowest-sorting target ID, so on a dual-stack host a
// cache-miss run measured Cloudflare over IPv4 ("1.1.1.1" < "2606:") and every
// other bundled resolver over IPv6 ("2001:" < "8.8.8.8"), and its one ranking
// compared families by accident of string order. Each profile now contributes
// its first transport at its first declared address, which for the bundled
// catalog is IPv4 throughout, and the same input always selects the same set.
func TestCacheMissKeepsEachProfilesDeclaredFirstAddress(t *testing.T) {
	oldDetector := detectAddressFamiliesFunc
	t.Cleanup(func() { detectAddressFamiliesFunc = oldDetector })
	detectAddressFamiliesFunc = func() (map[catalog.AddressFamily]bool, error) {
		return map[catalog.AddressFamily]bool{catalog.Family4: true, catalog.Family6: true}, nil
	}
	for _, test := range []struct {
		family string
		want   func(netip.Addr) bool
	}{
		{family: "auto", want: netip.Addr.Is4},
		{family: "both", want: netip.Addr.Is4},
		// With IPv4 filtered out, the first declared address left is IPv6.
		{family: "6", want: netip.Addr.Is6},
	} {
		t.Run(test.family, func(t *testing.T) {
			config := cliConfig{protocols: "udp,tcp,doh,dot,doq", family: test.family}
			measured, _ := runCacheMissFixture(t, config)
			if len(measured) != 9 {
				t.Fatalf("cache-miss measured %d endpoints, want one per bundled cache (9): %q", len(measured), measuredIDs(measured))
			}
			for _, target := range measured {
				address := netip.MustParseAddr(target.Address)
				if !test.want(address) || target.Address != target.Resolver.Addresses[0] || target.Protocol != catalog.UDP {
					t.Fatalf("kept %s, want udp at the first declared address of %q", target.ID(), target.Resolver.Addresses)
				}
			}
			again, _ := runCacheMissFixture(t, config)
			if !slices.Equal(measuredIDs(again), measuredIDs(measured)) {
				t.Fatalf("selection is not deterministic: %q then %q", measuredIDs(measured), measuredIDs(again))
			}
		})
	}
}

// TestCacheMissGroupsAreTransitive pins why cacheGroups is a union-find. Here
// "bridge" shares an address with "first" and another with "second", which
// share nothing with each other directly; all three are one server. A single
// pass that compared each profile only with those kept before it would have
// kept "second", because it was declared before the profile that links it.
// It also pins the address rule: "v6first" declares IPv6 first, so IPv6 is
// what it is measured over, although its IPv4 target ID sorts first.
func TestCacheMissGroupsAreTransitive(t *testing.T) {
	udp := map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}}
	profiles := []catalog.ResolverProfile{
		{ID: "first", Addresses: []string{"192.0.2.1"}, Transports: udp},
		{ID: "second", Addresses: []string{"192.0.2.2"}, Transports: udp},
		{ID: "bridge", Addresses: []string{"192.0.2.2", "192.0.2.1"}, Transports: udp},
		{ID: "v6first", Addresses: []string{"2001:db8::9", "192.0.2.9"}, Transports: udp},
	}
	kept, dropped := cacheMissTargets(profiles, catalog.Expand(profiles, []catalog.Protocol{catalog.UDP}))
	if got, want := measuredIDs(kept), []string{"first@192.0.2.1/udp", "v6first@2001:db8::9/udp"}; !slices.Equal(got, want) {
		t.Fatalf("kept %q, want %q", got, want)
	}
	if got, want := measuredIDs(dropped), []string{"bridge@192.0.2.1/udp", "bridge@192.0.2.2/udp", "second@192.0.2.2/udp", "v6first@192.0.2.9/udp"}; !slices.Equal(got, want) {
		t.Fatalf("dropped %q, want %q", got, want)
	}
	if got, want := cacheGroups(profiles), []int{0, 0, 0, 3}; !slices.Equal(got, want) {
		t.Fatalf("cacheGroups = %v, want %v", got, want)
	}
}

// TestCacheMissWarningRedactsDroppedSystemEndpoints covers the one place the
// warning must not name an endpoint. A system resolver that is the same
// server as a bundled profile is dropped in its favour, and the report only
// redacts system endpoints it measured, so naming the dropped one would print
// the system resolver's address in a report the operator asked to redact.
func TestCacheMissWarningRedactsDroppedSystemEndpoints(t *testing.T) {
	oldDiscover := discoverSystemResolvers
	t.Cleanup(func() { discoverSystemResolvers = oldDiscover })
	discoverSystemResolvers = func(context.Context) ([]catalog.ResolverProfile, error) {
		return []catalog.ResolverProfile{{
			ID: "system-8-8-8-8", Name: "System DNS", Owner: "configured locally", Policy: "unknown",
			Addresses:  []string{"8.8.8.8"},
			Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}, catalog.TCP: {Port: 53}},
		}}, nil
	}
	config := cliConfig{protocols: "udp,tcp", family: "4", includeSystem: true}
	_, named := runCacheMissFixture(t, config)
	if !strings.Contains(named, "system-8-8-8-8@8.8.8.8/udp") {
		t.Fatalf("the dropped system endpoint was not named: %s", named)
	}
	config.redactSystem = true
	measured, redacted := runCacheMissFixture(t, config)
	if slices.ContainsFunc(measured, report.IsSystemTarget) {
		t.Fatalf("the system resolver was measured beside google-8888: %q", measuredIDs(measured))
	}
	if strings.Contains(redacted, "system-8-8-8-8") || !strings.Contains(redacted, "google-8844@8.8.4.4/udp") ||
		!strings.Contains(redacted, "2 redacted system endpoint(s)") {
		t.Fatalf("--redact-system warning = %s", redacted)
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

func TestOutputWriterPreservesExistingFileMode(t *testing.T) {
	for _, mode := range []fs.FileMode{0o600, 0o640, 0o664} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte("old"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			writer, finalize, err := outputWriter(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(writer, "new\n"); err != nil {
				t.Fatal(err)
			}
			if err := finalize(true); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != mode {
				t.Fatalf("replacement mode = %04o, want %04o", got, mode)
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != "new\n" {
				t.Fatalf("replacement content = %q/%v", content, err)
			}
		})
	}
}

func TestOutputWriterRefusesToBroadenModeWhenPreservationFails(t *testing.T) {
	oldChmod := chmodOutputFile
	t.Cleanup(func() { chmodOutputFile = oldChmod })
	chmodOutputFile = func(string, fs.FileMode) error { return errors.New("chmod failed") }

	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "new\n"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err == nil || !strings.Contains(err.Error(), "preserve output file mode") {
		t.Fatalf("mode preservation error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("failed replacement changed mode to %04o", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "old" {
		t.Fatalf("failed replacement changed content to %q/%v", content, err)
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

// TestInterruptWarningFollowsTheReportEvidence pins the warning an
// interrupted run carries. The engine returns the cancellation whenever the
// run context was cancelled, including after every target had finished and
// only statistics were left, and the CLI used to call every such report
// "interrupted before all targets completed" -- telling an operator to
// distrust a complete, ranked report. The exit status and the precedence of
// the interrupt over assertions are the documented contract and must not move.
func TestInterruptWarningFollowsTheReportEvidence(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	const (
		completeWarning   = "interrupt received after measurement completed; results are complete"
		incompleteWarning = "benchmark interrupted before all targets completed"
	)
	for _, tc := range []struct {
		name  string
		shape func([]benchmark.TargetResult) []benchmark.TargetResult
		want  string
	}{
		{name: "complete", shape: func(results []benchmark.TargetResult) []benchmark.TargetResult { return results }, want: completeWarning},
		{name: "incomplete target", shape: func(results []benchmark.TargetResult) []benchmark.TargetResult {
			results[0].Incomplete = true
			return results
		}, want: incompleteWarning},
		{name: "missing target", shape: func([]benchmark.TargetResult) []benchmark.TargetResult { return nil }, want: incompleteWarning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runBenchmarkEngine = func(_ context.Context, targets []catalog.Target, _ benchmark.Options) (benchmark.Report, error) {
				report := fakeCLIReport()
				results := make([]benchmark.TargetResult, 0, len(targets))
				for _, target := range targets {
					result := report.Targets[0]
					result.Target = target
					results = append(results, result)
				}
				report.Targets = tc.shape(results)
				report.Rankings = []benchmark.Ranking{{Protocol: targets[0].Protocol, TargetID: targets[0].ID(), Rank: 1}}
				return report, context.Canceled
			}
			config := cliConfigForTest(t)
			// A failing assertion proves the interrupt still takes precedence:
			// a complete report is not a reason to start evaluating them.
			config.assertions = []string{"p95<1ms"}
			config.output = filepath.Join(t.TempDir(), "interrupted.json")
			err := runBenchmark(context.Background(), config)
			if !errors.Is(err, context.Canceled) || exitCodeForError(err) != 130 {
				t.Fatalf("interrupted run returned %v (exit %d), want context.Canceled and 130", err, exitCodeForError(err))
			}
			content, readErr := os.ReadFile(config.output)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, warning := range []string{completeWarning, incompleteWarning} {
				if strings.Contains(string(content), warning) != (warning == tc.want) {
					t.Fatalf("report warnings disagree with the evidence, want only %q: %s", tc.want, content)
				}
			}
		})
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

// TestClassifyLocalResolversSeparatesTheHostFromTheNetwork pins the two
// deliberately different strengths.
//
// METHODOLOGY promises a resolver on the local host is never ranked, because it
// answers from its own cache and excludes the upstream resolution it forwards.
// That fired only for system-discovered targets and tested loopback alone, so
// `--resolver pihole=udp://127.0.0.1` was ranked and a router forwarder
// competed with public resolvers.
func TestClassifyLocalResolversSeparatesTheHostFromTheNetwork(t *testing.T) {
	// The measuring host holds one routable address and one ULA.
	own := map[string]bool{"203.0.113.7": true, "fd00::7": true}

	profile := func(id string, addresses ...string) catalog.ResolverProfile {
		return catalog.ResolverProfile{
			ID: id, Name: id, Owner: "Owner", Policy: "unfiltered",
			Addresses:  addresses,
			Transports: map[catalog.Protocol]catalog.TransportSpec{catalog.UDP: {Port: 53}},
		}
	}
	profiles := []catalog.ResolverProfile{
		profile("loopback4", "127.0.0.1"),
		profile("loopback6", "::1"),
		profile("this-host", "203.0.113.7"),
		profile("this-host-v6", "fd00::7"),
		profile("router", "192.168.1.1"),
		profile("cgnat", "100.100.100.100"),
		profile("linklocal", "169.254.1.1"),
		profile("ula", "fd7a:115c:a1e0::53"),
		profile("public", "8.8.8.8"),
		profile("public6", "2001:4860:4860::8888"),
		profile("mapped-loopback", "::ffff:127.0.0.1"),
		// A hostname endpoint carries no literal to classify; it must be
		// skipped rather than guessed at.
		profile("hostname", "dns.example.test"),
	}

	onNetwork := classifyLocalResolvers(profiles, own)

	local := map[string]bool{}
	for _, p := range profiles {
		if p.Local {
			local[p.ID] = true
		}
	}
	// Loopback and the host's own addresses ARE the local host.
	for _, id := range []string{"loopback4", "loopback6", "this-host", "this-host-v6", "mapped-loopback"} {
		if !local[id] {
			t.Errorf("%s should be classified as running on the local host", id)
		}
	}
	// Everything else keeps its rank, including private addresses the host
	// does not hold: the tool cannot tell a forwarder from a self-hosted
	// recursive resolver, and refusing to rank one would punish a legitimate
	// setup.
	for _, id := range []string{"router", "cgnat", "linklocal", "ula", "public", "public6", "hostname"} {
		if local[id] {
			t.Errorf("%s must not be treated as running on the local host", id)
		}
	}
	// But the private ones must be disclosed.
	reported := strings.Join(onNetwork, " ")
	for _, id := range []string{"router", "cgnat", "linklocal", "ula"} {
		if !strings.Contains(reported, id) {
			t.Errorf("%s is reached over the local network and must be reported: %q", id, reported)
		}
	}
	for _, id := range []string{"public", "public6", "loopback4", "this-host", "hostname"} {
		if strings.Contains(reported, id) {
			t.Errorf("%s must not be reported as on-network: %q", id, reported)
		}
	}
}

// TestHostOwnAddressesReadsUpInterfacesOnly covers the inventory, including
// loopback, which the family detector deliberately skips but this one needs.
func TestHostOwnAddressesReadsUpInterfacesOnly(t *testing.T) {
	oldList, oldAddrs := listNetworkInterfacesFunc, interfaceAddressesFunc
	t.Cleanup(func() { listNetworkInterfacesFunc, interfaceAddressesFunc = oldList, oldAddrs })

	listNetworkInterfacesFunc = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo", Flags: net.FlagUp},
			{Index: 2, Name: "eth0", Flags: net.FlagUp},
			{Index: 3, Name: "eth1"}, // down: must be ignored
		}, nil
	}
	interfaceAddressesFunc = func(iface net.Interface) ([]net.Addr, error) {
		switch iface.Name {
		case "lo":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1")}}, nil
		case "eth0":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.7")}}, nil
		default:
			return []net.Addr{&net.IPNet{IP: net.ParseIP("198.51.100.9")}}, nil
		}
	}
	own, err := hostOwnAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if !own["127.0.0.1"] || !own["203.0.113.7"] {
		t.Fatalf("inventory missing an up-interface address: %#v", own)
	}
	if own["198.51.100.9"] {
		t.Fatalf("an address on a down interface reached the inventory: %#v", own)
	}

	listNetworkInterfacesFunc = func() ([]net.Interface, error) { return nil, errors.New("no interfaces") }
	if _, err := hostOwnAddresses(); err == nil {
		t.Fatal("an interface enumeration failure must be reported")
	}
	listNetworkInterfacesFunc = func() ([]net.Interface, error) {
		return []net.Interface{{Index: 1, Name: "eth0", Flags: net.FlagUp}}, nil
	}
	interfaceAddressesFunc = func(net.Interface) ([]net.Addr, error) { return nil, errors.New("no addresses") }
	if _, err := hostOwnAddresses(); err == nil {
		t.Fatal("an address enumeration failure must be reported")
	}
}

// TestOnNetworkResolversAreDisclosedAndRedacted covers how the on-network
// warning reaches the report, including under --redact-system where naming the
// resolver would leak the host's own network layout.
func TestOnNetworkResolversAreDisclosedAndRedacted(t *testing.T) {
	oldEngine, oldOwn := runBenchmarkEngine, hostOwnAddressesFunc
	t.Cleanup(func() { runBenchmarkEngine, hostOwnAddressesFunc = oldEngine, oldOwn })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}
	hostOwnAddressesFunc = func() (map[string]bool, error) { return map[string]bool{}, nil }

	base := &cliConfig{
		protocols: "udp", resolverFlags: []string{"router=udp://192.168.1.1:53"}, noDefaults: true,
		sample: 5, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1,
		format: "json", family: "4",
	}
	named := *base
	named.output = filepath.Join(t.TempDir(), "named.json")
	if err := runBenchmark(context.Background(), &named); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(named.output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "192.168.1.1") ||
		!strings.Contains(string(content), "may be a forwarder") {
		t.Fatalf("the on-network resolver was not disclosed: %s", content)
	}

	// Redacted: the count is still disclosed, the address is not.
	redacted := *base
	redacted.redactSystem = true
	redacted.output = filepath.Join(t.TempDir(), "redacted.json")
	if err := runBenchmark(context.Background(), &redacted); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(redacted.output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "1 resolver(s) are reached over the local network") {
		t.Fatalf("the redacted disclosure is missing: %s", content)
	}
	if strings.Contains(string(content), "192.168.1.1") {
		t.Fatalf("--redact-system leaked a local address: %s", content)
	}

	// An inventory failure must stop the run rather than silently skipping
	// classification, which would quietly restore the old behaviour.
	hostOwnAddressesFunc = func() (map[string]bool, error) { return nil, errors.New("inventory unavailable") }
	failing := *base
	failing.output = filepath.Join(t.TempDir(), "failing.json")
	if err := runBenchmark(context.Background(), &failing); err == nil ||
		!strings.Contains(err.Error(), "inventory unavailable") {
		t.Fatalf("inventory failure = %v", err)
	}
}

// TestProvenanceRecordsFamilyAndDNSSEC pins two settings that change WHAT was
// measured rather than how it was reported.
//
// --family decides which targets exist at all, and --dnssec sets the EDNS(0) DO
// bit on every measured query, changing the wire format. Neither was recorded,
// so two reports could describe different experiments while looking identical
// in their provenance -- which any tool comparing runs has to be able to tell.
//
// The recorded value is what the user asked for, not what it resolved to:
// "auto" on a host with no IPv6 selects a different target set than "auto" on
// one with IPv6, and both record "auto". Comparing target sets is what catches
// that; this field records intent.
func TestProvenanceRecordsFamilyAndDNSSEC(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		return fakeCLIReport(), nil
	}

	for _, testCase := range []struct {
		name       string
		family     string
		dnssec     bool
		wantFamily string
	}{
		{"explicit v4", "4", false, "4"},
		{"explicit v6 with dnssec", "6", true, "6"},
		{"auto records the request", "auto", false, "auto"},
		{"both", "both", true, "both"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// An explicit family filters by address literal, so the resolver
			// has to be in the family being requested.
			resolver := "lab=udp://127.0.0.1:53"
			if testCase.family == "6" {
				resolver = "lab=udp://[::1]:53"
			}
			config := &cliConfig{
				protocols: "udp", resolverFlags: []string{resolver}, noDefaults: true,
				sample: 3, seed: 1, queryTypes: "A", timeout: time.Second, concurrency: 1,
				format: "json", family: testCase.family, dnssec: testCase.dnssec,
				output: filepath.Join(t.TempDir(), "run.json"),
			}
			if err := runBenchmark(context.Background(), config); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(config.output)
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Run struct {
					Provenance struct {
						Family string `json:"family"`
						DNSSEC bool   `json:"dnssec"`
					} `json:"provenance"`
				} `json:"run"`
			}
			if err := json.Unmarshal(content, &report); err != nil {
				t.Fatal(err)
			}
			if report.Run.Provenance.Family != testCase.wantFamily {
				t.Fatalf("family = %q, want %q", report.Run.Provenance.Family, testCase.wantFamily)
			}
			if report.Run.Provenance.DNSSEC != testCase.dnssec {
				t.Fatalf("dnssec = %v, want %v", report.Run.Provenance.DNSSEC, testCase.dnssec)
			}
		})
	}
}
