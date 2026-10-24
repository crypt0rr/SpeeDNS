package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/compare"
	"github.com/crypt0rr/SpeeDNS/internal/schematest"
	"github.com/crypt0rr/SpeeDNS/schema"
	"github.com/miekg/dns"
)

// writeDiffFixture writes a minimal comparable report and returns its path.
func writeDiffFixture(t *testing.T, name string, mutate func(map[string]any)) string {
	t.Helper()
	document := map[string]any{
		"schema_version": 1,
		"run": map[string]any{
			"started_at":         "2026-08-25T09:00:00Z",
			"seed":               7,
			"sample_size":        20,
			"queries_per_target": 40,
			"query_types":        []int{1, 28},
			"corpus_mode":        "warm-cache",
			"provenance": map[string]any{
				"speedns_version": "0.6.0", "commit": "abc12345",
				"os": "linux", "architecture": "amd64", "interfaces": []string{"eth0"},
				"corpus_entries": 1000, "corpus_sha256": "800d075a",
				"timeout_ms": 2000, "concurrency": 4,
				"family": "auto", "dnssec": false,
			},
		},
		"results": []any{map[string]any{
			"target": map[string]any{"id": "a@1.1.1.1/udp", "address": "1.1.1.1", "protocol": "udp"},
			"status": "qualified",
			"stats": map[string]any{
				"total": 40, "successes": 40, "usable_responses": 40, "answers": 20, "scored": 40,
				"rcode_counts": map[string]int{"NOERROR": 40},
			},
		}},
	}
	if mutate != nil {
		mutate(document)
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func resultStats(document map[string]any) map[string]any {
	results := document["results"].([]any)
	return results[0].(map[string]any)["stats"].(map[string]any)
}

// TestDiffCommandOutcomes covers the exit codes a caller scripts against.
func TestDiffCommandOutcomes(t *testing.T) {
	baseline := writeDiffFixture(t, "baseline.json", nil)

	t.Run("identical runs are silent and exit zero", func(t *testing.T) {
		var out bytes.Buffer
		if err := runDiff(&out, baseline, writeDiffFixture(t, "same.json", nil), "table", "", nil); err != nil {
			t.Fatalf("identical runs = %v", err)
		}
		if !strings.Contains(out.String(), "WITHIN NOISE") {
			t.Fatalf("identical runs should report within noise:\n%s", out.String())
		}
	})

	t.Run("a differing run parameter refuses", func(t *testing.T) {
		other := writeDiffFixture(t, "seed.json", func(d map[string]any) {
			d["run"].(map[string]any)["seed"] = 99
		})
		var out bytes.Buffer
		err := runDiff(&out, baseline, other, "table", "", nil)
		if err == nil || !strings.Contains(err.Error(), "not comparable") {
			t.Fatalf("differing seed = %v", err)
		}
		if exitCodeForError(err) != 3 {
			t.Fatalf("a refusal must exit 3, got %d", exitCodeForError(err))
		}
		if !strings.Contains(out.String(), "RUNS NOT COMPARABLE") {
			t.Fatalf("refusal screen missing:\n%s", out.String())
		}
	})

	t.Run("a behaviour change is reported", func(t *testing.T) {
		other := writeDiffFixture(t, "dark.json", func(d map[string]any) {
			stats := resultStats(d)
			stats["successes"] = 0
			stats["usable_responses"] = 0
		})
		var out bytes.Buffer
		if err := runDiff(&out, baseline, other, "table", "", nil); err != nil {
			t.Fatalf("a behaviour change should still exit 0: %v", err)
		}
		if !strings.Contains(out.String(), "FAILED") {
			t.Fatalf("expected a FAILED finding:\n%s", out.String())
		}
	})

	t.Run("require fails with status four", func(t *testing.T) {
		other := writeDiffFixture(t, "dark2.json", func(d map[string]any) {
			resultStats(d)["successes"] = 0
		})
		err := runDiff(&bytes.Buffer{}, baseline, other, "table", "", []string{"no-new-failed-targets"})
		if err == nil || exitCodeForError(err) != 4 {
			t.Fatalf("a failed condition must exit 4, got %v (%d)", err, exitCodeForError(err))
		}
	})

	t.Run("require never reports a pass on a refusal", func(t *testing.T) {
		other := writeDiffFixture(t, "seed2.json", func(d map[string]any) {
			d["run"].(map[string]any)["seed"] = 99
		})
		err := runDiff(&bytes.Buffer{}, baseline, other, "table", "", []string{"no-behaviour-change"})
		if exitCodeForError(err) != 3 {
			t.Fatalf("a gate that cannot evaluate must exit 3, got %d", exitCodeForError(err))
		}
	})

	t.Run("an unknown condition is a usage error", func(t *testing.T) {
		err := runDiff(&bytes.Buffer{}, baseline, writeDiffFixture(t, "x.json", nil), "table", "", []string{"nope"})
		if err == nil || exitCodeForError(err) != 2 {
			t.Fatalf("unknown condition = %v (%d)", err, exitCodeForError(err))
		}
	})

	t.Run("an unsupported format is a usage error", func(t *testing.T) {
		err := runDiff(&bytes.Buffer{}, baseline, baseline, "csv", "", nil)
		if err == nil || !strings.Contains(err.Error(), "unsupported output format") {
			t.Fatalf("csv format = %v", err)
		}
	})

	// run accepts --format JSON, so diff must too: the same spelling asked
	// for the same document and was refused on one command only.
	t.Run("the format is case-insensitive", func(t *testing.T) {
		var document bytes.Buffer
		if err := runDiff(&document, baseline, baseline, "JSON", "", nil); err != nil {
			t.Fatalf("--format JSON = %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(document.Bytes(), &decoded); err != nil || decoded["comparable"] != true {
			t.Fatalf("--format JSON did not write the JSON diff (%v): %s", err, document.String())
		}
		var table bytes.Buffer
		if err := runDiff(&table, baseline, baseline, "Table", "", nil); err != nil || !strings.Contains(table.String(), "COMPARABLE") {
			t.Fatalf("--format Table = %v:\n%s", err, table.String())
		}
		if err := runDiff(&bytes.Buffer{}, baseline, baseline, "CSV", "", nil); err == nil ||
			!strings.Contains(err.Error(), `unsupported output format "CSV"`) {
			t.Fatalf("--format CSV = %v, want the typed value echoed", err)
		}
	})

	t.Run("an unreadable input is an error", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.json")
		if err := runDiff(&bytes.Buffer{}, missing, baseline, "table", "", nil); err == nil {
			t.Fatal("a missing baseline must fail")
		}
		if err := runDiff(&bytes.Buffer{}, baseline, missing, "table", "", nil); err == nil {
			t.Fatal("a missing current report must fail")
		}
	})

	t.Run("json goes to a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "diff.json")
		if err := runDiff(&bytes.Buffer{}, baseline, writeDiffFixture(t, "y.json", nil), "json", path, nil); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(content, &document); err != nil {
			t.Fatal(err)
		}
		if document["comparable"] != true {
			t.Fatalf("identical runs should be comparable: %s", content)
		}
	})
}

// TestDiffCommandIsWired covers the cobra surface itself.
func TestDiffCommandIsWired(t *testing.T) {
	command := newDiffCommand()
	if command.Use == "" || command.Short == "" || command.Long == "" {
		t.Fatal("the diff command is missing its help text")
	}
	if !strings.Contains(command.Long, "never compares latency") {
		t.Fatal("the help must state the claim boundary")
	}
	if err := command.Args(command, []string{"one.json"}); err == nil {
		t.Fatal("one argument must be rejected")
	}
	if err := command.Args(command, []string{"a.json", "b.json", "c.json"}); err == nil {
		t.Fatal("three arguments must be rejected")
	}
	if err := command.Args(command, []string{"a.json", "b.json"}); err != nil {
		t.Fatalf("two arguments must be accepted: %v", err)
	}
	baseline := writeDiffFixture(t, "cobra.json", nil)
	command.SetArgs([]string{baseline, baseline})
	var out bytes.Buffer
	command.SetOut(&out)
	if err := command.Execute(); err != nil {
		t.Fatalf("executing the command = %v", err)
	}
	if !strings.Contains(out.String(), "COMPARABLE") {
		t.Fatalf("command output:\n%s", out.String())
	}
}

// TestDiffOutputFileFailures covers the paths where the destination itself is
// the problem, so a failed write is reported rather than silently losing the
// diff.
func TestDiffOutputFileFailures(t *testing.T) {
	baseline := writeDiffFixture(t, "base.json", nil)

	t.Run("an unusable destination is an error", func(t *testing.T) {
		// A directory is never a valid output file.
		if err := runDiff(&bytes.Buffer{}, baseline, baseline, "table", t.TempDir(), nil); err == nil {
			t.Fatal("writing to a directory must fail")
		}
	})

	t.Run("a failing writer is reported", func(t *testing.T) {
		oldWriter := outputWriterFunc
		t.Cleanup(func() { outputWriterFunc = oldWriter })
		outputWriterFunc = func(string) (io.Writer, outputFinalizer, error) {
			return failingDiffWriter{}, outputFinalizer(func(bool) error { return nil }), nil
		}
		if err := runDiff(&bytes.Buffer{}, baseline, baseline, "table", "somewhere.txt", nil); err == nil {
			t.Fatal("a failing writer must be reported")
		}
	})

	t.Run("a failing finalize is reported", func(t *testing.T) {
		oldWriter := outputWriterFunc
		t.Cleanup(func() { outputWriterFunc = oldWriter })
		outputWriterFunc = func(string) (io.Writer, outputFinalizer, error) {
			return &bytes.Buffer{}, outputFinalizer(func(bool) error { return errors.New("rename failed") }), nil
		}
		if err := runDiff(&bytes.Buffer{}, baseline, baseline, "table", "somewhere.txt", nil); err == nil {
			t.Fatal("a failing finalize must be reported")
		}
	})
}

type failingDiffWriter struct{}

func (failingDiffWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// diffTarget is one results[] entry for writeDiffFixture: a healthy UDP target
// unless a change says otherwise.
func diffTarget(id string, changes ...func(result, stats map[string]any)) any {
	stats := map[string]any{
		"total": 40, "successes": 40, "usable_responses": 40, "answers": 20, "scored": 40,
		"rcode_counts": map[string]int{"NOERROR": 40},
	}
	result := map[string]any{
		"target": map[string]any{"id": id, "address": "192.0.2.1", "protocol": "udp"},
		"status": "qualified",
		"stats":  stats,
	}
	for _, change := range changes {
		change(result, stats)
	}
	return result
}

func deadDiffTarget(_, stats map[string]any) {
	stats["successes"], stats["usable_responses"], stats["answers"], stats["scored"] = 0, 0, 0, 0
	stats["rcode_counts"] = map[string]int{}
}

func incompleteDiffTarget(result, _ map[string]any) { result["incomplete"] = true }

func localDiffTarget(result, _ map[string]any) { result["target"].(map[string]any)["local"] = true }

// TestDiffRequireFailsClosed pins #230 end to end through the exit status, the
// only signal a CI gate reads: a gate that compared nothing exits 3 rather
// than passing, a recovery is not a new failure, and every failed condition is
// named in the order the flags gave them.
func TestDiffRequireFailsClosed(t *testing.T) {
	reportWith := func(name string, results ...any) string {
		return writeDiffFixture(t, name, func(d map[string]any) { d["results"] = results })
	}
	for _, testCase := range []struct {
		name              string
		baseline, current []any
		required          []string
		exit              int
		// message is the exact error text; empty when the exit is 0.
		message string
	}{
		{
			name:     "every current target incomplete",
			baseline: []any{diffTarget("a@1.1.1.1/udp"), diffTarget("b@9.9.9.9/udp")},
			current: []any{
				diffTarget("a@1.1.1.1/udp", incompleteDiffTarget, deadDiffTarget),
				diffTarget("b@9.9.9.9/udp", incompleteDiffTarget),
			},
			required: []string{"no-new-failed-targets"},
			exit:     3,
			message:  "nothing compared: no --require condition can pass (2 incomplete-target)",
		},
		{
			name:     "incomplete baseline",
			baseline: []any{diffTarget("a@1.1.1.1/udp", incompleteDiffTarget)},
			current:  []any{diffTarget("a@1.1.1.1/udp")},
			required: []string{"no-behaviour-change"},
			exit:     3,
			message:  "nothing compared: no --require condition can pass (1 incomplete-target)",
		},
		{
			name:     "every target local or redacted",
			baseline: []any{diffTarget("stub@127.0.0.1/udp", localDiffTarget), diffTarget("system-redacted-1")},
			current:  []any{diffTarget("stub@127.0.0.1/udp", localDiffTarget), diffTarget("system-redacted-1", deadDiffTarget)},
			required: []string{"no-new-failed-targets", "target-set-identical"},
			exit:     3,
			message:  "nothing compared: no --require condition can pass (1 local-position, 1 redacted-identity)",
		},
		{
			// Disjoint target sets compare nothing; a condition that passes
			// over them still read nothing, and the summary says why.
			name:     "only unpaired targets",
			baseline: []any{diffTarget("a@1.1.1.1/udp")},
			current:  []any{diffTarget("b@9.9.9.9/udp")},
			required: []string{"no-new-failed-targets"},
			exit:     3,
			message:  "nothing compared: no --require condition can pass (2 present in only one run)",
		},
		{
			name:     "neither run has a target",
			required: []string{"no-behaviour-change"},
			exit:     3,
			message:  "nothing compared: no --require condition can pass (neither run has a target)",
		},
		{
			// A PRESENCE failure needs no pairing, so it is a real failure
			// and keeps status 4 even though nothing was compared.
			name:     "a presence failure stands without a comparison",
			baseline: []any{diffTarget("a@1.1.1.1/udp")},
			current:  []any{diffTarget("b@9.9.9.9/udp")},
			required: []string{"no-new-failed-targets", "no-removed-targets"},
			exit:     4,
			message:  "assertion failed: --require no-removed-targets: a@1.1.1.1/udp is absent from the current run",
		},
		{
			// Without --require the diff is a report, not a gate.
			name:     "no gate, no refusal",
			baseline: []any{diffTarget("a@1.1.1.1/udp", incompleteDiffTarget)},
			current:  []any{diffTarget("a@1.1.1.1/udp")},
		},
		{
			name:     "recovery",
			baseline: []any{diffTarget("a@1.1.1.1/udp", deadDiffTarget)},
			current:  []any{diffTarget("a@1.1.1.1/udp")},
			required: []string{"no-new-failed-targets"},
		},
		{
			name: "open error cleared",
			baseline: []any{diffTarget("a@1.1.1.1/udp", deadDiffTarget, func(result, _ map[string]any) {
				result["open_error"] = "dial udp: i/o timeout"
			})},
			current:  []any{diffTarget("a@1.1.1.1/udp")},
			required: []string{"no-new-failed-targets"},
		},
		{
			name:     "healthy to dead",
			baseline: []any{diffTarget("a@1.1.1.1/udp")},
			current:  []any{diffTarget("a@1.1.1.1/udp", deadDiffTarget)},
			required: []string{"no-new-failed-targets"},
			exit:     4,
			message:  "assertion failed: --require no-new-failed-targets: a@1.1.1.1/udp: successes 40 -> 0",
		},
		{
			name:     "new dead target only in the current run",
			baseline: []any{diffTarget("a@1.1.1.1/udp")},
			current:  []any{diffTarget("a@1.1.1.1/udp"), diffTarget("b@9.9.9.9/udp", deadDiffTarget)},
			required: []string{"no-new-failed-targets"},
			exit:     4,
			message:  "assertion failed: --require no-new-failed-targets: b@9.9.9.9/udp: only in the current run, with successes 0 of 40",
		},
		{
			name:     "two failing conditions in flag order",
			baseline: []any{diffTarget("a@1.1.1.1/udp"), diffTarget("b@9.9.9.9/udp")},
			current:  []any{diffTarget("a@1.1.1.1/udp", deadDiffTarget)},
			required: []string{"no-removed-targets", "no-dnssec-regression", "no-new-failed-targets"},
			exit:     4,
			message: "assertion failed: --require no-removed-targets: b@9.9.9.9/udp is absent from the current run; " +
				"--require no-new-failed-targets: a@1.1.1.1/udp: successes 40 -> 0",
		},
		{
			name:     "two failing conditions in the other order",
			baseline: []any{diffTarget("a@1.1.1.1/udp"), diffTarget("b@9.9.9.9/udp")},
			current:  []any{diffTarget("a@1.1.1.1/udp", deadDiffTarget)},
			required: []string{"no-new-failed-targets", "no-removed-targets"},
			exit:     4,
			message: "assertion failed: --require no-new-failed-targets: a@1.1.1.1/udp: successes 40 -> 0; " +
				"--require no-removed-targets: b@9.9.9.9/udp is absent from the current run",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runDiff(&out, reportWith("baseline.json", testCase.baseline...),
				reportWith("current.json", testCase.current...), "table", "", testCase.required)
			if got := exitCodeForError(err); got != testCase.exit {
				t.Fatalf("exit = %d, want %d (error %v)", got, testCase.exit, err)
			}
			if testCase.exit == 0 {
				return
			}
			if err.Error() != testCase.message {
				t.Fatalf("error = %q\nwant    %q", err, testCase.message)
			}
			if testCase.exit == 3 && !errors.Is(err, compare.ErrNothingCompared) {
				t.Fatalf("a gate with nothing compared must be ErrNothingCompared: %v", err)
			}
			// The diff is written before any verdict, so the reader can see
			// what was and was not compared.
			if !strings.Contains(out.String(), "endpoint(s) compared.") {
				t.Fatalf("the diff must be written before the gate's verdict:\n%s", out.String())
			}
		})
	}

	// A refused diff produces no findings, so no condition can fail on it; what
	// this pins is that the refusal outranks the nothing-compared gate it would
	// otherwise also trip. Refusal over failing conditions follows from runDiff
	// checking comparability first.
	t.Run("a refusal outranks the nothing-compared gate", func(t *testing.T) {
		baseline := reportWith("baseline.json", diffTarget("a@1.1.1.1/udp"))
		current := writeDiffFixture(t, "refused.json", func(d map[string]any) {
			d["run"].(map[string]any)["seed"] = 99
			d["results"] = []any{diffTarget("b@9.9.9.9/udp", deadDiffTarget, incompleteDiffTarget)}
		})
		err := runDiff(&bytes.Buffer{}, baseline, current, "table", "",
			[]string{"no-new-failed-targets", "target-set-identical", "no-removed-targets"})
		if !errors.Is(err, compare.ErrRunsNotComparable) || errors.Is(err, ErrAssertionsFailed) || exitCodeForError(err) != 3 {
			t.Fatalf("a refused diff must exit 3 as not comparable, got %v (%d)", err, exitCodeForError(err))
		}
	})
}

// TestDiffRequireFailureEscapesReportText covers what `speedns diff` prints
// when a --require condition fails: the diff table on stdout and the failure
// on stderr. Both quote a target ID and an open error read from the report
// files, which a crafted or hostile report can fill with control and
// bidirectional characters.
func TestDiffRequireFailureEscapesReportText(t *testing.T) {
	const hostileID = "evil\x1b[2K\u202e@1.1.1.1/udp"
	hostile := func(document map[string]any) {
		results := document["results"].([]any)
		results[0].(map[string]any)["target"].(map[string]any)["id"] = hostileID
	}
	baseline := writeDiffFixture(t, "baseline.json", hostile)
	current := writeDiffFixture(t, "current.json", func(document map[string]any) {
		hostile(document)
		results := document["results"].([]any)
		results[0].(map[string]any)["open_error"] = "DoH HTTP status 418 \x1b[2J\x1b[H\u200bteapot"
	})
	var out bytes.Buffer
	err := runDiff(&out, baseline, current, "table", "", []string{"no-new-failed-targets"})
	if exitCodeForError(err) != 4 {
		t.Fatalf("a failed condition must exit 4, got %v (%d)", err, exitCodeForError(err))
	}
	for label, text := range map[string]string{"stdout": out.String(), "stderr": errorMessage(err)} {
		for _, value := range text {
			if (unicode.IsControl(value) && value != '\n') || unicode.Is(unicode.Cf, value) {
				t.Fatalf("%s kept a raw U+%04X: %q", label, value, text)
			}
		}
	}
	want := `--require no-new-failed-targets: evil\x1b[2K\u{202e}@1.1.1.1/udp: opened -> DoH HTTP status 418 \x1b[2J\x1b[H\u{200b}teapot`
	if !strings.Contains(errorMessage(err), want) {
		t.Fatalf("stderr = %q, want it to contain %q", errorMessage(err), want)
	}
}

// startLoopbackResolver answers every question with an empty NOERROR reply on
// 127.0.0.1 over network, "udp" or "tcp", and returns the address it serves.
func startLoopbackResolver(t *testing.T, network string) string {
	t.Helper()
	started := make(chan struct{})
	server := &dns.Server{NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		_ = writer.WriteMsg(reply)
	})}
	var address string
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn, address = conn, conn.LocalAddr().String()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener, address = listener, listener.Addr().String()
	}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return address
}

// TestInterruptedRunDiffsAsTheSameTargetSet runs the real engine twice against
// loopback resolvers, once to completion and once interrupted as soon as the
// UDP group finishes, so the TCP group never starts. An interrupted report used
// to omit every target of a group that had not started, and diffing it against
// the full baseline reported each of them as removed: --require
// no-removed-targets and target-set-identical failed on an interrupt rather
// than on a change in what was measured. The interrupted report now lists the
// TCP target as incomplete, which the diff declines to compare and does not
// call a removal.
func TestInterruptedRunDiffsAsTheSameTargetSet(t *testing.T) {
	udp, tcp := startLoopbackResolver(t, "udp"), startLoopbackResolver(t, "tcp")
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	interrupt := false
	runBenchmarkEngine = func(ctx context.Context, targets []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		// A loopback resolver is never ranked or paired by diff, which would
		// decline both targets before the target sets were ever compared. The
		// fixture stands in for two network resolvers, so it is measured as one.
		for index := range targets {
			targets[index].Resolver.Local = false
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		options.OnProgress = func(progress benchmark.Progress) {
			if interrupt && progress.Protocol == catalog.UDP && progress.Phase == benchmark.ProgressComplete {
				cancel()
			}
		}
		return benchmark.Run(ctx, targets, options)
	}
	run := func(name string) string {
		config := cliConfigForTest(t)
		config.protocols = "udp,tcp"
		config.resolverFlags = []string{"lab-udp=udp://" + udp, "lab-tcp=tcp://" + tcp}
		config.sample = 2
		config.output = filepath.Join(t.TempDir(), name)
		err := runBenchmark(context.Background(), config)
		if interrupt != errors.Is(err, context.Canceled) || (!interrupt && err != nil) {
			t.Fatalf("%s run returned %v (interrupted: %v)", name, err, interrupt)
		}
		return config.output
	}
	baseline := run("baseline.json")
	interrupt = true
	current := run("interrupted.json")

	var out bytes.Buffer
	if err := runDiff(&out, baseline, current, "json", "", []string{"no-removed-targets", "target-set-identical"}); err != nil {
		t.Fatalf("diff of an interrupted run against its full baseline failed: %v\n%s", err, out.String())
	}
	var document struct {
		Findings    []compare.Finding     `json:"findings"`
		NotCompared []compare.Suppression `json:"not_compared"`
		Compared    int                   `json:"compared"`
	}
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	for _, finding := range document.Findings {
		if finding.Code == "PRESENCE" {
			t.Fatalf("interrupt reported as a change in the target set: %#v", document.Findings)
		}
	}
	if document.Compared != 1 || len(document.NotCompared) != 1 || document.NotCompared[0].Reason != "incomplete-target" ||
		!strings.HasSuffix(document.NotCompared[0].Scope, "/tcp") {
		t.Fatalf("diff compared %d and declined %#v, want the finished UDP target compared and the TCP target declined as incomplete", document.Compared, document.NotCompared)
	}
	loaded, err := compare.Load(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Results) != 2 {
		t.Fatalf("interrupted report lists %d targets, want both selected targets: %#v", len(loaded.Results), loaded.Results)
	}
}

// TestDiffJSONRecordsTheGate pins R-005(d): with --require, the compare JSON
// carries each condition's verdict -- the same one the exit status is read
// from -- so an archived diff says which gate ran and how it ended. A gate
// that could not evaluate records not-evaluated and never passed, and a diff
// without --require has no conditions at all.
func TestDiffJSONRecordsTheGate(t *testing.T) {
	reportWith := func(name string, results ...any) string {
		return writeDiffFixture(t, name, func(d map[string]any) { d["results"] = results })
	}
	type condition struct {
		Name    string `json:"name"`
		Passed  bool   `json:"passed"`
		Outcome string `json:"outcome"`
		Detail  string `json:"detail"`
	}
	for _, testCase := range []struct {
		name              string
		baseline, current string
		required          []string
		exit              int
		want              []condition
	}{
		{
			name:     "two failures and a pass, in flag order",
			baseline: reportWith("baseline.json", diffTarget("a@1.1.1.1/udp"), diffTarget("b@9.9.9.9/udp")),
			current:  reportWith("current.json", diffTarget("a@1.1.1.1/udp", deadDiffTarget)),
			required: []string{"no-removed-targets", "no-dnssec-regression", "no-new-failed-targets"},
			exit:     4,
			want: []condition{
				{Name: "no-removed-targets", Outcome: "failed", Detail: "b@9.9.9.9/udp is absent from the current run"},
				{Name: "no-dnssec-regression", Passed: true, Outcome: "passed", Detail: "no target stopped validating"},
				{Name: "no-new-failed-targets", Outcome: "failed", Detail: "a@1.1.1.1/udp: successes 40 -> 0"},
			},
		},
		{
			name:     "nothing compared",
			baseline: reportWith("baseline.json", diffTarget("a@1.1.1.1/udp")),
			current:  reportWith("current.json", diffTarget("a@1.1.1.1/udp", incompleteDiffTarget)),
			required: []string{"no-behaviour-change"},
			exit:     3,
			want: []condition{
				{Name: "no-behaviour-change", Outcome: "not-evaluated", Detail: "not evaluated: no endpoint was compared (1 incomplete-target)"},
			},
		},
		{
			name:     "refused",
			baseline: reportWith("baseline.json", diffTarget("a@1.1.1.1/udp")),
			current: writeDiffFixture(t, "refused.json", func(d map[string]any) {
				d["run"].(map[string]any)["seed"] = 99
			}),
			required: []string{"target-set-identical"},
			exit:     3,
			want: []condition{
				{Name: "target-set-identical", Outcome: "not-evaluated", Detail: "not evaluated: the runs are not comparable"},
			},
		},
		{
			name:     "no gate",
			baseline: reportWith("baseline.json", diffTarget("a@1.1.1.1/udp")),
			current:  reportWith("current.json", diffTarget("a@1.1.1.1/udp", deadDiffTarget)),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runDiff(&out, testCase.baseline, testCase.current, "json", "", testCase.required)
			if got := exitCodeForError(err); got != testCase.exit {
				t.Fatalf("exit = %d, want %d (error %v)", got, testCase.exit, err)
			}
			if err := schematest.Validate(schema.CompareV1(), out.Bytes()); err != nil {
				t.Fatalf("diff JSON does not match compare-v1: %v\n%s", err, out.String())
			}
			var document struct {
				Conditions []condition `json:"conditions"`
			}
			if err := json.Unmarshal(out.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(document.Conditions, testCase.want) {
				t.Fatalf("conditions = %#v\nwant %#v", document.Conditions, testCase.want)
			}
			if testCase.want == nil && strings.Contains(out.String(), `"conditions"`) {
				t.Fatalf("a diff without --require must not carry conditions:\n%s", out.String())
			}
		})
	}
}
