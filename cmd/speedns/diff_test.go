package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
