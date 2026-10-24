package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/benchmark"
	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// TestDefaultSeedStaysInTheGeneratorRange pins #252: the default seed was the
// nanosecond clock, about 1.8e18, which double-based JSON readers round, so a
// seed copied out of a report reran a different sample. math/rand reduces
// seeds modulo 2^31-1 anyway, so [1, 2^31-2] loses nothing.
func TestDefaultSeedStaysInTheGeneratorRange(t *testing.T) {
	for range 10000 {
		if seed := newSeedFunc(); seed < 1 || seed > 1<<31-2 {
			t.Fatalf("default seed %d is outside [1, 2^31-2]", seed)
		}
	}

	oldSeed, oldEngine := newSeedFunc, runBenchmarkEngine
	t.Cleanup(func() { newSeedFunc, runBenchmarkEngine = oldSeed, oldEngine })
	newSeedFunc = func() int64 { return 1<<31 - 2 }
	var used []int64
	runBenchmarkEngine = func(_ context.Context, _ []catalog.Target, options benchmark.Options) (benchmark.Report, error) {
		used = append(used, options.Seed)
		return fakeCLIReport(), nil
	}
	for _, pinned := range []int64{0, 42} {
		config := cliConfigForTest(t)
		config.seed = pinned
		config.output = filepath.Join(t.TempDir(), "report.json")
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatal(err)
		}
	}
	if len(used) != 2 || used[0] != 1<<31-2 || used[1] != 42 {
		t.Fatalf("seeds handed to the engine = %v, want the drawn default and then the pinned 42", used)
	}
}

// TestTimeoutMustBeWholeMilliseconds pins the other half of #252: provenance
// records timeout_ms as an integer and diff gates on it, so a timeout with a
// fractional millisecond is a usage error (exit 2) rather than a value the
// report silently truncates.
func TestTimeoutMustBeWholeMilliseconds(t *testing.T) {
	oldEngine := runBenchmarkEngine
	t.Cleanup(func() { runBenchmarkEngine = oldEngine })
	runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
		t.Fatal("an invalid timeout must be rejected before anything is measured")
		return benchmark.Report{}, nil
	}
	for _, value := range []string{"1000500us", "1.5ms", "500us", "1ms1ns"} {
		t.Run(value, func(t *testing.T) {
			root := newRootCommand()
			root.SetOut(&bytes.Buffer{})
			root.SetArgs([]string{"--no-defaults", "--resolver", "lab=udp://127.0.0.1:53", "--format", "json", "--timeout", value})
			err := root.Execute()
			if err == nil || exitCodeForError(err) != 2 {
				t.Fatalf("--timeout %s: error %v (exit %d), want a usage error with exit 2", value, err, exitCodeForError(err))
			}
			if want := "--timeout must be a whole number of milliseconds, got "; !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("--timeout %s: error %q, want it to start with %q", value, err, want)
			}
		})
	}
	for _, accepted := range []time.Duration{time.Millisecond, 750 * time.Millisecond, 1500 * time.Millisecond, 2 * time.Second} {
		runBenchmarkEngine = func(context.Context, []catalog.Target, benchmark.Options) (benchmark.Report, error) {
			return fakeCLIReport(), nil
		}
		config := cliConfigForTest(t)
		config.timeout = accepted
		config.output = filepath.Join(t.TempDir(), "report.json")
		if err := runBenchmark(context.Background(), config); err != nil {
			t.Fatalf("--timeout %s must be accepted: %v", accepted, err)
		}
	}
}
