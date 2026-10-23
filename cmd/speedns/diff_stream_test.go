//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/compare"
)

// TestDiffReadsReportsThroughPipes pins that capping the diff inputs did not
// turn them into regular-file-only paths. `speedns diff <(cat a.json) b.json`
// hands the command /dev/fd/N for a pipe, and /dev/stdin is the same kind of
// path, so a report arriving through a pipe must compare exactly like one read
// from disk. Descriptor paths are a Unix concept, hence the build tag.
func TestDiffReadsReportsThroughPipes(t *testing.T) {
	baseline := writeDiffFixture(t, "baseline.json", nil)
	document, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	written := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(document)
		if closeErr := writer.Close(); writeErr == nil {
			writeErr = closeErr
		}
		written <- writeErr
	}()

	var out bytes.Buffer
	if err := runDiff(&out, fmt.Sprintf("/dev/fd/%d", reader.Fd()), baseline, "table", "", nil); err != nil {
		t.Fatalf("diff through a pipe = %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("pipe producer: %v", err)
	}
	if !strings.Contains(out.String(), "WITHIN NOISE") {
		t.Fatalf("a piped copy of the baseline should compare as identical:\n%s", out.String())
	}
}

// endlessPipe returns a /dev/fd/N path for a pipe whose producer never stops
// writing. The producer ends once every read end is closed, which the test
// cleanup does.
func endlessPipe(t *testing.T) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer writer.Close()
		chunk := bytes.Repeat([]byte{'{'}, 64<<10)
		for {
			if _, err := writer.Write(chunk); err != nil {
				return
			}
		}
	}()
	path := fmt.Sprintf("/dev/fd/%d", reader.Fd())
	t.Cleanup(func() {
		_ = reader.Close()
		<-stopped
	})
	return path
}

// TestDiffRefusesAnOversizedStream is the command-level form of the diff input
// cap from #247. An endless stream, /dev/zero or a pipe from a producer that
// never stops, used to grow `speedns diff` until the runtime aborted. It must
// end in status 2 with an error that names the limit, and write nothing. The
// cap is lowered so the stream does not have to reach 256 MiB.
func TestDiffRefusesAnOversizedStream(t *testing.T) {
	oldLimit := compare.MaxReportBytes
	t.Cleanup(func() { compare.MaxReportBytes = oldLimit })
	compare.MaxReportBytes = 1 << 20
	baseline := writeDiffFixture(t, "baseline.json", nil)
	for _, tc := range []struct {
		name  string
		input func(*testing.T) string
	}{
		{name: "endless pipe", input: endlessPipe},
		{name: "/dev/zero", input: func(*testing.T) string { return "/dev/zero" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			output := filepath.Join(t.TempDir(), "diff.txt")
			err := runDiff(&out, baseline, tc.input(t), "table", output, nil)
			if err == nil || !strings.Contains(err.Error(), "is larger than the 1 MiB limit for a report") {
				t.Fatalf("diff of an oversized stream = %v, want the size limit error", err)
			}
			if code := exitCodeForError(err); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if out.Len() != 0 {
				t.Fatalf("a refused diff wrote %q", out.String())
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused diff created its --output: %v", err)
			}
		})
	}
}
