//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
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
