//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestOutputWriterStreamsToAFIFO pins the reason outputWriter special-cases
// non-regular destinations at all: `speedns --output /path/to/fifo` with a
// reader on the other end must deliver the report through the pipe, not
// replace the pipe with a regular file via the write-temp-then-rename path
// that protects regular files. FIFOs are a Unix concept, so this lives apart
// from the rest of the writer tests to keep the package vetting on Windows.
func TestOutputWriterStreamsToAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}
	received := make(chan string, 1)
	go func() {
		content, readErr := os.ReadFile(fifo)
		if readErr != nil {
			received <- "read error: " + readErr.Error()
			return
		}
		received <- string(content)
	}()

	writer, finalize, err := outputWriter(fifo)
	if err != nil {
		t.Fatalf("fifo writer = %v", err)
	}
	if _, err := io.WriteString(writer, "piped report"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("fifo finalize = %v", err)
	}
	if got := <-received; got != "piped report" {
		t.Fatalf("fifo reader got %q", got)
	}

	info, err := os.Stat(fifo)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the fifo was replaced by a regular file: %v/%v", info, err)
	}
}
