//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// makeFIFOSymlink creates a named pipe and a symlink to it in a fresh
// directory, returning the link and the pipe.
func makeFIFOSymlink(t *testing.T) (link, fifo string) {
	t.Helper()
	directory := t.TempDir()
	fifo = filepath.Join(directory, "report.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}
	link = filepath.Join(directory, "report.json")
	if err := os.Symlink(filepath.Base(fifo), link); err != nil {
		t.Fatalf("create fifo symlink: %v", err)
	}
	return link, fifo
}

// readFIFOInBackground starts the reader a named pipe needs before a writer
// can open it, and returns what it read.
func readFIFOInBackground(path string) <-chan string {
	received := make(chan string, 1)
	go func() {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			received <- "read error: " + readErr.Error()
			return
		}
		received <- string(content)
	}()
	return received
}

// assertFIFOSymlinkIntact checks that writing through the link replaced
// neither the link nor the pipe it names.
func assertFIFOSymlinkIntact(t *testing.T, link, fifo string) {
	t.Helper()
	linkInfo, err := os.Lstat(link)
	if err != nil || linkInfo.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v/%v", linkInfo, err)
	}
	if target, err := os.Readlink(link); err != nil || target != filepath.Base(fifo) {
		t.Fatalf("symlink target = %q/%v", target, err)
	}
	fifoInfo, err := os.Lstat(fifo)
	if err != nil || fifoInfo.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the fifo was replaced: %v/%v", fifoInfo, err)
	}
}

// TestOutputWriterWritesThroughASymlinkToAFIFO pins that a user symlink is
// refused only where the atomic rename could replace it. A link to a named
// pipe, terminal or other character device can only deliver bytes to what it
// names, so it is written through in place, as a shell redirection through it
// would be.
func TestOutputWriterWritesThroughASymlinkToAFIFO(t *testing.T) {
	link, fifo := makeFIFOSymlink(t)

	// The preflight runs before anyone reads the pipe, so it must decide
	// without opening it: an open for writing would block right here.
	preflight := make(chan error, 1)
	go func() { preflight <- preflightOutput(link) }()
	select {
	case err := <-preflight:
		if err != nil {
			t.Fatalf("fifo symlink preflight = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the preflight blocked opening the named pipe")
	}

	received := readFIFOInBackground(link)
	writer, finalize, err := outputWriter(link)
	if err != nil {
		t.Fatalf("fifo symlink writer = %v", err)
	}
	if _, err := io.WriteString(writer, "piped report"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("fifo symlink finalize = %v", err)
	}
	if got := <-received; got != "piped report" {
		t.Fatalf("fifo reader got %q", got)
	}
	assertFIFOSymlinkIntact(t, link, fifo)
}

// TestRunBenchmarkStreamsThroughASymlinkToAFIFO runs the whole command against
// a symlinked pipe: the preflight accepts it without opening it, the benchmark
// runs once, and the report arrives through the pipe.
func TestRunBenchmarkStreamsThroughASymlinkToAFIFO(t *testing.T) {
	engineCalls := countEngineCalls(t)
	link, fifo := makeFIFOSymlink(t)
	received := readFIFOInBackground(fifo)
	config := cliConfigForTest(t)
	config.output = link
	if err := runBenchmark(context.Background(), config); err != nil || *engineCalls != 1 {
		t.Fatalf("run through a fifo symlink = %v after %d engine call(s)", err, *engineCalls)
	}
	if got := <-received; !strings.Contains(got, "\"results\"") {
		t.Fatalf("fifo reader got %q", got)
	}
	assertFIFOSymlinkIntact(t, link, fifo)
}

// TestProbeOutputWritableDoesNotBlockOnAFIFO pins that the permission probe
// cannot hang the preflight. It only ever means to open a regular file, but
// if the path is swapped for a named pipe between the inspection and the
// open, an ordinary open for writing would wait for a reader that never comes
// before the benchmark has even started.
func TestProbeOutputWritableDoesNotBlockOnAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}
	probed := make(chan error, 1)
	go func() { probed <- probeOutputWritable(fifo) }()
	select {
	case err := <-probed:
		if !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("probe of a fifo without a reader = %v, want ENXIO", err)
		}
	case <-time.After(5 * time.Second):
		// Release the blocked open before failing, so the goroutine ends.
		if reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			defer reader.Close()
		}
		t.Fatal("the writability probe blocked opening a named pipe")
	}
}

// TestRunBenchmarkRefusesABoundSocketBeforeMeasuring is the end-to-end form of
// TestOutputRefusesSocketsBeforeTheRun. A bound Unix socket, named directly or
// through a symlink, cannot be opened as a file, so it must be refused before
// the first query instead of after the whole run.
func TestRunBenchmarkRefusesABoundSocketBeforeMeasuring(t *testing.T) {
	// A socket path must fit in sun_path, 104 bytes on macOS, which a
	// t.TempDir path named after this test can exceed.
	directory, err := os.MkdirTemp("", "speedns-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("binding a Unix socket is unavailable: %v", err)
	}
	defer listener.Close()
	link := filepath.Join(directory, "report.json")
	if err := os.Symlink(filepath.Base(socket), link); err != nil {
		t.Fatalf("create socket symlink: %v", err)
	}

	engineCalls := countEngineCalls(t)
	for _, tc := range []struct{ path, wants string }{
		{path: link, wants: "output path is a symlink"},
		{path: socket, wants: "output path is a socket"},
	} {
		config := cliConfigForTest(t)
		config.output = tc.path
		err := runBenchmark(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), tc.wants) || exitCodeForError(err) != 2 {
			t.Fatalf("run to %s = %v, want %q with status 2", tc.path, err, tc.wants)
		}
	}
	if *engineCalls != 0 {
		t.Fatalf("the benchmark ran %d time(s) for a socket destination", *engineCalls)
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode()&fs.ModeSocket == 0 {
		t.Fatalf("the socket was replaced: %v/%v", info, err)
	}
	if target, err := os.Readlink(link); err != nil || target != filepath.Base(socket) {
		t.Fatalf("socket symlink target = %q/%v", target, err)
	}
}

// TestOutputWriterWritesThroughDevFDOfAPipe exercises a real descriptor alias
// on every Unix system, macOS included, where /dev/fd/N is not a symlink at
// all. It is the path `--output >(jq .)` hands the command, so the report must
// arrive through the pipe and nothing may be created beside it.
func TestOutputWriterWritesThroughDevFDOfAPipe(t *testing.T) {
	reader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer pipeWriter.Close()
	received := make(chan string, 1)
	go func() {
		content, readErr := io.ReadAll(reader)
		if readErr != nil {
			received <- "read error: " + readErr.Error()
			return
		}
		received <- string(content)
	}()

	path := fmt.Sprintf("/dev/fd/%d", pipeWriter.Fd())
	if err := preflightOutput(path); err != nil {
		t.Fatalf("preflight for %s: %v", path, err)
	}
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatalf("writer for %s: %v", path, err)
	}
	if _, err := io.WriteString(writer, "piped report"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("finalize for %s: %v", path, err)
	}
	if err := pipeWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "piped report" {
		t.Fatalf("pipe received %q", got)
	}
}
