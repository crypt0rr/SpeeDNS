//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// These tests write to real descriptors through their aliases. They need Unix
// descriptors, not Linux procfs, so they run on macOS as well; on macOS
// /dev/fd/N is not even a symlink.

// drainPipe reads a pipe or socket to its end in the background, so a writer
// never blocks on a full buffer.
func drainPipe(reader *os.File) <-chan string {
	received := make(chan string, 1)
	go func() {
		content, err := io.ReadAll(reader)
		if err != nil {
			received <- "read error: " + err.Error()
			return
		}
		received <- string(content)
	}()
	return received
}

// writeReportTo delivers report to an --output path the way a run does: the
// preflight first, then the writer and a commit.
func writeReportTo(t *testing.T, path, report string) {
	t.Helper()
	if err := preflightOutput(path); err != nil {
		t.Fatalf("preflight for %s: %v", path, err)
	}
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatalf("writer for %s: %v", path, err)
	}
	if _, err := io.WriteString(writer, report); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("finalize for %s: %v", path, err)
	}
}

// TestOutputWriterWritesThroughDevFDOfAPipe is the path `--output >(jq .)`
// hands the command. The report must arrive through the pipe, and the
// descriptor must still be open afterwards, because only the duplicate the
// writer made may be closed.
func TestOutputWriterWritesThroughDevFDOfAPipe(t *testing.T) {
	reader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer pipeWriter.Close()
	received := drainPipe(reader)

	writeReportTo(t, fmt.Sprintf("/dev/fd/%d", pipeWriter.Fd()), "piped report")
	if _, err := io.WriteString(pipeWriter, ", then more"); err != nil {
		t.Fatalf("the descriptor was closed behind its owner: %v", err)
	}
	if err := pipeWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "piped report, then more" {
		t.Fatalf("pipe received %q", got)
	}
}

// TestOutputWriterWritesAtTheDescriptorsOffset pins the redirection semantics
// an alias keeps now that it is written through the open file description. A
// file opened for appending, as `>> run.log` opens it, keeps what it held and
// gains the report after it; a file opened with truncation, as `> run.log`
// opens it, holds the report alone. Reopening the path instead truncated
// both. The descriptor stays open where the report ended, so a later write
// follows it.
func TestOutputWriterWritesAtTheDescriptorsOffset(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag int
		want string
	}{
		{name: "opened for appending", flag: os.O_WRONLY | os.O_APPEND, want: "previous run\nnew report"},
		{name: "opened with truncation", flag: os.O_WRONLY | os.O_TRUNC, want: "new report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			name := filepath.Join(directory, "run.log")
			if err := os.WriteFile(name, []byte("previous run\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(name, tc.flag, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}

			writeReportTo(t, fmt.Sprintf("/dev/fd/%d", file.Fd()), "new report")
			if content, err := os.ReadFile(name); err != nil || string(content) != tc.want {
				t.Fatalf("%s = %q/%v, want %q", name, content, err, tc.want)
			}
			if _, err := io.WriteString(file, "\n"); err != nil {
				t.Fatalf("the descriptor was closed behind its owner: %v", err)
			}
			if content, err := os.ReadFile(name); err != nil || string(content) != tc.want+"\n" {
				t.Fatalf("a later write did not follow the report: %q/%v", content, err)
			}
			after, err := os.Stat(name)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("the file was replaced: %v/%v", after, err)
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 {
				t.Fatalf("a temporary file was left behind: %v/%v", entries, err)
			}
		})
	}
}

// TestOutputWriterWritesToASocketDescriptor is the systemd journal case from
// #228 on a real socket. Under StandardOutput=journal standard output is a
// connected Unix socket, which no system can open by name, so the report has
// to go to the descriptor itself.
func TestOutputWriterWritesToASocketDescriptor(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("creating a socket pair is unavailable: %v", err)
	}
	local := os.NewFile(uintptr(pair[0]), "local")
	peer := os.NewFile(uintptr(pair[1]), "peer")
	defer local.Close()
	defer peer.Close()
	received := drainPipe(peer)

	writeReportTo(t, fmt.Sprintf("/dev/fd/%d", pair[0]), "socket report")
	if err := local.Close(); err != nil {
		t.Fatalf("the descriptor was closed behind its owner: %v", err)
	}
	if got := <-received; got != "socket report" {
		t.Fatalf("socket received %q", got)
	}
}

// TestOutputRefusesADirectoryDescriptor pins that a descriptor naming a
// directory is refused, before the run and after it, without anything being
// created inside the directory.
func TestOutputRefusesADirectoryDescriptor(t *testing.T) {
	directory := t.TempDir()
	handle, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	path := fmt.Sprintf("/dev/fd/%d", handle.Fd())
	if err := preflightOutput(path); err == nil || !strings.Contains(err.Error(), "output path is a directory") {
		t.Fatalf("directory descriptor preflight = %v", err)
	}
	if _, _, err := outputWriter(path); err == nil || !strings.Contains(err.Error(), "output path is a directory") {
		t.Fatalf("directory descriptor writer = %v", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("the directory gained entries: %v/%v", entries, err)
	}
}

// TestRunBenchmarkRefusesAClosedDescriptorBeforeMeasuring pins that an alias
// naming no open descriptor fails with EBADF and status 2 before the first
// query, like a missing directory, instead of after the whole run.
func TestRunBenchmarkRefusesAClosedDescriptorBeforeMeasuring(t *testing.T) {
	// Descriptor 2^30 is far above the default descriptor limits of Linux
	// and macOS, so it cannot be open; skip rather than guess if it is.
	const closed = 1 << 30
	var stat syscall.Stat_t
	if err := syscall.Fstat(closed, &stat); !errors.Is(err, syscall.EBADF) {
		t.Skipf("descriptor %d is not closed: %v", closed, err)
	}
	path := fmt.Sprintf("/dev/fd/%d", closed)
	engineCalls := countEngineCalls(t)
	if err := preflightOutput(path); !errors.Is(err, syscall.EBADF) || !strings.Contains(err.Error(), "inspect output path") {
		t.Fatalf("closed descriptor preflight = %v", err)
	}
	if _, _, err := outputWriter(path); !errors.Is(err, syscall.EBADF) || !strings.Contains(err.Error(), "inspect output path") {
		t.Fatalf("closed descriptor writer = %v", err)
	}
	config := cliConfigForTest(t)
	config.output = path
	err := runBenchmark(context.Background(), config)
	if !errors.Is(err, syscall.EBADF) || exitCodeForError(err) != 2 || *engineCalls != 0 {
		t.Fatalf("run = %v (exit %d) after %d engine call(s), want EBADF with status 2 and no run",
			err, exitCodeForError(err), *engineCalls)
	}
}

// TestRunBenchmarkAppendsThroughADescriptorAlias is `speedns --output
// /dev/stdout >> run.log` in a form every Unix system can run: the whole
// command must measure once and append its report to the log rather than
// overwrite what the log already held.
func TestRunBenchmarkAppendsThroughADescriptorAlias(t *testing.T) {
	engineCalls := countEngineCalls(t)
	name := filepath.Join(t.TempDir(), "run.log")
	if err := os.WriteFile(name, []byte("previous run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	config := cliConfigForTest(t)
	config.output = fmt.Sprintf("/dev/fd/%d", file.Fd())
	if err := runBenchmark(context.Background(), config); err != nil || *engineCalls != 1 {
		t.Fatalf("run = %v after %d engine call(s)", err, *engineCalls)
	}
	content, err := os.ReadFile(name)
	if err != nil || !strings.HasPrefix(string(content), "previous run\n{") || !strings.Contains(string(content), "\"results\"") {
		t.Fatalf("run.log = %q/%v, want the report after the previous run", content, err)
	}
}
