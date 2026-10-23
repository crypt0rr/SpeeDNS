//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// redirectDescriptor points descriptor fd at target and returns a function
// that restores the original early. The test cleanup restores it as well, so
// a failing test never leaves the runner writing into a test pipe. Dup3 is
// used because linux/arm64 has no dup2 system call.
func redirectDescriptor(t *testing.T, fd int, target *os.File) func() {
	t.Helper()
	saved, err := syscall.Dup(fd)
	if err != nil {
		t.Fatalf("save descriptor %d: %v", fd, err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := syscall.Dup3(saved, fd, 0); err != nil {
			t.Errorf("restore descriptor %d: %v", fd, err)
		}
		if err := syscall.Close(saved); err != nil {
			t.Errorf("close saved descriptor %d: %v", fd, err)
		}
	}
	t.Cleanup(restore)
	if err := syscall.Dup3(int(target.Fd()), fd, 0); err != nil {
		t.Fatalf("redirect descriptor %d: %v", fd, err)
	}
	return restore
}

func TestOutputWriterWritesProcFD1PipeInPlace(t *testing.T) {
	reader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer pipeWriter.Close()
	restoreStdout := redirectDescriptor(t, 1, pipeWriter)

	const path = "/proc/self/fd/1"
	assertProcFDLink(t, path)
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatalf("proc fd writer: %v", err)
	}
	if _, err := io.WriteString(writer, "report through stdout pipe"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("proc fd finalize: %v", err)
	}
	assertProcFDLink(t, path)

	restoreStdout()
	if err := pipeWriter.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	if err != nil || string(content) != "report through stdout pipe" {
		t.Fatalf("pipe received %q/%v", content, err)
	}
}

// TestOutputWriterWritesDescriptorAliasesInPlace pins #228. /dev/stdout,
// /dev/stderr and /dev/fd/N are symlinks into /proc/self/fd on Linux, and they
// were refused as user symlinks even though they name the same descriptors as
// the accepted /proc/self/fd/N spelling. Every alias must be written to the
// descriptor it names, whatever the descriptor refers to, and must stay a link
// afterwards. Writing to the descriptor rather than reopening the path is what
// lets `--output /dev/stdout >> run.log` append and lets a socket on standard
// output, as under systemd's StandardOutput=journal, take the report at all.
func TestOutputWriterWritesDescriptorAliasesInPlace(t *testing.T) {
	const previous = "a previous report longer than the new one"
	for _, tc := range []struct {
		name string
		// fd is redirected to the target for the duration of the case; a
		// negative fd addresses the target's own descriptor instead.
		fd    int
		alias func(target *os.File) string
		// file opens a regular file with these flags as the target, the way
		// a shell redirection would; zero uses a pipe, or a socket.
		file   int
		socket bool
		want   string
	}{
		{name: "/dev/stdout to a pipe", fd: 1, alias: func(*os.File) string { return "/dev/stdout" }},
		{name: "/dev/stdout to a socket", fd: 1, alias: func(*os.File) string { return "/dev/stdout" }, socket: true},
		{
			name: "/dev/stdout to a file opened with >", fd: 1, alias: func(*os.File) string { return "/dev/stdout" },
			file: os.O_WRONLY | os.O_CREATE | os.O_TRUNC, want: "new report",
		},
		{
			name: "/dev/stdout to a file opened with >>", fd: 1, alias: func(*os.File) string { return "/dev/stdout" },
			file: os.O_WRONLY | os.O_CREATE | os.O_APPEND, want: previous + "new report",
		},
		{name: "/dev/stderr to a pipe", fd: 2, alias: func(*os.File) string { return "/dev/stderr" }},
		{name: "/dev/fd/N of a pipe", fd: -1, alias: func(target *os.File) string { return fmt.Sprintf("/dev/fd/%d", target.Fd()) }},
		{name: "/proc/thread-self/fd/N of a pipe", fd: -1, alias: func(target *os.File) string {
			return fmt.Sprintf("/proc/thread-self/fd/%d", target.Fd())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target *os.File
			var received <-chan string
			switch {
			case tc.file != 0:
				name := filepath.Join(t.TempDir(), "run.log")
				if err := os.WriteFile(name, []byte(previous), 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(name, tc.file, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				target = file
			case tc.socket:
				pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				peer := os.NewFile(uintptr(pair[1]), "peer")
				defer peer.Close()
				target = os.NewFile(uintptr(pair[0]), "socket")
				defer target.Close()
				received = drainPipe(peer)
			default:
				reader, pipeWriter, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				defer pipeWriter.Close()
				target = pipeWriter
				received = drainPipe(reader)
			}
			restore := func() {}
			if tc.fd >= 0 {
				restore = redirectDescriptor(t, tc.fd, target)
			}

			path := tc.alias(target)
			assertProcFDLink(t, path)
			if err := preflightOutput(path); err != nil {
				t.Fatalf("preflight for %s: %v", path, err)
			}
			writer, finalize, err := outputWriter(path)
			if err != nil {
				t.Fatalf("writer for %s: %v", path, err)
			}
			if _, err := io.WriteString(writer, "new report"); err != nil {
				t.Fatal(err)
			}
			if err := finalize(true); err != nil {
				t.Fatalf("finalize for %s: %v", path, err)
			}
			assertProcFDLink(t, path)
			restore()

			if tc.file != 0 {
				if content, err := os.ReadFile(target.Name()); err != nil || string(content) != tc.want {
					t.Fatalf("descriptor referent = %q/%v, want %q", content, err, tc.want)
				}
				return
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			if got := <-received; got != "new report" {
				t.Fatalf("pipe received %q", got)
			}
		})
	}
}

// TestCommandsWriteThroughDevStdout runs both commands that accept --output
// with /dev/stdout redirected into a pipe, the shape of `speedns --output
// /dev/stdout | jq`: the run must measure once and exit 0, and both reports
// must arrive through the pipe.
func TestCommandsWriteThroughDevStdout(t *testing.T) {
	engineCalls := countEngineCalls(t)
	baseline := writeDiffFixture(t, "baseline.json", nil)
	for name, command := range map[string]func() error{
		"run": func() error {
			config := cliConfigForTest(t)
			config.output = "/dev/stdout"
			return runBenchmark(context.Background(), config)
		},
		"diff": func() error {
			return runDiff(&bytes.Buffer{}, baseline, baseline, "json", "/dev/stdout", nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader, pipeWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer pipeWriter.Close()
			received := drainPipe(reader)
			restoreStdout := redirectDescriptor(t, 1, pipeWriter)
			commandErr := command()
			restoreStdout()
			if err := pipeWriter.Close(); err != nil {
				t.Fatal(err)
			}
			got := <-received
			if commandErr != nil {
				t.Fatalf("%s --output /dev/stdout = %v", name, commandErr)
			}
			if !strings.Contains(got, "\"schema_version\"") {
				t.Fatalf("%s report through /dev/stdout = %q", name, got)
			}
			assertProcFDLink(t, "/dev/stdout")
		})
	}
	if *engineCalls != 1 {
		t.Fatalf("the benchmark ran %d time(s), want 1", *engineCalls)
	}
}

// TestOutputWriterWritesRegularProcFDInPlace pins that /proc/self/fd/N of a
// regular file is written through the descriptor, at its current offset, as
// `>&N` would write it, and that the file is neither reopened nor replaced.
func TestOutputWriterWritesRegularProcFDInPlace(t *testing.T) {
	target, err := os.CreateTemp(t.TempDir(), "report-*")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := io.WriteString(target, "old report, "); err != nil {
		t.Fatal(err)
	}

	path := fmt.Sprintf("/proc/self/fd/%d", target.Fd())
	assertProcFDLink(t, path)
	writer, finalize, err := outputWriter(path)
	if err != nil {
		t.Fatalf("proc fd writer: %v", err)
	}
	if _, err := io.WriteString(writer, "new report"); err != nil {
		t.Fatal(err)
	}
	if err := finalize(true); err != nil {
		t.Fatalf("proc fd finalize: %v", err)
	}
	assertProcFDLink(t, path)
	content, err := os.ReadFile(target.Name())
	if err != nil || string(content) != "old report, new report" {
		t.Fatalf("descriptor referent = %q/%v", content, err)
	}
}

func TestOutputWriterRejectsDirectoryProcFD(t *testing.T) {
	directory := t.TempDir()
	target, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	for _, path := range []string{
		fmt.Sprintf("/proc/self/fd/%d", target.Fd()),
		fmt.Sprintf("/proc/thread-self/fd/%d", target.Fd()),
	} {
		assertProcFDLink(t, path)
		if _, _, err := outputWriter(path); err == nil || !strings.Contains(err.Error(), "output path is a directory") {
			t.Fatalf("directory descriptor error for %s = %v", path, err)
		}
		if err := preflightOutput(path); err == nil || !strings.Contains(err.Error(), "output path is a directory") {
			t.Fatalf("directory descriptor preflight for %s = %v", path, err)
		}
		assertProcFDLink(t, path)
	}
}

func assertProcFDLink(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("proc fd link %q = %v/%v", path, info, err)
	}
}
