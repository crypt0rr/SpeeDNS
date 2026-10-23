//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// withDescriptorRedirected runs body with descriptor fd pointed at target and
// puts the original back before it returns, also if body panics. body reports
// a failure by returning it instead of failing the test: while descriptor 1
// or 2 points at a test pipe, a diagnostic that go test -v streams straight
// away would go into the pipe and be lost. The redirected descriptor is not
// close-on-exec, so it looks inherited, as descriptor 1 under a shell
// redirection does. Dup3 is used because linux/arm64 has no dup2 system call.
func withDescriptorRedirected(t *testing.T, fd int, target *os.File, body func() error) error {
	t.Helper()
	saved, err := syscall.Dup(fd)
	if err != nil {
		t.Fatalf("save descriptor %d: %v", fd, err)
	}
	if err := syscall.Dup3(int(target.Fd()), fd, 0); err != nil {
		_ = syscall.Close(saved)
		t.Fatalf("redirect descriptor %d: %v", fd, err)
	}
	defer func() {
		if err := errors.Join(syscall.Dup3(saved, fd, 0), syscall.Close(saved)); err != nil {
			t.Errorf("restore descriptor %d: %v", fd, err)
		}
	}()
	return body()
}

// deliverReportThroughLink is deliverReport for a descriptor alias that is a
// symlink into /proc, which must still be the same link afterwards.
func deliverReportThroughLink(path, report string) error {
	if err := procFDLinkError(path); err != nil {
		return err
	}
	if err := deliverReport(path, report); err != nil {
		return err
	}
	return procFDLinkError(path)
}

func TestOutputWriterWritesProcFD1PipeInPlace(t *testing.T) {
	reader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer pipeWriter.Close()

	err = withDescriptorRedirected(t, 1, pipeWriter, func() error {
		return deliverReportThroughLink("/proc/self/fd/1", "report through stdout pipe")
	})
	if err != nil {
		t.Fatal(err)
	}
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
			path := tc.alias(target)
			deliver := func() error { return deliverReportThroughLink(path, "new report") }
			var err error
			if tc.fd >= 0 {
				err = withDescriptorRedirected(t, tc.fd, target, deliver)
			} else {
				inheritDescriptor(t, target.Fd())
				err = deliver()
			}
			if err != nil {
				t.Fatal(err)
			}

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
			commandErr := withDescriptorRedirected(t, 1, pipeWriter, command)
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
	inheritDescriptor(t, target.Fd())
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
	inheritDescriptor(t, target.Fd())

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

// TestOutputRefusesAnOPathDescriptor pins that a descriptor open for no I/O at
// all, which Linux hands out for O_PATH, is refused like a read-only one: dup
// and fstat accept it, and only a write would fail.
func TestOutputRefusesAnOPathDescriptor(t *testing.T) {
	name := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(name, []byte("previous report"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := syscall.Open(name, unix.O_PATH|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("opening an O_PATH descriptor is unavailable: %v", err)
	}
	defer syscall.Close(descriptor)
	inheritDescriptor(t, uintptr(descriptor))

	path := fmt.Sprintf("/proc/self/fd/%d", descriptor)
	assertProcFDLink(t, path)
	wants := "output path is a descriptor not open for writing: " + path
	if err := preflightOutput(path); err == nil || err.Error() != wants {
		t.Fatalf("O_PATH preflight = %v, want %q", err, wants)
	}
	if _, _, err := outputWriter(path); err == nil || err.Error() != wants {
		t.Fatalf("O_PATH writer = %v, want %q", err, wants)
	}
	if content, err := os.ReadFile(name); err != nil || string(content) != "previous report" {
		t.Fatalf("the file behind the descriptor = %q/%v", content, err)
	}
}

// TestOutputRefusesTheRuntimesPollerDescriptors is the failure behind the
// close-on-exec check, on the descriptors that caused it. The Go runtime's
// network poller holds an epoll descriptor and an eventfd, both open and
// writable, typically at 3 and 4 when the caller opened nothing more. So
// `--output /dev/fd/3` with the `3>` redirection forgotten ran the whole
// benchmark and then wrote the report into the poller. Each of them must count
// as closed, before the run and after it.
func TestOutputRefusesTheRuntimesPollerDescriptors(t *testing.T) {
	// A pipe end is registered with the poller, so the poller's descriptors
	// exist by now even when this test runs alone.
	reader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer pipeWriter.Close()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("listing /proc/self/fd is unavailable: %v", err)
	}
	engineCalls := countEngineCalls(t)
	refused := 0
	for _, entry := range entries {
		link, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil || (link != "anon_inode:[eventpoll]" && link != "anon_inode:[eventfd]") {
			continue
		}
		descriptor, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		// A poller descriptor a careless parent leaked into the test would
		// be inherited, and so the caller's to name; only the runtime's own
		// are close-on-exec.
		if flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
			continue
		}
		path := "/dev/fd/" + entry.Name()
		wants := "inspect output path: dup " + path + ": " + syscall.EBADF.Error()
		if err := preflightOutput(path); !errors.Is(err, syscall.EBADF) || err.Error() != wants {
			t.Fatalf("preflight for %s (%s) = %v, want %q", path, link, err, wants)
		}
		if _, _, err := outputWriter(path); !errors.Is(err, syscall.EBADF) || err.Error() != wants {
			t.Fatalf("writer for %s (%s) = %v, want %q", path, link, err, wants)
		}
		config := cliConfigForTest(t)
		config.output = path
		if err := runBenchmark(context.Background(), config); err == nil || err.Error() != wants || exitCodeForError(err) != 2 {
			t.Fatalf("run to %s (%s) = %v (exit %d), want %q with status 2", path, link, err, exitCodeForError(err), wants)
		}
		refused++
	}
	if *engineCalls != 0 {
		t.Fatalf("the benchmark ran %d time(s) for a poller descriptor", *engineCalls)
	}
	if refused == 0 {
		t.Skip("no poller descriptor of the runtime's own was found")
	}
}

// procFDLinkError reports whether path is a symlink, as every descriptor alias
// on Linux is, without failing the test.
func procFDLinkError(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("proc fd link %q = %v/%v", path, info, err)
	}
	return nil
}

func assertProcFDLink(t *testing.T, path string) {
	t.Helper()
	if err := procFDLinkError(path); err != nil {
		t.Fatal(err)
	}
}
