//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestOutputWriterWritesProcFD1PipeInPlace(t *testing.T) {
	reader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer pipeWriter.Close()

	savedStdout, err := syscall.Dup(1)
	if err != nil {
		t.Fatalf("save stdout: %v", err)
	}
	restoredStdout := false
	restoreStdout := func() {
		if restoredStdout {
			return
		}
		if err := syscall.Dup2(savedStdout, 1); err != nil {
			t.Errorf("restore stdout: %v", err)
		}
		if err := syscall.Close(savedStdout); err != nil {
			t.Errorf("close saved stdout: %v", err)
		}
		restoredStdout = true
	}
	defer restoreStdout()
	if err := syscall.Dup2(int(pipeWriter.Fd()), 1); err != nil {
		t.Fatalf("redirect stdout to pipe: %v", err)
	}

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

func TestOutputWriterWritesRegularProcFDInPlace(t *testing.T) {
	target, err := os.CreateTemp(t.TempDir(), "report-*")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := io.WriteString(target, "old report"); err != nil {
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
	if err != nil || string(content) != "new report" {
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

	path := fmt.Sprintf("/proc/self/fd/%d", target.Fd())
	assertProcFDLink(t, path)
	if _, _, err := outputWriter(path); err == nil || !strings.Contains(err.Error(), "output path is a directory") {
		t.Fatalf("directory descriptor error = %v", err)
	}
	assertProcFDLink(t, path)
}

func assertProcFDLink(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("proc fd link %q = %v/%v", path, info, err)
	}
}
