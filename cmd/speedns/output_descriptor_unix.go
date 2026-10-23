//go:build unix

package main

import (
	"os"
	"syscall"
)

// openOutputDescriptor returns a handle on the open descriptor a descriptor
// alias names, without opening the alias by path. Reopening /dev/stdout would
// create a new open file description: on Linux it starts at offset zero
// without O_APPEND, so `>> run.log` was overwritten, and a socket, which is
// what standard output is under systemd's StandardOutput=journal, cannot be
// opened by name at all. A duplicate shares the open file description
// instead, so the report lands exactly where a write to standard output would
// put it: appended after `>>`, at the current offset after `>`, and into a
// pipe or socket as is.
//
// The handle owns only the duplicate, and closing it leaves the inherited
// descriptor open. Closing descriptor 1 or 2 would break every later write to
// standard output or standard error; the process exit closes them anyway.
// Wrapping the inherited number itself in os.NewFile is not an option either,
// because the garbage collector closes such a file once it is unreachable,
// possibly after its number has been reused by another file.
var openOutputDescriptor = func(descriptor int, path string) (outputDescriptorHandle, error) {
	// The fork lock keeps a concurrent fork from inheriting the duplicate
	// before it is marked close-on-exec.
	syscall.ForkLock.RLock()
	duplicate, err := syscall.Dup(descriptor)
	if err == nil {
		syscall.CloseOnExec(duplicate)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, &os.PathError{Op: "dup", Path: path, Err: err}
	}
	return os.NewFile(uintptr(duplicate), path), nil
}
