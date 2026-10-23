//go:build unix

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
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
// The result also says whether the descriptor is open for writing, which
// fstat cannot tell: openDescriptorOutput refuses one that is not.
//
// Only a descriptor the process inherited counts as open. By the time the
// preflight runs, the Go runtime holds descriptors of its own, such as the
// network poller's epoll and eventfd descriptors on Linux or its kqueue on
// macOS. They take the lowest free numbers, typically 3 and 4 when the caller
// opened nothing more, and dup, fstat and F_GETFL all accept them, so
// `--output /dev/fd/3` with the `3>` redirection forgotten ran the whole
// benchmark and then wrote the report into the poller. Every descriptor the
// runtime and package os open is close-on-exec, and an inherited one cannot
// be, because exec would have closed it. A close-on-exec descriptor is
// therefore refused with EBADF, exactly as if it were closed. The /dev/null
// descriptors the runtime opens in place of a closed 0, 1 or 2 are not
// close-on-exec, so those are still written to, as standard output would be.
// A descriptor that really is closed fails F_GETFD too, and is left to dup to
// report.
//
// The handle owns only the duplicate, and closing it leaves the inherited
// descriptor open. Closing descriptor 1 or 2 would break every later write to
// standard output or standard error; the process exit closes them anyway.
// Wrapping the inherited number itself in os.NewFile is not an option either,
// because the garbage collector closes such a file once it is unreachable,
// possibly after its number has been reused by another file.
var openOutputDescriptor = func(descriptor int, path string) (outputDescriptorHandle, bool, error) {
	if flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); err == nil && flags&unix.FD_CLOEXEC != 0 {
		return nil, false, &os.PathError{Op: "dup", Path: path, Err: syscall.EBADF}
	}
	// The fork lock keeps a concurrent fork from inheriting the duplicate
	// before it is marked close-on-exec.
	syscall.ForkLock.RLock()
	duplicate, err := syscall.Dup(descriptor)
	if err == nil {
		syscall.CloseOnExec(duplicate)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, false, &os.PathError{Op: "dup", Path: path, Err: err}
	}
	// The access mode belongs to the open file description, which the
	// duplicate shares. It is read from the raw duplicate, because the Fd
	// method of the wrapping file could switch that shared description to
	// blocking mode. Flags that cannot be read count as writable and leave
	// the decision to the write itself.
	flags, err := unix.FcntlInt(uintptr(duplicate), unix.F_GETFL, 0)
	writable := err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY
	return os.NewFile(uintptr(duplicate), path), writable, nil
}
