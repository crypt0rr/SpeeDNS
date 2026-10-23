//go:build unix

package main

import (
	"io/fs"
	"syscall"
)

// outputLinkCount reports how many directory entries name the file behind
// info. A FileInfo that does not come from the operating system counts as one
// link, which keeps the ordinary atomic replacement.
func outputLinkCount(info fs.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}
