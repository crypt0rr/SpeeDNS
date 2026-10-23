//go:build !unix

package main

import "io/fs"

// outputLinkCount reports one link on platforms whose FileInfo does not expose
// a link count, so a destination there keeps the ordinary atomic replacement.
func outputLinkCount(fs.FileInfo) uint64 { return 1 }
