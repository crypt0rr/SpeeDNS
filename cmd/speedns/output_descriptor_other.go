//go:build !unix

package main

import (
	"errors"
	"os"
)

// openOutputDescriptor refuses every descriptor alias on a platform without
// Unix descriptors. Windows never gets here, because the aliases are not
// absolute paths there and so never match; this keeps the package building.
var openOutputDescriptor = func(_ int, path string) (outputDescriptorHandle, error) {
	return nil, &os.PathError{Op: "dup", Path: path, Err: errors.ErrUnsupported}
}
