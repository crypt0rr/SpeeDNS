//go:build !windows

package systemdns

import "errors"

// platformWindowsAdapters exists so the package compiles everywhere. currentOS
// mirrors runtime.GOOS, so Discover routes to the Windows path only in a build
// that has the real implementation — or in a test that forces the platform and
// supplies its own adapter table.
func platformWindowsAdapters() ([]windowsAdapter, error) {
	return nil, errors.New("this binary was not built for Windows, so it cannot read the Windows adapter table")
}
