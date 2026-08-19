// Package data contains the versioned assets shipped with SpeeDNS.
package data

import (
	_ "embed"
	"strings"
)

//go:embed domains.txt
var domainsFile string

// Domains returns the bundled domain corpus as normalized newline-separated
// names. The canonical corpus bytes used for the metadata checksum are these
// names joined by LF and terminated by LF. The caller receives a new slice and
// may safely modify it.
func Domains() []string {
	lines := strings.Split(domainsFile, "\n")
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "" {
			domains = append(domains, strings.TrimSuffix(line, "."))
		}
	}
	return domains
}
