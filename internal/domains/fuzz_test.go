package domains

import (
	"strings"
	"testing"
)

func FuzzNormalizeNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"example.com\nExample.ORG.",
		"BÜCHER.example\n*.invalid.example",
		"example..com\n",
		"_sip._tcp.example.com\n_dmarc.example.com",
		"__dmarc.example\n_.example\nunder_score.example",
		string([]byte{0xff, '.', 'c', 'o', 'm'}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = Normalize(strings.Split(input, "\n"))
	})
}
