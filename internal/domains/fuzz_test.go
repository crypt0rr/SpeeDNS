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
		string([]byte{0xff, '.', 'c', 'o', 'm'}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = Normalize(strings.Split(input, "\n"))
	})
}
