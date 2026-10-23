package textwidth

import "testing"

func TestDisplayCountsTerminalCells(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  int
	}{
		{name: "empty", value: "", want: 0},
		{name: "ascii", value: "resolver", want: 8},
		{name: "combining mark", value: "e\u0301clair", want: 6},
		{name: "enclosing mark", value: "a\u20dd", want: 1},
		{name: "east asian wide", value: "東京", want: 4},
		{name: "fullwidth", value: "\uff21\uff22", want: 4},
		{name: "mixed", value: "東京-dns", want: 8},
		{name: "colour sequence", value: "\x1b[32mQUALIFIED\x1b[0m", want: 9},
		{name: "bare escape", value: "\x1b", want: 0},
		{name: "two rune escape", value: "\x1bMok", want: 2},
		{name: "unterminated sequence", value: "ok\x1b[32", want: 2},
		// Format characters draw nothing, except the soft hyphen, which
		// terminals render as a visible hyphen.
		{name: "zero width space", value: "a\u200bb", want: 2},
		{name: "zero width joiners", value: "a\u200cb\u200dc", want: 3},
		{name: "bidi override", value: "a\u202eb\u202c", want: 2},
		{name: "bidi isolate", value: "\u2067ab\u2069", want: 2},
		{name: "byte order mark", value: "\ufeffdns", want: 3},
		{name: "word joiner", value: "a\u2060b", want: 2},
		{name: "soft hyphen", value: "a\u00adb", want: 3},
		{name: "combining mark with zero width space", value: "e\u0301\u200b", want: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := Display(testCase.value); got != testCase.want {
				t.Fatalf("Display(%q) = %d, want %d", testCase.value, got, testCase.want)
			}
		})
	}
}
