package safetext

import "testing"

func TestEscapeRendersControlCharactersVisible(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "printable ascii", value: "resolver one (udp)", want: "resolver one (udp)"},
		{name: "multi byte utf8", value: "Bäckerei 日本", want: "Bäckerei 日本"},
		{name: "replacement character", value: "a\ufffdb", want: "a\ufffdb"},
		{name: "escape sequence", value: "x509: valid for \x1b[2K\rfake", want: `x509: valid for \x1b[2K\x0dfake`},
		{name: "nul and c0", value: "a\x00b\tc\nd", want: `a\x00b\x09c\x0ad`},
		{name: "delete and c1", value: "a\x7fb\u0085c\u009fd", want: `a\x7fb\x85c\x9fd`},
		{name: "invalid utf8 byte", value: "a\xffb\x9b", want: `a\xffb\x9b`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Escape(tc.value)
			if got != tc.want {
				t.Fatalf("Escape(%q) = %q, want %q", tc.value, got, tc.want)
			}
			if again := Escape(got); again != got {
				t.Fatalf("Escape is not idempotent: Escape(%q) = %q", got, again)
			}
		})
	}
}

func TestEscapeReturnsInputWhenNothingNeedsEscaping(t *testing.T) {
	value := "owner name"
	if got := Escape(value); got != value {
		t.Fatalf("Escape(%q) = %q, want the input unchanged", value, got)
	}
}
