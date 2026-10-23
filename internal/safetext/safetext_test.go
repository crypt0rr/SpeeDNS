package safetext

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

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
		// A bidi override is three bytes of UTF-8. Writing it through the
		// byte form would print \x2e - the low byte of U+202E, and a full
		// stop - so it gets a rune-sized sequence instead.
		{name: "right to left override", value: "a\u202eb", want: `a\u{202e}b`},
		{name: "arabic letter mark", value: "a\u061cb", want: `a\u{061c}b`},
		{name: "marks and isolates", value: "\u200e\u200f\u2066\u2067\u2068\u2069", want: `\u{200e}\u{200f}\u{2066}\u{2067}\u{2068}\u{2069}`},
		{name: "embeddings and overrides", value: "\u202a\u202b\u202c\u202d\u202e", want: `\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}`},
		{name: "zero width", value: "a\u200bb\u200cc\u200dd", want: `a\u{200b}b\u{200c}c\u{200d}d`},
		{name: "invisible operators", value: "\u2060\u2061\u2062\u2063\u2064", want: `\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}`},
		{name: "byte order mark", value: "\ufeffresolver", want: `\u{feff}resolver`},
		{name: "mixed with control", value: "\x1b[2K\u202e", want: `\x1b[2K\u{202e}`},
		// The soft hyphen is a format character that terminals draw, and the
		// unassigned U+2065 between the two ranges is not a control.
		{name: "soft hyphen kept", value: "re\u00adsolver", want: "re\u00adsolver"},
		{name: "unassigned neighbour kept", value: "a\u2065b", want: "a\u2065b"},
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

// TestEscapeOutputIsPrintableASCIIForEveryRewrittenRune walks every code point
// Escape rewrites and checks the two properties callers rely on: the sequence
// is printable ASCII, so a second pass leaves it alone, and it decodes back to
// the original rune, so nothing was truncated on the way.
func TestEscapeOutputIsPrintableASCIIForEveryRewrittenRune(t *testing.T) {
	rewritten := 0
	for value := rune(0); value <= utf8.MaxRune; value++ {
		if value >= 0xd800 && value <= 0xdfff {
			continue
		}
		if !needsEscape(value) || value == utf8.RuneError {
			continue
		}
		rewritten++
		input := "a" + string(value) + "b"
		got := Escape(input)
		for index := 0; index < len(got); index++ {
			if got[index] < 0x20 || got[index] > 0x7e {
				t.Fatalf("Escape(%q) = %q, which is not printable ASCII", input, got)
			}
		}
		if again := Escape(got); again != got {
			t.Fatalf("Escape is not idempotent for U+%04X: %q -> %q", value, got, again)
		}
		if decoded := unescapeForTest(t, got); decoded != input {
			t.Fatalf("Escape(%q) = %q, which decodes to %q", input, got, decoded)
		}
	}
	// 65 C0, DEL and C1 controls, 12 Bidi_Control runes and 9 invisible
	// format characters.
	if rewritten != 86 {
		t.Fatalf("Escape rewrote %d runes, want 86", rewritten)
	}
}

func TestWriteRuneEscapedKeepsEveryHexDigit(t *testing.T) {
	for _, tc := range []struct {
		value rune
		want  string
	}{
		{value: 0, want: `\u{0000}`},
		{value: 0x61c, want: `\u{061c}`},
		{value: 0xfeff, want: `\u{feff}`},
		{value: 0xe0001, want: `\u{e0001}`},
		{value: utf8.MaxRune, want: `\u{10ffff}`},
	} {
		var builder strings.Builder
		writeRuneEscaped(&builder, tc.value)
		if got := builder.String(); got != tc.want {
			t.Fatalf("writeRuneEscaped(U+%04X) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestHasEscapePrefixRecognisesBothForms(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{value: Escape("\x1b=cmd"), want: true},
		{value: Escape("\u202e=cmd"), want: true},
		{value: Escape("=cmd"), want: false},
		{value: Escape("resolver"), want: false},
		{value: "", want: false},
	} {
		if got := HasEscapePrefix(tc.value); got != tc.want {
			t.Fatalf("HasEscapePrefix(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// unescapeForTest reverses Escape for valid UTF-8 inputs that contain no
// literal backslash. It exists to prove that every sequence carries the whole
// code point it replaced. An invalid byte and the C1 control with the same
// value share one \xNN spelling, so invalid input is deliberately out of its
// scope.
func unescapeForTest(t *testing.T, value string) string {
	t.Helper()
	var builder strings.Builder
	for index := 0; index < len(value); {
		switch {
		case strings.HasPrefix(value[index:], RuneEscapePrefix):
			end := strings.IndexByte(value[index:], '}')
			if end < 0 {
				t.Fatalf("unterminated rune escape in %q", value)
			}
			code, err := strconv.ParseUint(value[index+len(RuneEscapePrefix):index+end], 16, 32)
			if err != nil {
				t.Fatalf("bad rune escape in %q: %v", value, err)
			}
			builder.WriteRune(rune(code))
			index += end + 1
		case strings.HasPrefix(value[index:], EscapePrefix):
			code, err := strconv.ParseUint(value[index+len(EscapePrefix):index+len(EscapePrefix)+2], 16, 8)
			if err != nil {
				t.Fatalf("bad byte escape in %q: %v", value, err)
			}
			// Every control Escape writes this way is below U+00A0, where
			// the code point and the byte value coincide.
			builder.WriteRune(rune(code))
			index += len(EscapePrefix) + 2
		default:
			builder.WriteByte(value[index])
			index++
		}
	}
	return builder.String()
}
