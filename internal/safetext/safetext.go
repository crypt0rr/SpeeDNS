// Package safetext renders text that SpeeDNS did not produce itself so it can
// be written to a terminal or a CSV cell without changing the meaning of the
// surrounding output.
//
// Report values carry strings chosen by the measured endpoint or by local
// configuration: TLS handshake diagnostics quote certificate fields, and
// resolver names, owners and policies come from --resolver, --resolver-file
// and the system resolver configuration. None of those sources is trusted to
// contain printable text only, so control characters - and the bidirectional
// and invisible format characters that disguise the text around them - are
// escaped at the point a value becomes report output.
package safetext

import (
	"strings"
	"unicode/utf8"
)

// EscapePrefix begins every sequence Escape writes for a control character or
// an invalid byte. RuneEscapePrefix begins the sequence written for a
// bidirectional or invisible format character. Callers that inspect the first
// characters of a rendered value should use HasEscapePrefix, which recognises
// both, to tell that a value's leading character was escaped.
const (
	EscapePrefix     = `\x`
	RuneEscapePrefix = `\u{`
)

const hexDigits = "0123456789abcdef"

// runeEscapeDigits is the minimum number of hex digits in a \u{...} sequence.
// Every rune in the invisible class fits in four, so the width never varies
// within that class, and four digits match the U+XXXX spelling a reader would
// search for.
const runeEscapeDigits = 4

// Escape returns value with every control character rendered as a visible
// \xNN sequence. C0 controls (0x00-0x1f), DEL and the C1 range (0x7f-0x9f)
// are escaped, as is any byte that is not part of a valid UTF-8 sequence.
//
// Bidirectional controls and invisible format characters are rendered as a
// \u{xxxx} sequence instead, see isInvisible. They cannot move the cursor, but
// they can reorder or hide the characters around them on screen, so a value
// carrying one does not read as what it is. They are multi-byte runes, which
// is why they get a rune-sized form rather than a truncated \xNN byte.
//
// Printable text, including other multi-byte UTF-8, is returned unchanged.
//
// Escaping is preferred over stripping: it never removes bytes, so a caller
// that inspects the first character of the result - such as the CSV formula
// guard - still sees a character that belongs to the original value rather
// than one that a removal shifted into place. Escape is idempotent, because
// every sequence it writes is printable ASCII.
func Escape(value string) string {
	if strings.IndexFunc(value, needsEscape) < 0 {
		return value
	}
	var builder strings.Builder
	builder.Grow(len(value) + 8)
	for index := 0; index < len(value); {
		decoded, size := utf8.DecodeRuneInString(value[index:])
		switch {
		case decoded == utf8.RuneError && size == 1:
			writeEscaped(&builder, value[index])
		case isControl(decoded):
			writeEscaped(&builder, byte(decoded))
		case isInvisible(decoded):
			writeRuneEscaped(&builder, decoded)
		default:
			builder.WriteString(value[index : index+size])
		}
		index += size
	}
	return builder.String()
}

// HasEscapePrefix reports whether value begins with a sequence Escape wrote.
func HasEscapePrefix(value string) bool {
	return strings.HasPrefix(value, EscapePrefix) || strings.HasPrefix(value, RuneEscapePrefix)
}

// needsEscape reports whether a rune sends Escape down its rewriting path.
// utf8.RuneError is included so that invalid encodings are rewritten too; a
// genuine U+FFFD is not a control character and Escape writes it back
// unchanged.
func needsEscape(value rune) bool {
	return isControl(value) || isInvisible(value) || value == utf8.RuneError
}

func isControl(value rune) bool {
	return value < 0x20 || (value >= 0x7f && value <= 0x9f)
}

// isInvisible reports whether value is a bidirectional control or an
// invisible format character. The first group is exactly the Unicode
// Bidi_Control property: the Arabic letter mark, the left-to-right and
// right-to-left marks, and the embedding, override and isolate controls. Any
// of them can make a terminal that applies the bidirectional algorithm draw
// the text around it in another order. The second group draws nothing at all
// - zero-width spaces and joiners, the word joiner and the invisible
// operators, and the byte order mark - so two values that look identical can
// differ, and a cell can be wider than it appears.
//
// The soft hyphen (U+00AD) is a format character too, but terminals draw it as
// a visible hyphen, so it stays as written.
func isInvisible(value rune) bool {
	switch {
	case value == 0x061c, value == 0xfeff:
		return true
	case value >= 0x200b && value <= 0x200f:
		return true
	case value >= 0x202a && value <= 0x202e:
		return true
	case value >= 0x2060 && value <= 0x2064:
		return true
	case value >= 0x2066 && value <= 0x2069:
		return true
	default:
		return false
	}
}

func writeEscaped(builder *strings.Builder, value byte) {
	builder.WriteString(EscapePrefix)
	builder.WriteByte(hexDigits[value>>4])
	builder.WriteByte(hexDigits[value&0x0f])
}

// writeRuneEscaped writes value as \u{xxxx}: lowercase hex, at least
// runeEscapeDigits digits, and the whole code point, never a truncated byte.
func writeRuneEscaped(builder *strings.Builder, value rune) {
	var digits [8]byte
	position := len(digits)
	for remaining := uint32(value); remaining > 0 || len(digits)-position < runeEscapeDigits; remaining >>= 4 {
		position--
		digits[position] = hexDigits[remaining&0x0f]
	}
	builder.WriteString(RuneEscapePrefix)
	builder.Write(digits[position:])
	builder.WriteByte('}')
}
