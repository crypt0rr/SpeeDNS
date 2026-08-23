// Package safetext renders text that SpeeDNS did not produce itself so it can
// be written to a terminal or a CSV cell without changing the meaning of the
// surrounding output.
//
// Report values carry strings chosen by the measured endpoint or by local
// configuration: TLS handshake diagnostics quote certificate fields, and
// resolver names, owners and policies come from --resolver, --resolver-file
// and the system resolver configuration. None of those sources is trusted to
// contain printable text only, so control characters are escaped at the point
// a value becomes report output.
package safetext

import (
	"strings"
	"unicode/utf8"
)

// EscapePrefix begins every sequence Escape writes. Callers that inspect the
// first characters of a rendered value can use it to recognise a value whose
// leading character was escaped.
const EscapePrefix = `\x`

const hexDigits = "0123456789abcdef"

// Escape returns value with every control character rendered as a visible
// \xNN sequence. C0 controls (0x00-0x1f), DEL and the C1 range (0x7f-0x9f)
// are escaped, as is any byte that is not part of a valid UTF-8 sequence.
// Printable text, including multi-byte UTF-8, is returned unchanged.
//
// Escaping is preferred over stripping: it never removes bytes, so a caller
// that inspects the first character of the result - such as the CSV formula
// guard - still sees a character that belongs to the original value rather
// than one that a removal shifted into place. Escape is idempotent, because
// its output is printable ASCII.
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
		default:
			builder.WriteString(value[index : index+size])
		}
		index += size
	}
	return builder.String()
}

// needsEscape reports whether a rune sends Escape down its rewriting path.
// utf8.RuneError is included so that invalid encodings are rewritten too; a
// genuine U+FFFD is not a control character and Escape writes it back
// unchanged.
func needsEscape(value rune) bool {
	return isControl(value) || value == utf8.RuneError
}

func isControl(value rune) bool {
	return value < 0x20 || (value >= 0x7f && value <= 0x9f)
}

func writeEscaped(builder *strings.Builder, value byte) {
	builder.WriteString(EscapePrefix)
	builder.WriteByte(hexDigits[value>>4])
	builder.WriteByte(hexDigits[value&0x0f])
}
