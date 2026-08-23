// Package textwidth measures how many terminal cells a string occupies.
//
// Resolver names, owners and policies reach the terminal from --resolver and
// --resolver-file, so byte length and rune count are both unsafe measures:
// East Asian wide characters occupy two cells, combining marks occupy none,
// and ANSI escape sequences occupy none. Progress erasure and table column
// padding depend on the same measurement, so it lives here once.
package textwidth

import (
	"unicode"

	"golang.org/x/text/width"
)

// escape introduces an ANSI escape sequence.
const escape = '\x1b'

// Display returns the number of terminal cells used by value.
func Display(value string) int {
	result := 0
	runes := []rune(value)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if character == escape {
			index = skipEscape(runes, index)
			continue
		}
		if unicode.Is(unicode.Mn, character) || unicode.Is(unicode.Me, character) {
			continue
		}
		switch width.LookupRune(character).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			result += 2
		default:
			result++
		}
	}
	return result
}

// skipEscape returns the index of the last rune belonging to the escape
// sequence starting at start. A control sequence runs until its final rune in
// the range @ to ~; any other escape is assumed to be two runes long, and an
// unterminated sequence consumes the rest of the string.
func skipEscape(runes []rune, start int) int {
	index := start + 1
	if index >= len(runes) || runes[index] != '[' {
		return index
	}
	for index++; index < len(runes); index++ {
		if runes[index] >= '@' && runes[index] <= '~' {
			return index
		}
	}
	return len(runes)
}
