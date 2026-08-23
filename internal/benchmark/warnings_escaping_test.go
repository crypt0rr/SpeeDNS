package benchmark

import (
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// TestCollectWarningsEscapesEndpointSuppliedText covers the path a hostile or
// intercepted TLS endpoint has into report text: x509 quotes the certificate's
// subject alternative name in its hostname mismatch error, and ESC passes the
// IA5String check applied to that field. Warnings are printed verbatim under
// --details, so the escaping has to happen where the warning is built.
func TestCollectWarningsEscapesEndpointSuppliedText(t *testing.T) {
	target := testTarget(catalog.DoT, "192.0.2.10")
	target.Resolver.Name = "Resolver\x1b[2K\rhidden"
	result := TargetResult{
		Target:     target,
		OpenError:  "x509: certificate is valid for \x1b[2K\rspoofed.example, not resolver.example",
		Incomplete: true,
	}
	warnings := collectWarnings([]TargetResult{result})
	if len(warnings) != 2 {
		t.Fatalf("warnings = %#v", warnings)
	}
	joined := strings.Join(warnings, "\n")
	if strings.ContainsAny(joined, "\x1b\r") {
		t.Fatalf("warnings kept a control character: %q", joined)
	}
	for _, expected := range []string{
		`Resolver\x1b[2K\x0dhidden 192.0.2.10/dot`,
		`valid for \x1b[2K\x0dspoofed.example`,
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("warnings missing escaped text %q: %q", expected, joined)
		}
	}
}
