package benchmark

import (
	"strings"
	"testing"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// TestCollectWarningsEscapesEndpointSuppliedText covers the path a hostile or
// intercepted TLS endpoint has into report text: x509 quotes the certificate's
// subject alternative name in its hostname mismatch error, and ESC passes the
// IA5String check applied to that field. The message is escaped where the
// warning is built, so no producer can hand a presenter raw control bytes.
//
// The target identity is deliberately not escaped here. A structured warning
// carries the target rather than a rendered label, so the identity is escaped
// by whichever presenter renders it - covered by the report tests.
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
	messages := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		if !warning.Targeted() {
			t.Fatalf("warning is not attributed to its target: %#v", warning)
		}
		messages = append(messages, warning.Message)
	}
	joined := strings.Join(messages, "\n")
	if strings.ContainsAny(joined, "\x1b\r") {
		t.Fatalf("warning message kept a control character: %q", joined)
	}
	if !strings.Contains(joined, `valid for \x1b[2K\x0dspoofed.example`) {
		t.Fatalf("warning message missing escaped endpoint text: %q", joined)
	}
	if strings.Contains(joined, "192.0.2.10") {
		t.Fatalf("warning message should not carry the endpoint identity: %q", joined)
	}
}
