package benchmark

import (
	"encoding/json"
	"fmt"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
)

// Warning is a diagnostic produced by a benchmark run.
//
// Target identifies the endpoint the warning belongs to and is nil when the
// warning describes the run as a whole. Message carries the diagnostic only:
// it never contains the endpoint identity, so a presenter decides whether and
// how the identity is rendered. Consumers therefore never have to recover the
// attribution by matching a rebuilt label against the message text, and a
// change to the label format cannot silently drop warnings from a view.
type Warning struct {
	Target  *catalog.Target
	Message string
}

// RunWarning returns a warning about the run as a whole.
func RunWarning(message string) Warning {
	return Warning{Message: message}
}

// TargetWarning returns a warning attributed to a single endpoint. The target
// is copied, so later mutation of the caller's value cannot change the
// attribution of an already recorded warning.
func TargetWarning(target catalog.Target, message string) Warning {
	return Warning{Target: &target, Message: message}
}

// Targeted reports whether the warning belongs to a single endpoint.
func (w Warning) Targeted() bool {
	return w.Target != nil
}

// RenderWith renders the warning using the supplied display name and address
// for its target. Presenters use it to substitute a redacted identity without
// re-implementing the label format.
func (w Warning) RenderWith(name, address string) string {
	if w.Target == nil {
		return w.Message
	}
	return fmt.Sprintf("%s %s/%s %s", name, address, w.Target.Protocol, w.Message)
}

// String renders the warning with the target's own identity.
func (w Warning) String() string {
	if w.Target == nil {
		return w.Message
	}
	return w.RenderWith(w.Target.DisplayName(), w.Target.Address)
}

// MarshalJSON keeps the published report contract: a warning is emitted as the
// rendered string, so "warnings" stays an array of strings.
func (w Warning) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.String())
}

// UnmarshalJSON accepts the emitted string form. Endpoint attribution is a
// process-local detail that is not carried in JSON, so a decoded warning is
// always run-level.
func (w *Warning) UnmarshalJSON(data []byte) error {
	var message string
	if err := json.Unmarshal(data, &message); err != nil {
		return err
	}
	w.Target = nil
	w.Message = message
	return nil
}
