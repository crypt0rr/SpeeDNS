package transport

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// responseIsAcceptable restates, independently of validateResponse, the
// properties a response must have before a measured exchange may be counted.
// validateResponse is the anti-spoofing boundary for UDP and the
// question/transaction-ID match for DoH, DoT and DoQ, so the fuzz target
// asserts the biconditional: it accepts exactly the responses that satisfy
// every property here, and rejects every other input.
func responseIsAcceptable(response *dns.Msg, name string, qtype, queryID uint16, zeroID bool) bool {
	if response == nil || !response.Response {
		return false
	}
	if zeroID {
		if response.Id != 0 {
			return false
		}
	} else if response.Id != queryID {
		return false
	}
	if len(response.Question) != 1 {
		return false
	}
	question := response.Question[0]
	if !strings.EqualFold(dns.Fqdn(question.Name), dns.Fqdn(name)) {
		return false
	}
	return question.Qtype == qtype && question.Qclass == dns.ClassINET
}

func fuzzResponseSeed(f *testing.F, mutate func(*dns.Msg)) []byte {
	f.Helper()
	query := newQuery("example.com", dns.TypeA, 1, false)
	response := new(dns.Msg)
	response.SetReply(query)
	if mutate != nil {
		mutate(response)
	}
	packed, err := response.Pack()
	if err != nil {
		f.Fatal(err)
	}
	return packed
}

func FuzzValidateResponseMatchesRequest(f *testing.F) {
	// A well-formed reply, plus mutations that each defeat exactly one of the
	// acceptance properties, so the interesting rejection paths are reached
	// before the mutator starts flipping bytes.
	f.Add(fuzzResponseSeed(f, nil), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, nil), "EXAMPLE.COM.", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Response = false }), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Id = 4242 }), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Id = 0 }), "example.com", dns.TypeA, uint16(0), true)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Id = 7 }), "example.com", dns.TypeA, uint16(0), true)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Question = nil }), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) {
		m.Question = append(m.Question, dns.Question{Name: "second.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	}), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Question[0].Name = "attacker.example." }), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }), "example.com", dns.TypeA, uint16(1), false)
	f.Add(fuzzResponseSeed(f, func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }), "example.com", dns.TypeA, uint16(1), false)
	f.Add([]byte{}, "example.com", dns.TypeA, uint16(0), true)

	f.Fuzz(func(t *testing.T, wire []byte, name string, qtype, queryID uint16, zeroID bool) {
		// A response that cannot be unpacked is still handed to
		// validateResponse: truncated and malformed wire data is exactly what
		// an off-path spoofer produces, and it must be rejected rather than
		// skipped by the harness.
		message := new(dns.Msg)
		unpackErr := message.Unpack(wire)

		err := validateResponse(message, name, qtype, queryID, zeroID)
		if want := responseIsAcceptable(message, name, qtype, queryID, zeroID); (err == nil) != want {
			t.Fatalf("validateResponse(unpack=%v) err = %v, acceptable = %v, message = %v", unpackErr, err, want, message)
		}
		if err != nil {
			return
		}
		if !message.Response {
			t.Fatalf("accepted a message without the response flag: %v", message)
		}
		if len(message.Question) != 1 {
			t.Fatalf("accepted %d questions: %v", len(message.Question), message)
		}
		question := message.Question[0]
		if !strings.EqualFold(dns.Fqdn(question.Name), dns.Fqdn(name)) {
			t.Fatalf("accepted question name %q for request %q", question.Name, name)
		}
		if question.Qtype != qtype {
			t.Fatalf("accepted question type %d for request type %d", question.Qtype, qtype)
		}
		if question.Qclass != dns.ClassINET {
			t.Fatalf("accepted question class %d, want IN", question.Qclass)
		}
		if zeroID && message.Id != 0 {
			t.Fatalf("accepted non-zero transaction ID %d on a zero-ID transport", message.Id)
		}
		if !zeroID && message.Id != queryID {
			t.Fatalf("accepted transaction ID %d, want %d", message.Id, queryID)
		}
	})
}

func TestValidateResponseRejectsMissingMessage(t *testing.T) {
	if err := validateResponse(nil, "example.com", dns.TypeA, 1, false); err == nil {
		t.Fatal("a nil response must be rejected")
	}
}
