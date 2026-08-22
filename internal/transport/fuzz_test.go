package transport

import (
	"testing"

	"github.com/miekg/dns"
)

func FuzzValidateResponseNeverPanics(f *testing.F) {
	query := newQuery("example.com", dns.TypeA, 1, false, QueryOptions{})
	response := new(dns.Msg)
	response.SetReply(query)
	packed, err := response.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(packed, uint16(1), false)
	f.Add([]byte{}, uint16(0), true)
	f.Fuzz(func(t *testing.T, wire []byte, queryID uint16, zeroID bool) {
		message := new(dns.Msg)
		if err := message.Unpack(wire); err != nil {
			return
		}
		_ = validateResponse(message, "example.com", dns.TypeA, queryID, zeroID)
	})
}
