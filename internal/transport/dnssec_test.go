package transport

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
)

// legacyQuery rebuilds the query form SpeeDNS shipped before DNSSEC probing
// existed. A default run must keep producing exactly these bytes so results
// stay comparable with previously published reports.
func legacyQuery(name string, qtype, id uint16, padded bool) *dns.Msg {
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               id,
			RecursionDesired: true,
			Opcode:           dns.OpcodeQuery,
		},
		Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}},
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}
	if padded {
		opt.Option = []dns.EDNS0{&dns.EDNS0_PADDING{}}
	}
	query.Extra = []dns.RR{opt}
	return query
}

func TestDefaultQueriesStayByteIdenticalWithoutDNSSEC(t *testing.T) {
	for _, padded := range []bool{false, true} {
		current, err := packQuery(newQuery("example.com", dns.TypeA, 4242, padded, QueryOptions{}))
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := packQuery(legacyQuery("example.com", dns.TypeA, 4242, padded))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(current, legacy) {
			t.Fatalf("padded=%v default query changed:\n got %x\nwant %x", padded, current, legacy)
		}
	}
	if newQuery("example.com", dns.TypeA, 1, false, QueryOptions{}).IsEdns0().Do() {
		t.Fatal("default query set the DO bit")
	}
}

func TestDNSSECOptionSetsOnlyTheDOBit(t *testing.T) {
	plain := newQuery("example.com", dns.TypeA, 4242, false, QueryOptions{})
	signed := newQuery("example.com", dns.TypeA, 4242, false, QueryOptions{DNSSEC: true})
	if !signed.IsEdns0().Do() {
		t.Fatal("DNSSEC query did not set the DO bit")
	}
	if signed.CheckingDisabled || plain.CheckingDisabled {
		t.Fatal("SpeeDNS must never set the CD bit")
	}
	signedBytes, err := packQuery(signed)
	if err != nil {
		t.Fatal(err)
	}
	plainBytes, err := packQuery(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(signedBytes, plainBytes) {
		t.Fatal("DNSSEC query is identical to the default query")
	}
	signed.IsEdns0().SetDo(false)
	clearedBytes, err := packQuery(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clearedBytes, plainBytes) {
		t.Fatalf("DNSSEC query differs beyond the DO bit:\n got %x\nwant %x", clearedBytes, plainBytes)
	}
}

func TestPaddedDNSSECQueriesKeepPaddingPolicy(t *testing.T) {
	packed, err := packQuery(newQuery("example.com", dns.TypeA, 0, true, QueryOptions{DNSSEC: true}))
	if err != nil {
		t.Fatal(err)
	}
	if len(packed)%128 != 0 {
		t.Fatalf("padded DNSSEC query length = %d, want a 128-byte boundary", len(packed))
	}
}

func TestFactoriesCarryQueryOptionsToEverySession(t *testing.T) {
	options := QueryOptions{DNSSEC: true}
	cases := []struct {
		protocol catalog.Protocol
		read     func(Factory) QueryOptions
	}{
		{catalog.UDP, func(f Factory) QueryOptions { return f.(*udpFactory).queryOptions }},
		{catalog.TCP, func(f Factory) QueryOptions { return f.(*streamFactory).queryOptions }},
		{catalog.DoT, func(f Factory) QueryOptions { return f.(*streamFactory).queryOptions }},
		{catalog.DoH, func(f Factory) QueryOptions { return f.(*doHFactory).queryOptions }},
		{catalog.DoQ, func(f Factory) QueryOptions { return f.(*doqFactory).queryOptions }},
	}
	for _, tc := range cases {
		target := catalog.Target{
			Protocol: tc.protocol, Address: "192.0.2.1",
			Spec: catalog.TransportSpec{Port: 53, URL: "https://dns.example/dns-query", ServerName: "dns.example"},
		}
		factory, err := NewFactoryWithOptions(target, time.Second, options)
		if err != nil {
			t.Fatalf("%s: %v", tc.protocol, err)
		}
		if got := tc.read(factory); got != options {
			t.Fatalf("%s factory query options = %+v, want %+v", tc.protocol, got, options)
		}
		defaultFactory, err := NewFactory(target, time.Second)
		if err != nil {
			t.Fatalf("%s: %v", tc.protocol, err)
		}
		if got := tc.read(defaultFactory); got != (QueryOptions{}) {
			t.Fatalf("%s default factory query options = %+v, want zero", tc.protocol, got)
		}
	}
	opened, err := (&udpFactory{address: "192.0.2.1:53", timeout: time.Second, queryOptions: options}).Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if opened.(*udpSession).queryOptions != options {
		t.Fatal("UDP session did not inherit the factory query options")
	}
}

func TestStreamSessionSendsDOBitOnTheWire(t *testing.T) {
	conn := newScriptedStreamConn()
	session := &streamSession{conn: conn, timeout: time.Second, queryOptions: QueryOptions{DNSSEC: true}}
	if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	sent := new(dns.Msg)
	if err := sent.Unpack(conn.lastWrite); err != nil {
		t.Fatal(err)
	}
	opt := sent.IsEdns0()
	if opt == nil || !opt.Do() {
		t.Fatalf("stream query did not carry the DO bit: %v", sent)
	}
}
