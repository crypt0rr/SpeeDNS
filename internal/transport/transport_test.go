package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/miekg/dns"
)

func TestUDPSessionRoundTrip(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stop := make(chan struct{})
	defer close(stop)
	go serveUDP(conn, stop)

	target := catalog.Target{Protocol: catalog.UDP, Address: "127.0.0.1", Spec: catalog.TransportSpec{Port: conn.LocalAddr().(*net.UDPAddr).Port}}
	factory, err := NewFactory(target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	response, err := session.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if ResponseClass(response) != "answer" {
		t.Fatalf("response class = %q", ResponseClass(response))
	}
}

func TestTCPSessionReusesConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stop := make(chan struct{})
	defer close(stop)
	go serveTCP(listener, stop)

	port := listener.Addr().(*net.TCPAddr).Port
	target := catalog.Target{Protocol: catalog.TCP, Address: "127.0.0.1", Spec: catalog.TransportSpec{Port: port}}
	factory, err := NewFactory(target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for index := 0; index < 2; index++ {
		if _, err := session.Query(context.Background(), "example.com", dns.TypeA); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecureQueriesUseRFCStylePaddingAndZeroID(t *testing.T) {
	query := newQuery("example.com", dns.TypeA, 0, true)
	packed, err := packQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if len(packed)%128 != 0 {
		t.Fatalf("padded query length = %d, want a 128-byte boundary", len(packed))
	}
	decoded := new(dns.Msg)
	if err := decoded.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if decoded.Id != 0 {
		t.Fatalf("secure query ID = %d, want zero", decoded.Id)
	}
}

func TestValidateResponseRejectsMismatchedQuestion(t *testing.T) {
	query := newQuery("example.com", dns.TypeA, 123, false)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Question[0].Name = "other.example."
	if err := validateResponse(response, "example.com", dns.TypeA, 123, false); err == nil {
		t.Fatal("expected mismatched response question to fail validation")
	}
}

func serveUDP(conn *net.UDPConn, stop <-chan struct{}) {
	buffer := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, address, err := conn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			continue
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
		packed, _ := response.Pack()
		_, _ = conn.WriteToUDP(packed, address)
	}
}

func serveTCP(listener net.Listener, stop <-chan struct{}) {
	for {
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}
		go func() {
			defer conn.Close()
			for {
				var prefix [2]byte
				if _, err := io.ReadFull(conn, prefix[:]); err != nil {
					return
				}
				length := int(binary.BigEndian.Uint16(prefix[:]))
				request := make([]byte, length)
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				query := new(dns.Msg)
				if err := query.Unpack(request); err != nil {
					return
				}
				response := new(dns.Msg)
				response.SetReply(query)
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
				packed, _ := response.Pack()
				binary.BigEndian.PutUint16(prefix[:], uint16(len(packed)))
				if _, err := conn.Write(prefix[:]); err != nil {
					return
				}
				if _, err := conn.Write(packed); err != nil {
					return
				}
			}
		}()
	}
}

// TestDoTOffersTheALPNToken pins the ALPN token on DNS-over-TLS. RFC 7858
// registers "dot" and RFC 8310 says a client SHOULD offer it; DoQ and DoH
// already negotiate their own tokens, so DoT was the one transport that
// presented an unlabelled connection.
func TestDoTOffersTheALPNToken(t *testing.T) {
	factory, err := NewFactory(catalog.Target{
		Protocol: catalog.DoT, Address: "192.0.2.1",
		Spec: catalog.TransportSpec{Port: 853, ServerName: "dns.example"},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stream, ok := factory.(*streamFactory)
	if !ok {
		t.Fatalf("DoT factory type = %T", factory)
	}
	if got := stream.tlsConfig.NextProtos; len(got) != 1 || got[0] != "dot" {
		t.Fatalf("DoT NextProtos = %#v, want [dot]", got)
	}
	if stream.tlsConfig.ServerName != "dns.example" {
		t.Fatalf("DoT ServerName = %q", stream.tlsConfig.ServerName)
	}
}

// TestUDPFactoryResolvesHostnameOnce covers the bootstrap lookup moving out of
// the measured exchange. dns.Client.ExchangeContext dials whatever address it
// is handed, so a hostname endpoint previously went through the system
// resolver on every query, inside the timed region.
func TestUDPFactoryResolvesHostnameOnce(t *testing.T) {
	oldResolve := resolveUDPAddress
	t.Cleanup(func() { resolveUDPAddress = oldResolve })
	lookups := 0
	resolveUDPAddress = func(context.Context, string) (string, error) {
		lookups++
		return "192.0.2.53", nil
	}
	factory, err := NewFactory(catalog.Target{
		Protocol: catalog.UDP, Address: "dns.example", Spec: catalog.TransportSpec{Port: 53},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 {
		t.Fatalf("lookups during Open = %d, want 1", lookups)
	}
	dialer, ok := session.(interface{ DialAddress() string })
	if !ok {
		t.Fatal("UDP session does not report a dial address")
	}
	if got := dialer.DialAddress(); got != "192.0.2.53:53" {
		t.Fatalf("UDP dial address = %q, want %q", got, "192.0.2.53:53")
	}

	// A literal endpoint must not consult the resolver at all.
	lookups = 0
	literal, err := NewFactory(catalog.Target{
		Protocol: catalog.UDP, Address: "192.0.2.1", Spec: catalog.TransportSpec{Port: 53},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := literal.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lookups != 0 {
		t.Fatalf("lookups for a literal endpoint = %d, want 0", lookups)
	}
}

// TestUDPFactoryReportsResolutionFailure keeps a failed bootstrap lookup a
// session-open error rather than a per-query mystery.
func TestUDPFactoryReportsResolutionFailure(t *testing.T) {
	oldResolve := resolveUDPAddress
	t.Cleanup(func() { resolveUDPAddress = oldResolve })
	resolveUDPAddress = func(context.Context, string) (string, error) {
		return "", errors.New("no such host")
	}
	factory, err := NewFactory(catalog.Target{
		Protocol: catalog.UDP, Address: "dns.example", Spec: catalog.TransportSpec{Port: 53},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Open(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "resolve UDP endpoint") {
		t.Fatalf("UDP resolution error = %v", err)
	}
}

// TestResponseClassSeparatesAnswersFromNodata pins the distinction the
// divergence engine depends on. A canonical NODATA response carries an SOA in
// the authority section, so classifying on answer-or-authority presence made
// "no such record" indistinguishable from a real answer.
func TestResponseClassSeparatesAnswersFromNodata(t *testing.T) {
	message := func(rcode int, qtype uint16, answer []dns.RR, authority []dns.RR) *dns.Msg {
		return &dns.Msg{
			MsgHdr:   dns.MsgHdr{Rcode: rcode, Response: true},
			Question: []dns.Question{{Name: "example.com.", Qtype: qtype, Qclass: dns.ClassINET}},
			Answer:   answer,
			Ns:       authority,
		}
	}
	aRecord := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}}
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME}}

	cases := []struct {
		name    string
		message *dns.Msg
		want    string
	}{
		{"answer for the requested type", message(dns.RcodeSuccess, dns.TypeA, []dns.RR{aRecord}, nil), "answer"},
		{"canonical nodata with an SOA", message(dns.RcodeSuccess, dns.TypeAAAA, nil, []dns.RR{soa}), "nodata"},
		{"bare nodata", message(dns.RcodeSuccess, dns.TypeAAAA, nil, nil), "nodata"},
		{"chain without the requested type", message(dns.RcodeSuccess, dns.TypeAAAA, []dns.RR{cname}, []dns.RR{soa}), "nodata"},
		{"chain completed to the requested type", message(dns.RcodeSuccess, dns.TypeA, []dns.RR{cname, aRecord}, nil), "answer"},
		{"nxdomain", message(dns.RcodeNameError, dns.TypeA, nil, []dns.RR{soa}), "nxdomain"},
		{"servfail", message(dns.RcodeServerFailure, dns.TypeA, nil, nil), "rcode-2"},
	}
	for _, tc := range cases {
		if got := ResponseClass(tc.message); got != tc.want {
			t.Fatalf("ResponseClass(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}

	// validateResponse rejects other question shapes before scoring, so the
	// fallback is defensive only; keep it pinned so it stays predictable.
	malformed := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, Response: true}}
	if got := ResponseClass(malformed); got != "nodata" {
		t.Fatalf("ResponseClass(no question, no answer) = %q, want %q", got, "nodata")
	}
	malformed.Answer = []dns.RR{aRecord}
	if got := ResponseClass(malformed); got != "answer" {
		t.Fatalf("ResponseClass(no question, one answer) = %q, want %q", got, "answer")
	}
}
