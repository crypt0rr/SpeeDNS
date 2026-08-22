package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
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
	query := newQuery("example.com", dns.TypeA, 0, true, QueryOptions{})
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
	query := newQuery("example.com", dns.TypeA, 123, false, QueryOptions{})
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
