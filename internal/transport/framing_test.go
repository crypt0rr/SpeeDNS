package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func packedQuery(t *testing.T, name string, qtype, id uint16, padded bool) []byte {
	t.Helper()
	packed, err := packQuery(newQuery(name, qtype, id, padded, QueryOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

// The connection-oriented transports and DoQ share one framing implementation
// but keep their stream lifecycles: a reused TCP or DoT connection must stay
// writable, while DoQ closes the send side of its per-query stream.
func TestFramedStreamLifecycleDiffers(t *testing.T) {
	conn := newScriptedStreamConn()
	response, err := framedStream{stream: conn, label: "DNS"}.query(packedQuery(t, "example.com", dns.TypeA, 7, false), "example.com", dns.TypeA, 7, false)
	if err != nil {
		t.Fatal(err)
	}
	if response.Id != 7 {
		t.Fatalf("stream response ID = %d, want 7", response.Id)
	}
	if conn.closeCalls != 0 {
		t.Fatalf("stream framing closed the connection %d times", conn.closeCalls)
	}

	stream, _ := newFakeDoQStream()
	closes := 0
	closeSend := func() error {
		closes++
		return stream.Close()
	}
	response, err = framedStream{stream: stream, closeSend: closeSend, label: "DoQ"}.query(packedQuery(t, "example.com", dns.TypeA, 0, true), "example.com", dns.TypeA, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if response.Id != 0 {
		t.Fatalf("DoQ response ID = %d, want 0", response.Id)
	}
	if closes != 1 {
		t.Fatalf("DoQ framing closed the send side %d times, want 1", closes)
	}
}

func TestFramedStreamErrorsCarryTransportLabel(t *testing.T) {
	for _, label := range []string{"DNS", "DoQ"} {
		t.Run(label, func(t *testing.T) {
			empty := &fakeDoQStream{}
			empty.readBuf.Write([]byte{0, 0})
			_, err := framedStream{stream: empty, label: label}.query(packedQuery(t, "example.com", dns.TypeA, 0, false), "example.com", dns.TypeA, 0, false)
			if err == nil || err.Error() != "empty "+label+" response" {
				t.Fatalf("empty response error = %v", err)
			}

			malformed := &fakeDoQStream{}
			malformed.readBuf.Write([]byte{0, 1, 1})
			_, err = framedStream{stream: malformed, label: label}.query(packedQuery(t, "example.com", dns.TypeA, 0, false), "example.com", dns.TypeA, 0, false)
			if err == nil || !strings.HasPrefix(err.Error(), "unpack "+label+" response: ") {
				t.Fatalf("unpack error = %v", err)
			}
		})
	}

	failing := &fakeDoQStream{}
	closeSend := func() error { return errors.New("close send failed") }
	if _, err := (framedStream{stream: failing, closeSend: closeSend, label: "DoQ"}).query(packedQuery(t, "example.com", dns.TypeA, 0, true), "example.com", dns.TypeA, 0, true); err == nil {
		t.Fatal("expected close-send error")
	}
}

// Both session types must bound one query by the transport timeout, even when
// the caller deadline is further away. The deadline target differs (the reused
// connection versus the per-query DoQ stream); the computation must not.
func TestStreamAndDoQShareQueryDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	const timeout = 50 * time.Millisecond

	conn := newScriptedStreamConn()
	if _, err := (&streamSession{conn: conn, timeout: timeout}).Query(ctx, "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if len(conn.deadlines) != 1 {
		t.Fatalf("stream deadlines = %v", conn.deadlines)
	}
	if conn.deadlines[0].After(time.Now().Add(time.Minute)) {
		t.Fatalf("stream deadline %v ignored the %v timeout", conn.deadlines[0], timeout)
	}

	stream, doqConn := newFakeDoQStream()
	if _, err := (&doqSession{conn: doqConn, timeout: timeout}).Query(ctx, "example.com", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if len(stream.deadlines) != 1 {
		t.Fatalf("DoQ deadlines = %v", stream.deadlines)
	}
	if stream.deadlines[0].After(time.Now().Add(time.Minute)) {
		t.Fatalf("DoQ deadline %v ignored the %v timeout", stream.deadlines[0], timeout)
	}
}
