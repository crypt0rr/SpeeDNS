package benchmark

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/crypt0rr/SpeeDNS/internal/catalog"
	"github.com/crypt0rr/SpeeDNS/internal/transport"
	"github.com/miekg/dns"
)

// connectedSession describes its connection, as every transport session does.
type connectedSession struct {
	fakeSession
	connection transport.ConnectionInfo
}

func (s *connectedSession) Connection() transport.ConnectionInfo { return s.connection }

// TestRunRecordsTheWarmSessionConnection carries the peer and negotiated
// protocols from the warm session into the result, where the report reads
// them; a session that cannot describe its connection leaves them empty.
func TestRunRecordsTheWarmSessionConnection(t *testing.T) {
	oldFactory := newFactory
	t.Cleanup(func() { newFactory = oldFactory })
	useFairScheduler(t)
	want := transport.ConnectionInfo{RemoteAddress: "[2001:db8::1]:443", TLSVersion: "TLS 1.3", HTTPProtocol: "h2"}
	newFactory = func(catalog.Target, time.Duration, transport.QueryOptions) (transport.Factory, error) {
		return &scriptedFactory{open: func(int, context.Context) (transport.Session, error) {
			return &connectedSession{connection: want}, nil
		}}, nil
	}
	report, err := Run(context.Background(), []catalog.Target{testTarget(catalog.DoH, "192.0.2.1")}, validBenchmarkOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Targets[0].Connection; got != want {
		t.Fatalf("result connection = %#v, want %#v", got, want)
	}
	if got := sessionConnection(&fakeSession{}); got != (transport.ConnectionInfo{}) {
		t.Fatalf("session without connection metadata = %#v", got)
	}
}

// TestCalculateStatisticsIsTheEnginePath pins the exported helper to the
// function Run uses, so a fixture built with it describes what Run would have
// published for the same observations.
func TestCalculateStatisticsIsTheEnginePath(t *testing.T) {
	result := TargetResult{
		Target: testTarget(catalog.UDP, "192.0.2.1"),
		Observations: []Observation{
			{Name: "example.com", QType: dns.TypeA, Success: true, Usable: true, ResponseClass: "answer", LatencyMS: 12},
			{Name: "example.org", QType: dns.TypeA, Error: "timeout"},
		},
		Cold: []ColdObservation{{Name: "example.com", QType: dns.TypeA, Success: true, LatencyMS: 30}},
	}
	got := CalculateStatistics(result, time.Second, 42)
	if want := calculateStatistics(result, time.Second, 42); !reflect.DeepEqual(got, want) {
		t.Fatalf("CalculateStatistics = %#v, want %#v", got, want)
	}
	if got.Scored != 1 || got.Recommended {
		t.Fatalf("one scored sample must not be recommended: %#v", got)
	}
}
