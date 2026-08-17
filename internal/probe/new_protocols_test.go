package probe

import (
	"net"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
)

func TestRequestMatchesChunkedResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		conn.Read(buf)
		conn.Write([]byte("+PO"))
		time.Sleep(5 * time.Millisecond)
		conn.Write([]byte("NG\r\n"))
	}()
	c := testCheck(check.KindRequest, listener.Addr().String())
	c.Send, c.ExpectBody = "PING", "+PONG"
	status, _, detail := (Request{}).Probe(t.Context(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
}

func TestDNSQueriesExplicitServer(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 512)
		n, peer, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if query.Unpack(buf[:n]) != nil || len(query.Questions) != 1 {
			return
		}
		answer := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, Authoritative: true},
			Questions: query.Questions,
			Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}}}},
		}
		raw, _ := answer.Pack()
		server.WriteTo(raw, peer)
	}()
	c := testCheck(check.KindDNS, "fixture.example")
	c.DNSServer, c.DNSRecord, c.ExpectBody = server.LocalAddr().String(), "A", "192.0.2.42"
	status, _, detail := (DNS{}).Probe(t.Context(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
}

func TestNTPValidatesServerReply(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		request := make([]byte, 48)
		n, peer, err := server.ReadFrom(request)
		if err != nil || n < 48 {
			return
		}
		response := make([]byte, 48)
		response[0], response[1] = 0x24, 2
		copy(response[24:32], request[40:48])
		server.WriteTo(response, peer)
	}()
	c := testCheck(check.KindNTP, server.LocalAddr().String())
	status, _, detail := (NTP{}).Probe(t.Context(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
}

func TestGRPCHealthServing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("fixture.Service", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)
	go server.Serve(listener)
	defer server.Stop()
	c := testCheck(check.KindGRPC, listener.Addr().String())
	c.GRPCService = "fixture.Service"
	status, _, detail := (GRPC{}).Probe(t.Context(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
}

func TestGRPCGuardedTargetIsUnknown(t *testing.T) {
	c := testCheck(check.KindGRPC, "127.0.0.1:443")
	c.Vantage = check.VantagePublic
	result := Run(t.Context(), GRPC{}, c, "probe-a", "provider-a")
	if result.Status != check.StatusUnknown {
		t.Fatalf("status=%s detail=%q, want unknown", result.Status, result.Detail)
	}
}
