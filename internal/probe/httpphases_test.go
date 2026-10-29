package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func stalledCheck(target string) check.Check {
	c := httpCheck(target)
	c.Timeout = 300 * time.Millisecond
	return c
}

func assertStalledIn(t *testing.T, r check.Result, phase string) {
	t.Helper()
	t.Logf("detail: %s", r.Detail)
	if r.Status != check.StatusDown {
		t.Fatalf("status = %q (%s), want down", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "during "+phase+" to 127.0.0.1:") {
		t.Errorf("detail = %q, want it to name the %s phase and the address", r.Detail, phase)
	}
}

func TestHTTPTimeoutWaitingForResponseNamesThePhase(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	r := Run(t.Context(), HTTP{}, stalledCheck(srv.URL), "probe-a", "")
	assertStalledIn(t, r, "waiting for response")
	if !strings.Contains(r.Detail, "connect ") {
		t.Errorf("detail = %q, want the completed connect timing", r.Detail)
	}
}

func TestHTTPTimeoutInTLSNamesThePhase(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		// Accept and say nothing, so the handshake never completes.
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	r := Run(t.Context(), HTTP{}, stalledCheck("https://"+ln.Addr().String()+"/"), "probe-a", "")
	assertStalledIn(t, r, "tls")
}

func TestHTTPTimeoutInConnectNamesThePhase(t *testing.T) {
	// A dial that never completes, standing in for a path that drops SYNs.
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if trace := httptrace.ContextClientTrace(ctx); trace != nil && trace.ConnectStart != nil {
				trace.ConnectStart(network, addr)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}}

	r := Run(t.Context(), HTTP{Client: client}, stalledCheck("http://127.0.0.1:9/"), "probe-a", "")
	assertStalledIn(t, r, "connect")
}

func TestHTTPRefusalStillReportsTheOriginalError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	r := Run(t.Context(), HTTP{}, httpCheck("http://"+addr+"/"), "probe-a", "")
	if r.Status != check.StatusDown || !strings.HasPrefix(r.Detail, "connect: connection refused (during connect to "+addr) {
		t.Errorf("status = %q, detail = %q", r.Status, r.Detail)
	}
}
