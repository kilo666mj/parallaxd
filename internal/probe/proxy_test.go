package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func proxyCheck(target string) check.Check {
	return check.Check{Name: "proxy-test", Kind: check.KindHTTP, Target: target, Vantage: check.VantageInternal,
		Interval: time.Minute, Timeout: time.Second, Quorum: check.Quorum{Agree: 1, Of: 1}, ProxyProfile: "egress"}
}

func relayProxy(client net.Conn, upstream net.Conn) {
	defer func() { _ = client.Close(); _ = upstream.Close() }()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(client, upstream); _ = client.Close(); close(done) }()
	_, _ = io.Copy(upstream, client)
	_ = upstream.Close()
	<-done
}

func connectProxy(t *testing.T, secure bool, targetAddress string, seen *atomic.Int64) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.Method != http.MethodConnect {
			t.Errorf("method %s", r.Method)
			w.WriteHeader(400)
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || net.ParseIP(host) == nil {
			t.Errorf("proxy received hostname: %q", r.Host)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			w.WriteHeader(407)
			return
		}
		upstream, err := net.DialTimeout("tcp", targetAddress, time.Second)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = conn.Close()
			_ = upstream.Close()
			return
		}
		if err = buffer.Flush(); err != nil {
			_ = conn.Close()
			_ = upstream.Close()
			return
		}
		relayProxy(conn, upstream)
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server
}

func proxyCredentials(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(p, []byte(`{"username":"user","password":"pass"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProxyCONNECTPreservesTargetHostTLSAndCredentials(t *testing.T) {
	for _, secureProxy := range []bool{false, true} {
		for _, secureTarget := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "HTTP-proxy", true: "HTTPS-proxy"}[secureProxy], map[bool]string{false: "HTTP-target", true: "HTTPS-target"}[secureTarget]}, "/"), func(t *testing.T) {
				cert, roots := localCertificate(t)
				target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !strings.HasPrefix(r.Host, "localhost:") {
						t.Errorf("lost Host: %q", r.Host)
					}
					if secureTarget && r.TLS.ServerName != "localhost" {
						t.Errorf("lost SNI: %q", r.TLS.ServerName)
					}
					if r.Header.Get("Proxy-Authorization") != "" {
						t.Error("proxy credentials reached target")
					}
					_, _ = io.WriteString(w, "healthy")
				}))
				if secureTarget {
					target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
					target.StartTLS()
				} else {
					target.Start()
				}
				t.Cleanup(target.Close)
				var seen atomic.Int64
				server := connectProxy(t, secureProxy, target.Listener.Addr().String(), &seen)
				profile := ProxyProfile{URL: server.URL, Egress: "exit-a", CredentialsFile: proxyCredentials(t)}
				transport, err := newProxyTransport(profile, Policy{}, check.VantageInternal, roots)
				if err != nil {
					t.Fatal(err)
				}
				if secureProxy {
					transport.proxyTLS.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
				}
				u, err := url.Parse(target.URL)
				if err != nil {
					t.Fatal(err)
				}
				u.Host = net.JoinHostPort("localhost", u.Port())
				client := &http.Client{Transport: transport, Timeout: time.Second}
				response, err := client.Get(u.String())
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "healthy" || seen.Load() == 0 {
					t.Fatalf("response %q, %v", body, err)
				}
			})
		}
	}
}

func TestProxyMissingBlockedFailedAndRedirectedRoutes(t *testing.T) {
	var seen atomic.Int64
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		w.WriteHeader(407)
		_, _ = io.WriteString(w, "password=private-token")
	}))
	defer proxyServer.Close()
	p := HTTP{ProxyProfiles: map[string]ProxyProfile{"egress": {URL: proxyServer.URL, Egress: "a"}}}
	for _, target := range []string{"http://169.254.169.254/latest/meta-data", "http://[::ffff:169.254.169.254]/"} {
		status, _, detail := p.Probe(context.Background(), proxyCheck(target))
		if status != check.StatusUnknown || seen.Load() != 0 {
			t.Fatalf("blocked %s: %s %s, contacted proxy %d", target, status, detail, seen.Load())
		}
	}
	c := proxyCheck("http://127.0.0.1:12345/")
	c.ProxyProfile = "missing"
	if status, _, _ := p.Probe(context.Background(), c); status != check.StatusUnknown {
		t.Fatal(status)
	}
	c.ProxyProfile = "egress"
	status, _, detail := p.Probe(context.Background(), c)
	if status != check.StatusUnknown || strings.Contains(detail, "private-token") || strings.Contains(detail, proxyServer.URL) {
		t.Fatalf("auth failure leaked/misclassified: %s %q", status, detail)
	}
	seen.Store(0)
	c.Vantage = check.VantagePublic
	if status, _, _ := p.Probe(context.Background(), c); status != check.StatusUnknown || seen.Load() != 0 {
		t.Fatal("public target escaped policy")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer target.Close()
	var tunnels atomic.Int64
	server := connectProxy(t, false, target.Listener.Addr().String(), &tunnels)
	p = HTTP{ProxyProfiles: map[string]ProxyProfile{"egress": {URL: server.URL, Egress: "a", CredentialsFile: proxyCredentials(t)}}}
	status, _, _ = p.Probe(context.Background(), proxyCheck(target.URL))
	if status != check.StatusUnknown || tunnels.Load() != 1 {
		t.Fatalf("redirect bypassed guard: %s, tunnels=%d", status, tunnels.Load())
	}
}

func TestProxyHandshakeCancellationAndTLSFailure(t *testing.T) {
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}))
	defer server.Close()
	p := HTTP{ProxyProfiles: map[string]ProxyProfile{"egress": {URL: server.URL, Egress: "a"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	status, _, _ := p.Probe(ctx, proxyCheck("http://127.0.0.1:1234"))
	if status != check.StatusUnknown || time.Since(start) > time.Second {
		t.Fatal("proxy handshake ignored budget")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake leaked connection")
	}
	tlsProxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted proxy accepted") }))
	defer tlsProxy.Close()
	p.ProxyProfiles["egress"] = ProxyProfile{URL: tlsProxy.URL, Egress: "a"}
	status, _, _ = p.Probe(context.Background(), proxyCheck("https://127.0.0.1:1234"))
	if status != check.StatusUnknown {
		t.Fatalf("proxy TLS failure = %s", status)
	}
}

func TestSOCKS5AuthenticatesAndUsesNumericDestination(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "localhost:") {
			t.Errorf("lost Host: %s", r.Host)
		}
		_, _ = io.WriteString(w, "healthy")
	}))
	defer target.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		reader := bufio.NewReader(conn)
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(reader, greeting); err != nil {
			t.Error(err)
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(reader, methods); err != nil {
			t.Error(err)
			return
		}
		if _, err := conn.Write([]byte{5, 2}); err != nil {
			t.Error(err)
			return
		}
		auth := make([]byte, 2)
		if _, err := io.ReadFull(reader, auth); err != nil {
			t.Error(err)
			return
		}
		user := make([]byte, int(auth[1]))
		_, _ = io.ReadFull(reader, user)
		length, err := reader.ReadByte()
		if err != nil {
			t.Error(err)
			return
		}
		password := make([]byte, int(length))
		_, _ = io.ReadFull(reader, password)
		if string(user) != "user" || string(password) != "pass" {
			t.Error("SOCKS credentials incorrect")
			return
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			t.Error(err)
			return
		}
		header := make([]byte, 4)
		if _, err := io.ReadFull(reader, header); err != nil {
			t.Error(err)
			return
		}
		if header[0] != 5 || header[1] != 1 || (header[3] != 1 && header[3] != 4) {
			t.Errorf("SOCKS request: %v", header)
			return
		}
		addrLen := 4
		if header[3] == 4 {
			addrLen = 16
		}
		addr := make([]byte, addrLen+2)
		if _, err := io.ReadFull(reader, addr); err != nil {
			t.Error(err)
			return
		}
		if !net.IP(addr[:addrLen]).IsLoopback() || binary.BigEndian.Uint16(addr[addrLen:]) == 0 {
			t.Error("bad numeric destination")
			return
		}
		upstream, err := net.DialTimeout("tcp", target.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
			_ = upstream.Close()
			t.Error(err)
			return
		}
		relayProxy(conn, upstream)
	}()
	p := HTTP{ProxyProfiles: map[string]ProxyProfile{"egress": {URL: "socks5://" + listener.Addr().String(), Egress: "a", CredentialsFile: proxyCredentials(t)}}}
	u, _ := url.Parse(target.URL)
	u.Host = net.JoinHostPort("localhost", u.Port())
	c := proxyCheck(u.String())
	c.ExpectBody = "healthy"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status, _, detail := p.Probe(ctx, c)
	if status != check.StatusUp {
		t.Fatalf("SOCKS probe: %s %s", status, detail)
	}
	<-done
}

func TestProxyProfileValidationDoesNotEchoSecrets(t *testing.T) {
	for _, endpoint := range []string{"socks5h://proxy:1080", "http://user:secret@proxy:80", "http://proxy/?token=secret", "file:///etc/passwd", "http://proxy:0"} {
		err := ValidateProxyProfiles(map[string]ProxyProfile{"egress": {URL: endpoint, Egress: "a"}})
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe validation: %v", err)
		}
	}
}

func TestProxyTargetFailuresRemainDownAndPolicyStaysLocal(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted target accepted") }))
	defer target.Close()
	var seen atomic.Int64
	proxyServer := connectProxy(t, false, strings.TrimPrefix(target.URL, "https://"), &seen)
	defer proxyServer.Close()
	p := HTTP{ProxyProfiles: map[string]ProxyProfile{"egress": {URL: proxyServer.URL, Egress: "west", CredentialsFile: proxyCredentials(t)}}}
	status, _, _ := p.Probe(t.Context(), proxyCheck(target.URL))
	if status != check.StatusDown || seen.Load() != 1 {
		t.Fatalf("target TLS: %s, tunnels=%d", status, seen.Load())
	}
	p.Policy = Policy{RequireAllowForInternal: true}
	status, _, _ = p.Probe(t.Context(), proxyCheck(target.URL))
	if status != check.StatusUnknown || seen.Load() != 1 {
		t.Fatal("proxy bypassed required allowlist")
	}
	p.Policy.Allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	p.Policy.Deny = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	status, _, _ = p.Probe(t.Context(), proxyCheck(target.URL))
	if status != check.StatusUnknown || seen.Load() != 1 {
		t.Fatal("proxy bypassed target denylist")
	}
	p.Policy.Deny = nil
	status, _, _ = p.Probe(t.Context(), proxyCheck(target.URL))
	if status != check.StatusDown || seen.Load() != 2 {
		t.Fatal("allowlisted destination not contacted")
	}
}
