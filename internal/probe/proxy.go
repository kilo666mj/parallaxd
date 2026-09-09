package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"golang.org/x/net/proxy"
)

// ProxyProfile belongs only to the prober. The coordinator sees its name and
// egress identity, never its endpoint or credentials. DNS is always local:
// the proxy receives validated numeric destinations, never target hostnames.
type ProxyProfile struct {
	URL             string `json:"url"`
	Egress          string `json:"egress"`
	CredentialsFile string `json:"credentials_file,omitempty"`
	CAFile          string `json:"ca_file,omitempty"`
}

func (p ProxyProfile) endpoint() (*url.URL, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") ||
		(u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return nil, errors.New("proxy URL must be http, https, or socks5 with no credentials, path, query, or fragment")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080"}[u.Scheme]
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid proxy port")
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	u.Path = ""
	return u, nil
}

// ValidateProxyProfiles catches local deployment mistakes before listeners start.
// Credential contents are read per probe to support rotation without a restart.
func ValidateProxyProfiles(profiles map[string]ProxyProfile) error {
	for name, p := range profiles {
		if !check.ValidRouteID(name) || !check.ValidRouteID(p.Egress) {
			return errors.New("proxy profiles require valid names and egress identifiers")
		}
		if _, err := p.endpoint(); err != nil {
			return fmt.Errorf("proxy profile %q: %w", name, err)
		}
		if p.CredentialsFile != "" && !filepath.IsAbs(p.CredentialsFile) {
			return fmt.Errorf("proxy profile %q: credentials_file must be absolute", name)
		}
		if p.CAFile != "" && (!strings.HasPrefix(p.URL, "https://") || !strings.HasPrefix(filepath.Clean(p.CAFile), customCARoot+"/")) {
			return fmt.Errorf("proxy profile %q: ca_file requires an HTTPS proxy and a path under /etc/parallaxd/ca", name)
		}
	}
	return nil
}

// proxyFailure never includes endpoint URLs, upstream text, or credential data.
// Failure to establish a usable proxy path is not evidence against the target.
type proxyFailure struct{ stage string }

func (e *proxyFailure) Error() string { return "proxy " + e.stage + " failed" }

type proxyTransport struct {
	endpoint    *url.URL
	policy      Policy
	vantage     check.Vantage
	credentials *proxy.Auth
	proxyTLS    *tls.Config
	tunnel      *http.Transport
	established atomic.Bool
}

func newProxyTransport(p ProxyProfile, policy Policy, vantage check.Vantage, targetRoots *x509.CertPool) (*proxyTransport, error) {
	u, err := p.endpoint()
	if err != nil {
		return nil, &proxyFailure{"configuration"}
	}
	t := &proxyTransport{endpoint: u, policy: policy, vantage: vantage}
	if p.CredentialsFile != "" {
		f, err := os.Open(p.CredentialsFile)
		if err != nil {
			return nil, &proxyFailure{"credentials"}
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, 4097))
		closeErr := f.Close()
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if readErr != nil || closeErr != nil || len(raw) > 4096 || json.Unmarshal(raw, &credentials) != nil ||
			credentials.Username == "" || credentials.Password == "" ||
			(u.Scheme == "socks5" && (len(credentials.Username) > 255 || len(credentials.Password) > 255)) ||
			strings.Contains(credentials.Username, ":") {
			return nil, &proxyFailure{"credentials"}
		}
		t.credentials = &proxy.Auth{User: credentials.Username, Password: credentials.Password}
	}
	roots, err := rootsForCheck(p.CAFile, nil)
	if err != nil {
		return nil, &proxyFailure{"TLS configuration"}
	}
	t.proxyTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname()}
	t.tunnel = &http.Transport{
		DialContext: t.dialTarget, ForceAttemptHTTP2: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: targetRoots},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true,
	}
	return t, nil
}

func (t *proxyTransport) addresses(ctx context.Context, address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &proxyFailure{"destination configuration"}
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, &proxyFailure{"destination DNS"}
	}
	if len(ips) == 0 {
		return nil, &proxyFailure{"destination DNS"}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if err := t.policy.allows(t.vantage, ip); err != nil {
			return nil, err
		}
		out = append(out, net.JoinHostPort(ip.String(), port))
	}
	return out, nil
}

func (t *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, &proxyFailure{"destination scheme"}
	}
	req = req.Clone(req.Context())
	req.Header.Del("Proxy-Authorization")
	// net/http detaches dial cancellation to permit connection reuse. These
	// one-shot probes must instead stop proxy negotiation with the request.
	t.established.Store(false)
	transport := t.tunnel.Clone()
	transport.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		conn, err := t.dialTarget(req.Context(), network, address)
		if err == nil {
			t.established.Store(true)
		}
		return conn, err
	}
	defer transport.CloseIdleConnections()
	return transport.RoundTrip(req)
}

func (t *proxyTransport) authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(t.credentials.User+":"+t.credentials.Password))
}

func (t *proxyTransport) dialTarget(ctx context.Context, _, address string) (net.Conn, error) {
	addresses, err := t.addresses(ctx, address)
	if err != nil {
		return nil, err
	}
	for _, destination := range addresses {
		var conn net.Conn
		if t.endpoint.Scheme == "socks5" {
			// The endpoint is explicitly granted by the local profile, not by
			// monitor target policy. Permanent metadata/link-local blocks remain.
			d, dialErr := proxy.SOCKS5("tcp", t.endpoint.Host, t.credentials, guardedDialer(check.VantageInternal, Policy{}, nil))
			if dialErr != nil {
				return nil, &proxyFailure{"SOCKS configuration"}
			}
			conn, err = d.(proxy.ContextDialer).DialContext(ctx, "tcp", destination)
		} else {
			conn, err = t.connect(ctx, destination)
		}
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, &proxyFailure{"tunnel establishment"}
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (t *proxyTransport) connect(ctx context.Context, destination string) (_ net.Conn, err error) {
	conn, err := guardedDialer(check.VantageInternal, Policy{}, nil).DialContext(ctx, "tcp", t.endpoint.Host)
	if err != nil {
		return nil, &proxyFailure{"connection"}
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if deadline, has := ctx.Deadline(); has {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, &proxyFailure{"deadline setup"}
		}
	}
	if t.endpoint.Scheme == "https" {
		tlsConn := tls.Client(conn, t.proxyTLS)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, &proxyFailure{"TLS handshake"}
		}
		conn = tlsConn
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: destination}, Host: destination, Header: make(http.Header)}
	if t.credentials != nil {
		request.Header.Set("Proxy-Authorization", t.authorization())
	}
	if err := request.Write(conn); err != nil {
		return nil, &proxyFailure{"CONNECT request"}
	}
	limited := &io.LimitedReader{R: conn, N: 32 << 10}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, &proxyFailure{"CONNECT response"}
	}
	limited.N = 1<<63 - 1 // subsequent tunneled bytes are not HTTP proxy headers
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, &proxyFailure{"deadline setup"}
	}
	if !stop() && ctx.Err() != nil {
		return nil, &proxyFailure{"cancellation"}
	}
	ok = true
	return &bufferedProxyConn{Conn: conn, reader: reader}, nil
}
