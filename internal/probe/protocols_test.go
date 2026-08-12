package probe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func localCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return cert, pool
}

func testCheck(kind check.Kind, target string) check.Check {
	return check.Check{
		Name: "fixture", Kind: kind, Target: target, Vantage: check.VantageInternal,
		Interval: time.Minute, Timeout: 2 * time.Second, Quorum: check.Quorum{Agree: 1, Of: 1},
	}
}

func TestTLSFixtureValidatesTrustNameAndPeerDetail(t *testing.T) {
	cert, roots := localCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _ = conn.(*tls.Conn).Handshake() }()
		}
	}()

	c := testCheck(check.KindTLS, ln.Addr().String())
	c.ServerName = "localhost"
	status, _, detail := (TLS{RootCAs: roots}).Probe(t.Context(), c)
	if status != check.StatusUp || !strings.Contains(detail, "localhost") || !strings.Contains(detail, "expires") {
		t.Fatalf("valid TLS fixture: status=%s detail=%q", status, detail)
	}
	c.TLSExpiryWarning = 2 * time.Hour
	if status, _, detail := (TLS{RootCAs: roots}).Probe(t.Context(), c); status != check.StatusDown || !strings.Contains(detail, "warning threshold 2h0m0s") {
		t.Fatalf("expiry warning: status=%s detail=%q", status, detail)
	}
	c.TLSExpiryWarning = 0
	c.ServerName = "wrong.example"
	if status, _, detail := (TLS{RootCAs: roots}).Probe(t.Context(), c); status != check.StatusDown || !strings.Contains(detail, "certificate") {
		t.Fatalf("name mismatch: status=%s detail=%q", status, detail)
	}
}

func TestDNSFixtureReturnsAndMatchesARecord(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		for range 2 { // LookupIPAddr asks for A and AAAA.
			buf := make([]byte, 512)
			n, peer, err := conn.ReadFrom(buf)
			if err != nil || n < 12 {
				return
			}
			end := 12
			for end < n && buf[end] != 0 {
				end += int(buf[end]) + 1
			}
			end += 5 // root label plus QTYPE and QCLASS
			if end > n {
				return
			}
			response := append([]byte(nil), buf[:end]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			if binary.BigEndian.Uint16(buf[end-4:end-2]) == 1 {
				binary.BigEndian.PutUint16(response[6:8], 1)
				response = append(response,
					0xc0, 0x0c, // compressed owner name
					0x00, 0x01, 0x00, 0x01, // A, IN
					0x00, 0x00, 0x00, 0x3c, // 60-second TTL
					0x00, 0x04, 127, 0, 0, 1,
				)
			}
			_, _ = conn.WriteTo(response, peer)
		}
	}()

	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	c := testCheck(check.KindDNS, "fixture.test")
	c.DNSRecord = "A"
	c.ExpectBody = "127.0.0.1"
	status, _, detail := (DNS{Resolver: resolver}).Probe(t.Context(), c)
	if status != check.StatusUp || detail != "127.0.0.1" {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
}

func TestSMTPFixtureExercisesGreetingEHLOAndNOOP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	commands := make(chan string, 8)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "220 fixture ESMTP ready\r\n")
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			commands <- line
			switch {
			case strings.HasPrefix(line, "EHLO "):
				fmt.Fprint(conn, "250-fixture\r\n250 HELP\r\n")
			case line == "NOOP":
				fmt.Fprint(conn, "250 OK\r\n")
			case line == "QUIT":
				fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprint(conn, "500 unexpected\r\n")
			}
		}
	}()

	c := testCheck(check.KindSMTP, ln.Addr().String())
	status, _, detail := (SMTP{}).Probe(context.Background(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
	close(commands)
	var got []string
	for command := range commands {
		got = append(got, command)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"EHLO parallaxd.local", "NOOP", "QUIT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("commands %q do not contain %q", joined, want)
		}
	}
}

func TestSMTPFixtureExercisesSTARTTLS(t *testing.T) {
	cert, roots := localCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "220 fixture ESMTP ready\r\n")
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "EHLO ") {
			done <- fmt.Errorf("initial EHLO: %q: %w", line, err)
			return
		}
		fmt.Fprint(conn, "250-fixture\r\n250 STARTTLS\r\n")
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "STARTTLS" {
			done <- fmt.Errorf("STARTTLS: %q: %w", line, err)
			return
		}
		fmt.Fprint(conn, "220 begin TLS\r\n")
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			done <- err
			return
		}
		reader = bufio.NewReader(tlsConn)
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				fmt.Fprint(tlsConn, "250 fixture\r\n")
			case strings.TrimSpace(line) == "NOOP":
				fmt.Fprint(tlsConn, "250 OK\r\n")
			case strings.TrimSpace(line) == "QUIT":
				fmt.Fprint(tlsConn, "221 bye\r\n")
				done <- nil
				return
			default:
				done <- fmt.Errorf("unexpected command %q", line)
				return
			}
		}
	}()

	c := testCheck(check.KindSMTP, ln.Addr().String())
	c.StartTLS = true
	c.ServerName = "localhost"
	status, _, detail := (SMTP{RootCAs: roots}).Probe(context.Background(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%q", status, detail)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
