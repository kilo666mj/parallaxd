package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/smtp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type DNS struct {
	Policy   Policy
	Resolver *net.Resolver
}

func (DNS) Kind() check.Kind { return check.KindDNS }
func (d DNS) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	record := c.DNSRecord
	if record == "" {
		record = "A"
	}
	start := time.Now()
	var values []string
	var err error
	switch record {
	case "A", "AAAA":
		var ips []net.IPAddr
		ips, err = r.LookupIPAddr(ctx, c.Target)
		for _, ip := range ips {
			addr, ok := netipAddr(ip.IP)
			if !ok {
				continue
			}
			if record == "A" && !addr.Is4() || record == "AAAA" && !addr.Is6() {
				continue
			}
			if guardErr := d.Policy.allows(c.Vantage, addr.Unmap()); guardErr != nil {
				return check.StatusUnknown, 0, guardErr.Error()
			}
			values = append(values, addr.String())
		}
	case "MX":
		var mx []*net.MX
		mx, err = r.LookupMX(ctx, c.Target)
		for _, v := range mx {
			values = append(values, fmt.Sprintf("%d %s", v.Pref, strings.TrimSuffix(v.Host, ".")))
		}
	case "TXT":
		values, err = r.LookupTXT(ctx, c.Target)
	}
	latency := time.Since(start)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	sort.Strings(values)
	joined := strings.Join(values, "\n")
	if len(values) == 0 {
		return check.StatusDown, latency, "DNS response contained no requested records"
	}
	if c.ExpectBody != "" && !strings.Contains(joined, c.ExpectBody) {
		return check.StatusDown, latency, fmt.Sprintf("DNS response %q does not contain %q", joined, c.ExpectBody)
	}
	return check.StatusUp, latency, joined
}

func netipAddr(ip net.IP) (netip.Addr, bool) { return netip.AddrFromSlice(ip) }

type TLS struct {
	Policy Policy
	Dialer *net.Dialer
	// RootCAs is nil in production, which uses the host trust store. Tests and
	// embedded callers may provide a private trust root for local fixtures.
	RootCAs *x509.CertPool
}

func (TLS) Kind() check.Kind { return check.KindTLS }
func (t TLS) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	host, _, err := net.SplitHostPort(c.Target)
	if err != nil {
		return check.StatusUnknown, 0, fmt.Sprintf("invalid TLS target: %v", err)
	}
	name := c.ServerName
	if name == "" {
		name = host
	}
	start := time.Now()
	conn, err := guardedDialer(c.Vantage, t.Policy, t.Dialer).DialContext(ctx, "tcp", c.Target)
	if err != nil {
		s, d := classify(err)
		return s, 0, d
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: t.RootCAs})
	if err := tc.HandshakeContext(ctx); err != nil {
		return check.StatusDown, time.Since(start), fmt.Sprintf("TLS handshake: %v", err)
	}
	state := tc.ConnectionState()
	peer := state.PeerCertificates[0]
	detail := fmt.Sprintf("TLS %x; %s; expires %s", state.Version, peer.Subject.CommonName, peer.NotAfter.UTC().Format(time.RFC3339))
	if c.TLSExpiryWarning > 0 {
		remaining := time.Until(peer.NotAfter)
		if remaining <= c.TLSExpiryWarning {
			return check.StatusDown, time.Since(start), fmt.Sprintf("%s; certificate expires in %s (warning threshold %s)", detail, remaining.Round(time.Minute), c.TLSExpiryWarning)
		}
	}
	if c.ExpectBody != "" && !strings.Contains(detail, c.ExpectBody) {
		return check.StatusDown, time.Since(start), fmt.Sprintf("TLS peer %q does not contain %q", detail, c.ExpectBody)
	}
	return check.StatusUp, time.Since(start), detail
}

type SMTP struct {
	Policy Policy
	Dialer *net.Dialer
	// RootCAs has the same trust semantics as TLS.RootCAs.
	RootCAs *x509.CertPool
}

func (SMTP) Kind() check.Kind { return check.KindSMTP }
func (s SMTP) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	host, _, err := net.SplitHostPort(c.Target)
	if err != nil {
		return check.StatusUnknown, 0, fmt.Sprintf("invalid SMTP target: %v", err)
	}
	name := c.ServerName
	if name == "" {
		name = host
	}
	start := time.Now()
	conn, err := guardedDialer(c.Vantage, s.Policy, s.Dialer).DialContext(ctx, "tcp", c.Target)
	if err != nil {
		st, d := classify(err)
		return st, 0, d
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, name)
	if err != nil {
		conn.Close()
		return check.StatusDown, time.Since(start), fmt.Sprintf("SMTP greeting: %v", err)
	}
	defer client.Close()
	if err := client.Hello("parallaxd.local"); err != nil {
		return check.StatusDown, time.Since(start), fmt.Sprintf("SMTP EHLO: %v", err)
	}
	if c.StartTLS {
		if err := client.StartTLS(&tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs}); err != nil {
			return check.StatusDown, time.Since(start), fmt.Sprintf("SMTP STARTTLS: %v", err)
		}
	}
	if err := client.Noop(); err != nil {
		return check.StatusDown, time.Since(start), fmt.Sprintf("SMTP NOOP: %v", err)
	}
	client.Quit()
	return check.StatusUp, time.Since(start), "SMTP greeting, EHLO and NOOP succeeded"
}

var icmpSequence atomic.Uint32

const icmpPayload = "parallaxd"

type ICMP struct {
	Policy   Policy
	Resolver *net.Resolver
}

func (ICMP) Kind() check.Kind { return check.KindICMP }
func (p ICMP) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	r := p.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupIPAddr(ctx, c.Target)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	var selected net.IP
	for _, candidate := range ips {
		addr, ok := netipAddr(candidate.IP)
		if !ok || p.Policy.allows(c.Vantage, addr.Unmap()) != nil {
			continue
		}
		selected = candidate.IP
		break
	}
	if selected == nil {
		return check.StatusUnknown, 0, "no resolved address is permitted by this prober"
	}

	network, bind, protocol := "udp4", "0.0.0.0", 1
	var echo, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if selected.To4() == nil {
		network, bind, protocol = "udp6", "::", 58
		echo, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	conn, err := icmp.ListenPacket(network, bind)
	if err != nil {
		return check.StatusUnknown, 0, fmt.Sprintf("open ICMP socket: %v", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	seq := int(icmpSequence.Add(1) & 0xffff)
	msg := icmp.Message{Type: echo, Body: &icmp.Echo{Seq: seq, Data: []byte(icmpPayload)}}
	raw, err := msg.Marshal(nil)
	if err != nil {
		return check.StatusUnknown, 0, err.Error()
	}
	start := time.Now()
	if _, err := conn.WriteTo(raw, &net.UDPAddr{IP: selected}); err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			status, detail := classify(err)
			return status, 0, detail
		}
		parsed, err := icmp.ParseMessage(protocol, buf[:n])
		if err != nil {
			continue
		}
		if matchesICMPEchoReply(parsed, reply, seq) {
			return check.StatusUp, time.Since(start), fmt.Sprintf("ICMP reply from %s", peer)
		}
	}
}

func matchesICMPEchoReply(parsed *icmp.Message, reply icmp.Type, seq int) bool {
	body, ok := parsed.Body.(*icmp.Echo)
	// Linux ping sockets replace the caller's echo ID with a socket-specific
	// value. Each probe owns its socket, so sequence plus payload identify the
	// response without rejecting the kernel-rewritten ID.
	return parsed.Type == reply && ok && body.Seq == seq && string(body.Data) == icmpPayload
}
