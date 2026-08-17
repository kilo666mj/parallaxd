package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/smtp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const ntpEpochOffset = 2208988800

type NTP struct {
	Policy Policy
	Dialer *net.Dialer
}

func (NTP) Kind() check.Kind { return check.KindNTP }

func (n NTP) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	target := c.Target
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "123")
	}
	conn, err := guardedDialer(c.Vantage, n.Policy, n.Dialer).DialContext(ctx, "udp", target)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	request := make([]byte, 48)
	request[0] = 0x23 // version 4, client mode
	now := time.Now()
	seconds := uint64(now.Unix() + ntpEpochOffset)
	fraction := (uint64(now.Nanosecond()) << 32) / 1_000_000_000
	binary.BigEndian.PutUint32(request[40:44], uint32(seconds))
	binary.BigEndian.PutUint32(request[44:48], uint32(fraction))
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	response := make([]byte, 512)
	read, err := conn.Read(response)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	if read < 48 {
		return check.StatusDown, time.Since(start), fmt.Sprintf("short NTP response: %d bytes", read)
	}
	mode, stratum := response[0]&7, response[1]
	if mode != 4 && mode != 5 {
		return check.StatusDown, time.Since(start), fmt.Sprintf("unexpected NTP mode %d", mode)
	}
	if stratum == 0 || stratum >= 16 {
		return check.StatusDown, time.Since(start), fmt.Sprintf("NTP server is unsynchronised (stratum %d)", stratum)
	}
	if string(response[24:32]) != string(request[40:48]) {
		return check.StatusDown, time.Since(start), "NTP response does not match request timestamp"
	}
	return check.StatusUp, time.Since(start), fmt.Sprintf("NTP version %d, stratum %d", response[0]>>3&7, stratum)
}

type DNS struct {
	Policy   Policy
	Resolver *net.Resolver
}

func (DNS) Kind() check.Kind { return check.KindDNS }
func (d DNS) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	if c.DNSServer != "" {
		return d.probeServer(ctx, c)
	}
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
	case "CNAME":
		var value string
		value, err = r.LookupCNAME(ctx, c.Target)
		if value != "" {
			values = append(values, strings.TrimSuffix(value, "."))
		}
	case "NS":
		var records []*net.NS
		records, err = r.LookupNS(ctx, c.Target)
		for _, value := range records {
			values = append(values, strings.TrimSuffix(value.Host, "."))
		}
	case "SRV":
		_, records, lookupErr := r.LookupSRV(ctx, "", "", c.Target)
		err = lookupErr
		for _, value := range records {
			values = append(values, fmt.Sprintf("%d %d %d %s", value.Priority, value.Weight, value.Port, strings.TrimSuffix(value.Target, ".")))
		}
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

var dnsQueryID atomic.Uint32

func (d DNS) probeServer(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	record := c.DNSRecord
	if record == "" {
		record = "A"
	}
	typeValue, ok := dnsRecordType(record)
	if !ok {
		return check.StatusUnknown, 0, fmt.Sprintf("unsupported DNS record %q", record)
	}
	name := c.Target
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return check.StatusUnknown, 0, fmt.Sprintf("invalid DNS name: %v", err)
	}
	id := uint16(dnsQueryID.Add(1))
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: qname, Type: typeValue, Class: dnsmessage.ClassINET}}}
	query, err := request.Pack()
	if err != nil {
		return check.StatusUnknown, 0, fmt.Sprintf("build DNS query: %v", err)
	}
	server := c.DNSServer
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	start := time.Now()
	response, err := d.exchangeDNS(ctx, c.Vantage, "udp", server, query)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return check.StatusDown, time.Since(start), fmt.Sprintf("invalid DNS response: %v", err)
	}
	if message.Header.Truncated {
		response, err = d.exchangeDNS(ctx, c.Vantage, "tcp", server, query)
		if err != nil {
			status, detail := classify(err)
			return status, 0, detail
		}
		if err := message.Unpack(response); err != nil {
			return check.StatusDown, time.Since(start), fmt.Sprintf("invalid TCP DNS response: %v", err)
		}
	}
	if message.Header.ID != id || !message.Header.Response {
		return check.StatusDown, time.Since(start), "DNS response does not match query"
	}
	rcode := dnsRCodeName(message.Header.RCode)
	wantRCode := strings.ToUpper(c.DNSRCode)
	if wantRCode == "" {
		wantRCode = "NOERROR"
	}
	if rcode != wantRCode {
		return check.StatusDown, time.Since(start), fmt.Sprintf("DNS response code %s, want %s", rcode, wantRCode)
	}
	values := dnsValues(message.Answers, typeValue)
	sort.Strings(values)
	joined := strings.Join(values, "\n")
	if c.ExpectBody != "" && !strings.Contains(joined, c.ExpectBody) {
		return check.StatusDown, time.Since(start), fmt.Sprintf("DNS response %q does not contain %q", joined, c.ExpectBody)
	}
	if len(values) == 0 && typeValue != dnsmessage.Type(0) && wantRCode == "NOERROR" {
		return check.StatusDown, time.Since(start), "DNS response contained no requested records"
	}
	return check.StatusUp, time.Since(start), fmt.Sprintf("%s%s", rcode, func() string {
		if joined != "" {
			return "\n" + joined
		}
		return ""
	}())
}

func (d DNS) exchangeDNS(ctx context.Context, vantage check.Vantage, network, server string, query []byte) ([]byte, error) {
	conn, err := guardedDialer(vantage, d.Policy, nil).DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if network == "tcp" {
		framed := make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		copy(framed[2:], query)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, err
		}
		response := make([]byte, binary.BigEndian.Uint16(header))
		_, err := io.ReadFull(conn, response)
		return response, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 64<<10)
	n, err := conn.Read(response)
	return response[:n], err
}

func dnsRecordType(record string) (dnsmessage.Type, bool) {
	switch record {
	case "A":
		return dnsmessage.TypeA, true
	case "AAAA":
		return dnsmessage.TypeAAAA, true
	case "CAA":
		return dnsmessage.Type(257), true
	case "CNAME":
		return dnsmessage.TypeCNAME, true
	case "MX":
		return dnsmessage.TypeMX, true
	case "NS":
		return dnsmessage.TypeNS, true
	case "SOA":
		return dnsmessage.TypeSOA, true
	case "SRV":
		return dnsmessage.TypeSRV, true
	case "TXT":
		return dnsmessage.TypeTXT, true
	default:
		return 0, false
	}
}

func dnsRCodeName(code dnsmessage.RCode) string {
	switch code {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}

func dnsValues(resources []dnsmessage.Resource, wanted dnsmessage.Type) []string {
	values := make([]string, 0, len(resources))
	for _, resource := range resources {
		if resource.Header.Type != wanted {
			continue
		}
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			values = append(values, net.IP(body.A[:]).String())
		case *dnsmessage.AAAAResource:
			values = append(values, net.IP(body.AAAA[:]).String())
		case *dnsmessage.CNAMEResource:
			values = append(values, strings.TrimSuffix(body.CNAME.String(), "."))
		case *dnsmessage.MXResource:
			values = append(values, fmt.Sprintf("%d %s", body.Pref, strings.TrimSuffix(body.MX.String(), ".")))
		case *dnsmessage.NSResource:
			values = append(values, strings.TrimSuffix(body.NS.String(), "."))
		case *dnsmessage.SOAResource:
			values = append(values, fmt.Sprintf("%s %s %d %d %d %d %d", strings.TrimSuffix(body.NS.String(), "."), strings.TrimSuffix(body.MBox.String(), "."), body.Serial, body.Refresh, body.Retry, body.Expire, body.MinTTL))
		case *dnsmessage.SRVResource:
			values = append(values, fmt.Sprintf("%d %d %d %s", body.Priority, body.Weight, body.Port, strings.TrimSuffix(body.Target.String(), ".")))
		case *dnsmessage.TXTResource:
			values = append(values, strings.Join(body.TXT, ""))
		case *dnsmessage.UnknownResource:
			if wanted == dnsmessage.Type(257) && len(body.Data) >= 2 && int(body.Data[1])+2 <= len(body.Data) {
				values = append(values, fmt.Sprintf("%d %s %s", body.Data[0], string(body.Data[2:2+int(body.Data[1])]), string(body.Data[2+int(body.Data[1]):])))
			}
		}
	}
	return values
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
	roots, err := rootsForCheck(c.CAFile, t.RootCAs)
	if err != nil {
		return check.StatusUnknown, 0, err.Error()
	}
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
	tc := tls.Client(conn, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: roots})
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
	roots, err := rootsForCheck(c.CAFile, s.RootCAs)
	if err != nil {
		return check.StatusUnknown, 0, err.Error()
	}
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
		if err := client.StartTLS(&tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: roots}); err != nil {
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
