package probe

import (
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

// httpPhases records how far an HTTP request got, so a failure can say where
// it stalled. DNS, connect, TLS and waiting for the server each point at a
// different culprit: the prober's resolver, the network path, or the server.
// It explains a result and never changes its status.
type httpPhases struct {
	mu         sync.Mutex
	phase      string
	phaseStart time.Time
	remote     string
	reused     bool
	done       []string // completed phases, e.g. "dns 4ms"
}

func (p *httpPhases) enter(phase string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase, p.phaseStart = phase, time.Now()
}

func (p *httpPhases) finish(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.phaseStart.IsZero() {
		p.done = append(p.done, fmt.Sprintf("%s %s", name, roundMS(time.Since(p.phaseStart))))
	}
}

func (p *httpPhases) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { p.enter("dns") },
		DNSDone:  func(httptrace.DNSDoneInfo) { p.finish("dns") },
		ConnectStart: func(_, addr string) {
			p.enter("connect")
			p.mu.Lock()
			p.remote = addr
			p.mu.Unlock()
		},
		ConnectDone:       func(_, _ string, _ error) { p.finish("connect") },
		TLSHandshakeStart: func() { p.enter("tls") },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { p.finish("tls") },
		GotConn: func(info httptrace.GotConnInfo) {
			p.enter("sending request")
			p.mu.Lock()
			p.remote, p.reused = info.Conn.RemoteAddr().String(), info.Reused
			p.mu.Unlock()
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { p.enter("waiting for response") },
		GotFirstResponseByte: func() { p.enter("reading response") },
	}
}

// describe names the phase the request was in when it failed, for example
// "during tls to 192.0.2.1:443 after 5s; dns 4ms, connect 31ms".
func (p *httpPhases) describe() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.phase == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("during " + p.phase)
	if p.remote != "" {
		b.WriteString(" to " + p.remote)
	}
	if p.reused {
		b.WriteString(" (reused connection)")
	}
	b.WriteString(" after " + roundMS(time.Since(p.phaseStart)).String())
	if len(p.done) > 0 {
		b.WriteString("; " + strings.Join(p.done, ", "))
	}
	return b.String()
}

func roundMS(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
