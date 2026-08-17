package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
)

// GRPC probes the standard grpc.health.v1.Health service.
type GRPC struct {
	Policy  Policy
	Dialer  *net.Dialer
	RootCAs *x509.CertPool
}

func (GRPC) Kind() check.Kind { return check.KindGRPC }

func (g GRPC) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	dialer := guardedDialer(c.Vantage, g.Policy, g.Dialer)
	options := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithReturnConnectionError(),
		grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", target)
		}),
	}
	if c.GRPCTLS {
		host, _, err := net.SplitHostPort(c.Target)
		if err != nil {
			return check.StatusUnknown, 0, fmt.Sprintf("invalid gRPC target: %v", err)
		}
		name := c.ServerName
		if name == "" {
			name = host
		}
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: g.RootCAs,
		})))
	} else {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	start := time.Now()
	conn, err := grpc.DialContext(ctx, c.Target, options...)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	defer conn.Close()
	response, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: c.GRPCService})
	if err != nil {
		return check.StatusDown, time.Since(start), fmt.Sprintf("gRPC health check: %v", err)
	}
	if response.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return check.StatusDown, time.Since(start), fmt.Sprintf("gRPC health status %s", response.Status)
	}
	return check.StatusUp, time.Since(start), fmt.Sprintf("gRPC service %q is SERVING", c.GRPCService)
}
