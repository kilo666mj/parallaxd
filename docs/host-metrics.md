# Host metrics

parallaxd can show a bounded, read-only host overview from one or more
Prometheus servers. Prometheus remains responsible for scraping, time-series
storage, recording rules, and metric alerts. Host measurements do not become
parallaxd checks and never contribute to corroborated availability verdicts.

## Coordinator configuration

Each source must have a unique name, an absolute URL, and `match_labels` that
select only its node-exporter scrape targets. Exact label matching prevents a
configuration mistake from exposing every target in a shared Prometheus.

```json
{
  "prometheus": [
    {
      "name": "primary-site",
      "url": "https://prometheus.example.com",
      "match_labels": {"job": "node"},
      "bearer_token_file": "/etc/parallaxd/keys/prometheus-token",
      "ca_file": "/etc/parallaxd/ca/prometheus-ca.pem",
      "timeout": "8s"
    }
  ]
}
```

For mutual TLS, use `cert_file` and `key_file` together. `server_name` may be
set when the certificate name differs from the URL host. The coordinator uses
TLS 1.2 or newer, augments rather than replaces the system roots when
`ca_file` is configured, and reads all credentials from files at startup.

Plain HTTP is rejected by default. It may be enabled with
`"allow_insecure": true` only when the entire path is protected separately,
such as loopback or a private WireGuard route. The setting is intentionally
named as an exception so an Internet-facing plaintext endpoint cannot be added
silently.

When using Ansible, put the non-secret source definitions in
`parallaxd_prometheus_sources`. Provision token, CA, and client-key files using
site-private or vaulted automation; do not place their contents in the public
repository.

## API and dashboard

Authenticated viewers can read `GET /v1/metrics/hosts`. The dashboard's Hosts
view shows, per source and instance:

- Prometheus scrape state;
- CPU and memory used percentages;
- highest filesystem used percentage after pseudo/container filesystems are
  excluded;
- one-minute load; and
- uptime.

The coordinator issues fixed instant queries only. It does not accept PromQL
from the browser. Upstream responses are limited to 2 MiB and 1,000 series per
query, successful and failed snapshots are cached for 15 seconds, queries
inherit request cancellation, and each configured HTTP client has a timeout.
One unavailable source returns a generic per-source error while the endpoint
and parallaxd's monitoring engine remain available.

## Network boundary

Keep node_exporter on a loopback, LAN, or WireGuard address and allow its port
only from the Prometheus scraper. parallaxd talks to Prometheus, not directly
to exporters. Prefer HTTPS with a bearer token or mutual TLS between parallaxd
and Prometheus; a private VPN path is also suitable when the HTTP exception is
made explicitly.

The primary and standby coordinators need equivalent network reachability and
credential files if host context must remain visible after failover. Metrics
configuration and secrets are deliberately not replicated through the live
monitor catalogue.
