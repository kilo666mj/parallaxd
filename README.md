# parallaxd

Corroborated availability monitoring: check from one place, confirm from
several, and alert only when they agree.

Parallax is the apparent shift of an object viewed from two separated points.
That is the idea here: one viewpoint cannot distinguish a service outage from
its own broken path, but several independent viewpoints can.

> **Status: operational.** The coordinator, public and private probers,
> external watcher, warm standby, dashboard, and durable alert lifecycle are
> implemented. See the [roadmap](ROADMAP.md) for current work.

![parallaxd operator dashboard](docs/images/dashboard-overview.png)

## How it works

One prober runs each check on its normal schedule. When it reports a failure,
the coordinator asks other probers to test the same target immediately and
applies a quorum rule to their signed results.

```text
scheduled probe reports down
        │
        ▼
coordinator requests corroboration
        │
        ▼
quorum agrees ── yes ──► alert once on the transition
        │
        no
        ▼
remain inconclusive and retain the suspect timeline
```

This keeps steady-state traffic low while still checking failures from
independent providers. It also supports richer checks—such as TLS, SMTP, DNS,
gRPC, NTP, and authenticated HTTP—without running every check from every host
all the time.

The design relies on a few rules:

- Results are `up`, `down`, or `unknown`; `unknown` never counts as a vote.
- Every check declares a `public` or `internal` vantage.
- Each prober votes once, and optional provider diversity prevents several
  hosts at one provider from masquerading as independent evidence.
- A prober that cannot reach any of at least two peers is treated as isolated,
  and its target results are suppressed until it rejoins.
- Alerts fire on state transitions, not on every result. An inconclusive result
  does not clear an active outage.
- Requests and results are signed with Ed25519. The control plane should still
  use WireGuard or another encrypted transport because signatures do not
  provide confidentiality.

## Components

| Binary | Role |
|---|---|
| `parallaxd` | Assigns checks, evaluates quorum, persists state, and sends alerts |
| `parallaxd-probe` | Runs scheduled and on-demand checks; makes no decisions |
| `parallaxd-watch` | Alerts when the coordinator's signed heartbeat stops |
| `parallaxd-ha` | Preflights and explicitly promotes a fenced warm standby |
| `parallaxd-network` | Creates and installs the WireGuard control overlay |

The coordinator also serves an operator dashboard, authenticated monitor and
incident APIs, a redacted public status export, observation history, and HA
diagnostics. Alert delivery supports the always-on log, durable generic
webhooks, and native Tintwire cards with a generic-webhook fallback (for
example, Mattermost) when Tintwire has a retryable delivery failure.

Supported checks are `tcp`, `http`, `banner`, `dns`, `tls`, `smtp`, `icmp`,
`request`, `grpc`, and `ntp`. Related checks can be grouped into components so
operators receive one service-level alert instead of one alert per port.

## Deployment

A meaningful production deployment needs one dedicated coordinator and at
least three probers in distinct failure domains. Four probers provide a spare.
The watcher may share a prober host, as may the optional standby.

Linux and Ansible are required for deployment:

```sh
git clone https://github.com/kilo666mj/parallaxd.git
cd parallaxd/ansible
ansible-galaxy collection install -r requirements.yml
cp inventory.example inventory
# Edit inventory and put secrets in the gitignored group_vars/all.yml.
ansible-playbook playbook.yml
```

Start with the documented variables in
[`ansible/group_vars/parallaxd.yml`](ansible/group_vars/parallaxd.yml). The
playbook generates signing keys on their owning hosts, validates rendered
configuration, installs systemd services, configures the project WireGuard
overlay where needed, and applies source-restricted firewall rules.

The inventory has these groups:

- `parallaxd_coordinator`: exactly one host, separate from the probers.
- `parallaxd_probers`: three or more independently hosted viewpoints.
- `parallaxd_watch`: the external dead-man's switch.
- `parallaxd_standby`: an optional coordinator in another failure domain.
- `parallaxd_internal_probers`: optional private probers on the managed
  WireGuard overlay.

Keep secrets out of committed configuration. The example group variables name
the expected gitignored secret values. Private prober keys remain on their
hosts; the standby is the deliberate exception because it must retain the
coordinator identity trusted by the fleet.

### Add a monitor

Checks live in the coordinator catalogue and can be managed through the
dashboard/API after deployment. The initial catalogue comes from
`parallaxd_checks`:

```yaml
parallaxd_checks:
  - name: website
    prober: probe-a
    kind: http
    target: https://example.com/health
    vantage: public
    interval: 1m
    timeout: 10s
    quorum:
      agree: 2
      of: 3
      distinct_providers: true
```

Use `probers` to restrict an internal monitor to a private pool. Internal
probers must also have an explicit `parallaxd_allow_targets` list. The prober
enforces target restrictions against resolved addresses, including permanent
blocks on link-local metadata ranges.

### Validate configuration

Validate a rendered coordinator configuration without starting listeners,
restoring state, or sending traffic:

```sh
parallaxd -config /etc/parallaxd/coordinator.json.candidate -validate
```

The Ansible deployment performs the same preflight before atomically replacing
the live configuration.

## Operations

- [Recurring operations](docs/operations.md)
- [Operational acceptance exercise](docs/acceptance.md) and
  [example record](docs/acceptance-example.md)
- [Coordinator failover drill](docs/ha-drill.md) and
  [example record](docs/ha-failover-example.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

The dashboard is served at the coordinator root. For a loopback-bound
coordinator, access it through an SSH tunnel:

```sh
ssh -L 8972:127.0.0.1:8972 coordinator.example
```

Then open `http://127.0.0.1:8972/`.

Warm-standby promotion is intentionally manual: fence the old primary, inspect
replication health with `parallaxd-ha`, promote with an explicit fence
attestation, and move the service entry point. Loss of contact is never proof
that the old primary is fenced. Follow the failover drill rather than treating
the summary here as a runbook.

## Development

Development requires the Go version declared in [`go.mod`](go.mod).

```sh
go build ./...
go test -race ./...
```

Tagged releases publish static Linux binaries for amd64 and arm64 with
checksums.

## License

MIT
