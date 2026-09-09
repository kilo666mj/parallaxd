# Product roadmap

parallaxd's current production scope is complete. The coordinator, public and
private probers, watcher, warm standby, operator control room, durable alert
lifecycle, and observation history are implemented and deployed.

## Completed

- corroborated public and internal checks with provider-diverse quorum
- signed coordinator/prober traffic and WireGuard transport for private agents
- dynamic assignment and automatic failover away from silent or isolated owners
- mesh-aware isolation suppression and an external dead-man's switch
- durable incidents, acknowledgements, resolutions, silences, notification
  retries, routing, and escalation
- historical observations, summaries, trends, components, and status export
- read-only host context from named Prometheus data sources, isolated from
  availability verdicts and raw time-series storage
- authenticated monitor management, testing, revision history, and rollback
- strict semantic configuration validation and atomic deployment preflight
- provider-neutral local, OIDC, and scoped-token identity with role-based access
- durable warm-standby replication with explicit, fenced promotion
- assignment, rejection, queue, delivery, mesh, and HA diagnostics
- direct authoritative/resolver DNS checks, bounded TCP request/response,
  standard gRPC health, and NTP protocol checks
- per-monitor additional certificate authorities for HTTPS, raw TLS, SMTP
  STARTTLS, and TLS-enabled gRPC checks, installed locally on each prober

## Operational assurance

Audited against repository code and the deployed site on 2026-09-08. The older
roadmap mixed implemented site infrastructure with work still needing tooling.

Implemented and verified:

- acceptance exercise and fenced failover/failback drill, recorded on
  2026-08-11 in [acceptance](docs/acceptance-example.md) and
  [HA drill](docs/ha-failover-example.md) records
- guarded `parallaxd-ha` preflight and explicit promotion
- service tunnel connector installed on both coordinators, active only on the
  primary; handoff remains an explicit step after independent fencing
- daily off-host backups of both coordinators, including configuration,
  identity, state, and observation history, plus independent backup freshness
  monitoring in the private site infrastructure
- fifteen-minute coordinator/watcher assurance and daily offline restore tests
  through [operations.yml](ansible/operations.yml); both current coordinator
  backups passed the real restore path without modifying the backups
- an independent weekly read-only site audit of assurance-job results/freshness,
  backup coverage, versions, firewall state, and available drift/retention evidence
- deterministic protocol/process coverage, weekly dependency scanning, and
  working Ansible access to the managed fleet

The [standby rebuild helper](ansible/ha-rebuild.yml) prepares a validated
candidate and provides an explicitly gated archive/reconfigure/resync workflow.
Its execution path still needs a disposable rehearsal or the next announced HA
exercise; it has not been exercised against the live primary.

## Remaining work

- Rehearse the new rebuild helper, including its failure path, and record the
  result. Provider/network fencing and service-entry-point movement stay
  operator-controlled; neither is triggered by loss of contact.
- Address findings from the weekly audit; unavailable private inventory or
  retention evidence must be reported as verification gaps. Immediate alert
  routing for assurance-job failures remains a site integration option.
- Continue periodic end-to-end delivery exercises, access reviews, and recovery
  drills from [operations.md](docs/operations.md). These are recurring duties,
  not missing coordinator features.

New check kinds and reporting features should be driven by operational need.
HTTP/HTTPS monitors now support HTTP(S) CONNECT and SOCKS5 proxy routes, with
local destination validation and independent-exit quorum; see
[proxy probing](docs/proxy-probing.md). Broader TCP proxying and SOCKS UDP remain
deferred. The guiding principle remains to make existing checks easy to trust,
operate, and understand before broadening the catalogue.
