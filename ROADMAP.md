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
- authenticated monitor management, testing, revision history, and rollback
- strict semantic configuration validation and atomic deployment preflight
- provider-neutral local, OIDC, and scoped-token identity with role-based access
- durable warm-standby replication with explicit, fenced promotion
- assignment, rejection, queue, delivery, mesh, and HA diagnostics

## Current work

The next milestone is operational assurance rather than new product surface:

1. Run and record the acceptance exercise in
   [`docs/acceptance-2026-08-11.md`](docs/acceptance-2026-08-11.md), including
   private-prober failure, reassignment, alert, recovery, and persistence
   scenarios. **Completed 2026-08-11.**
2. Rehearse the fenced standby-promotion procedure in
   [`docs/ha-drill.md`](docs/ha-drill.md). **Completed 2026-08-11; see the
   [drill record](docs/ha-failover-2026-08-11.md).**
3. Use the guarded `parallaxd-ha` command for standby preflight and promotion.
   It refuses stale/erroring replication, unexpected role or active state,
   excess lag, queued work, and promotion without explicit positive-fence
   attestation. Backups, independent fence verification, traffic movement, and
   rebuilding the former active remain visible infrastructure steps in the HA
   runbook; reachability loss is never treated as authority. **Guarded
   preflight/promotion completed; site-specific backup, fence, traffic, and
   rebuild automation remains.**
4. Provide Ansible a transport path that permits its Python module wrapper and
   file transfer. The command-restricting public SSH gateway refuses both and
   cannot support general Ansible by client configuration alone. The supported
   alternatives and security boundary are recorded in
   [`docs/operations.md`](docs/operations.md). **Requires an external deployment
   endpoint or internal runner.**
5. Maintain deterministic protocol and process coverage for DNS, SMTP and
   STARTTLS, TLS, ICMP reply behavior, assignment failover, notification
   ordering, HA replication, and coordinator restart recovery. **Completed.**
6. Follow [`docs/operations.md`](docs/operations.md) for recurring HA, watcher,
   delivery, backup-restore, version, firewall, and drift checks. Dependency
   and vulnerability checks now run weekly. Production checks require a
   private scheduled runner. **Repository automation completed; private runner
   scheduling remains.**

New check kinds and reporting features should be driven by operational need.
The guiding principle remains to make existing checks easy to trust, operate,
and understand before broadening the catalogue.
