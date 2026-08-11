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
3. Add a guarded manual failover command that preflights replication and
   queues, backs up both coordinators, positively fences and independently
   verifies the old active, promotes exactly one target, moves probe traffic,
   and rebuilds the former active as standby. It must never infer authority
   from reachability loss alone.
4. Make production Ansible runs compatible with the command-restricting SSH
   gateway; ordinary SSH commands work, but Python module execution and file
   transfer are currently refused.
5. Expand deterministic protocol and process-level integration coverage for
   DNS, SMTP, TLS, ICMP capability behavior, assignment failover, notification
   ordering, and coordinator restart recovery.
6. Treat dependency updates, security review, backups, and production findings
   as ongoing maintenance.

New check kinds and reporting features should be driven by operational need.
The guiding principle remains to make existing checks easy to trust, operate,
and understand before broadening the catalogue.
