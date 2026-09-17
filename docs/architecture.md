# Architecture and failure model

This document is the map for understanding a production parallaxd deployment.
The detailed installation and operator procedures remain in the linked
runbooks; this page records component ownership, trust boundaries, and expected
failure behavior.

## Component boundaries

| Component | Owns | Must not own |
| --- | --- | --- |
| Coordinator | Monitor catalogue, quorum decisions, incident state, observations, delivery queue, users and API tokens | Independent evidence or automatic fencing |
| Prober | Scheduled and requested checks, local target policy, signed evidence | Alert decisions, incident state, or credentials for other probers |
| Watcher | Independent verification of the coordinator heartbeat | Monitor execution or coordinator promotion |
| Warm standby | Replicated coordinator recovery state and explicit promotion tooling | Automatic promotion based only on lost contact |
| Prometheus | Host measurements and long-term metric storage | Quorum votes or incident transitions |

The coordinator is the only decision-maker, but it cannot invent evidence. A
prober contributes at most one vote and `unknown` never counts toward quorum.
Provider-diversity rules prevent several hosts behind one shared route from
appearing independent.

## Data and control flow

1. The assigned prober runs a scheduled check and signs its result.
2. A failure causes the coordinator to request immediate corroboration from
   eligible probers.
3. The coordinator validates signatures, target policy, freshness, provider
   diversity, and quorum before changing incident state.
4. A state transition is persisted before its notification is delivered.
5. The watcher evaluates a separately signed heartbeat so coordinator loss is
   visible even when the coordinator cannot alert for itself.

Monitor catalogue changes use the authenticated dashboard, API, or MCP tools.
They are versioned, audited, and replicated to the standby through the same
coordinator implementation.

## Trust and privacy boundaries

- Ed25519 authenticates control messages but does not encrypt their contents.
  Carry control traffic over WireGuard, a private network, or an equivalent
  encrypted transport.
- Public and internal vantages are separate. Internal probers require explicit
  target allowlists; resolved link-local metadata addresses remain blocked.
- Proxy credentials stay on the prober that uses them. Probers sharing one
  proxy exit count as one failure domain.
- Operator and MCP credentials are bearer secrets. Give automated readers a
  viewer token and expose the API only behind the intended TLS and network
  boundary.
- Observation history contains target availability and timing data. Treat
  exports and backups as operational data even when monitor definitions are
  public.

See [MCP access](mcp.md), [proxy probing](proxy-probing.md), and the repository
[security policy](../SECURITY.md) for the enforcement details.

## Failure behavior

| Failure | Expected behavior | Operator action |
| --- | --- | --- |
| One scheduled check fails | Coordinator requests corroboration; no alert until quorum agrees | Inspect the evidence timeline if the result remains inconclusive |
| One prober disappears | Its vote becomes unavailable; other eligible probers continue | Restore or replace it before quorum loses the required independence |
| A prober loses all but fewer than two peers | Its target results are suppressed as isolated | Repair the mesh; do not weaken isolation rules to regain a vote |
| Notification destination fails | Incident state remains durable and delivery is retried | Inspect diagnostics and destination error state |
| Coordinator stops | Watcher alerts; probers do not elect a replacement | Follow the fenced [failover drill](ha-drill.md) |
| Coordinator and standby disagree | Promotion preflight fails | Fence the old writer and reconcile replication before promotion |
| Backup is incomplete or corrupt | Restore verification fails without opening listeners | Repair the backup pipeline and retain the last verified recovery point |

Loss of contact is never proof that a coordinator is fenced. The standby is
warm recovery capacity, not a consensus member.

## Deployment and recovery references

- Start with the production prerequisites and minimal Ansible installation in
  the [README](../README.md#deployment).
- Use [recurring operations](operations.md) for backup verification, upgrades,
  drift checks, and routine diagnostics.
- Rehearse the [operational acceptance exercise](acceptance.md) before enabling
  alert delivery for a new deployment.
- Use the [coordinator failover drill](ha-drill.md) for promotion and failback;
  the [example record](ha-failover-example.md) shows the expected evidence.

Examples use `example.com`, `.example` hostnames, and documentation-only
addresses. Replace them only in private deployment inventory; never commit
real tokens, private target names, or internal addresses.
