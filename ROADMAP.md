# Product roadmap ideas

## Progress

- **Completed foundation:** alert lifecycle, diagnostics, and management UI
  - durable incident acknowledgement and manual resolution
  - durable, auditable operator silences for checks, components, and probers
  - authenticated mutation API, disabled unless an operator token is configured
  - assignment explanations, result rejection counters, queue pressure, and
    notification delivery diagnostics
  - dashboard controls for acknowledgement, manual resolution, silence
    creation/cancellation, and operational diagnostics
- **Completed configuration safety:** startup validation and deployment preflight
  - strict JSON parsing and shared-key/provider-diversity checks
  - timeout-budget and semantic coordinator validation
  - staged Ansible validation before atomic config replacement
- **Completed suspect/inconclusive timelines:** durable first-suspicion and
  corroboration-attempt metadata in status, diagnostics, alerts, and dashboard
- **Completed notification operations:** persisted per-destination outbox,
  ordered retries with exponential backoff, target/kind routing, and durable
  unacknowledged-incident escalation
- **Completed historical observations:** bounded append-only history, latency
  and availability summaries, structured DNS/TLS metadata, query APIs, and
  dashboard trend cards
- **Next:** coordinator high availability

parallaxd is already a capable distributed monitoring system: it supports
multiple protocols, dynamic probe assignment, failure corroboration, mesh-aware
suppression, durable incidents, maintenance windows, a status dashboard, and an
external dead-man's switch.

The next improvements should deepen the operational value of those features
before expanding the probe catalogue further.

## 1. Alert lifecycle

Add acknowledgement, manual resolution, silences, escalation policies,
notification retries, and per-target routing. Detection is strong today; the
next step is helping operators manage an incident from first notification to
closure.

## 2. Historical measurements

Retain latency, certificate lifetime, DNS answers, and outcome history in
addition to incident transitions. This would enable trend graphs, degradation
detection, availability reports, and service-level objectives.

## 3. Management API and UI

The authenticated foundation now manages incident acknowledgement/resolution
and operator silences. Remaining work is target editing, configured maintenance
windows, assignment overrides, and a richer incident-history view. Those write
operations should continue to use the operator authentication boundary rather
than becoming public dashboard actions.

## 4. Coordinator availability

The prober fleet can fail over work, but the coordinator remains the central
operational dependency. Explore a standby coordinator, leader election, or
reliable state replication while preserving the coordinator-owned decision
model.

## 5. Configuration validation

Add a dedicated `validate` command with semantic checks for duplicate IDs,
impossible quorums, unknown providers, unsupported check options, assignment
conflicts, and invalid maintenance windows.

## 6. Diagnostics

Expose why an assignment moved, why a result was rejected, which checks each
prober currently owns, queue pressure, and notification delivery status.
Distributed behavior should be explainable without reconstructing it from
several logs.

## 7. Protocol integration testing

Add local integration fixtures for SMTP, DNS, TLS expiry, ICMP capability
behavior, assignment failover, and coordinator restart recovery. These should
exercise real protocol interactions while remaining deterministic and safe to
run in CI.

## Suggested priority

1. Alert lifecycle and diagnostics
2. Historical measurements
3. Configuration validation
4. Coordinator availability
5. Management API and UI
6. Broader integration coverage throughout

The guiding principle is to make existing checks easier to trust, operate, and
understand before adding more check kinds.
