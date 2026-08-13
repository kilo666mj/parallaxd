# Example operational acceptance record

This anonymized record shows the evidence an operator should retain after
running the [acceptance exercise](acceptance.md). Names, addresses, incident
numbers, and timings are illustrative.

## Scope

- Release: `example-build`
- Operator: deployment team
- Primary coordinator: `coordinator-a`
- Warm standby: `coordinator-b`
- Internal probers exercised: `internal-a`, `internal-b`, `internal-c`
- Targets exercised: `internal-app-a`, `internal-app-b`
- Notification destination: test webhook

## Results

### Target failure and recovery — pass

Only the application process was stopped; its dependencies remained healthy.
Three independent probers agreed it was down, one notification was delivered,
and one recovery followed after the application restarted. Repeated
observations produced no duplicate transition.

### Assigned-prober loss and recovery — pass

The prober process alone was stopped on `internal-a`. Its checks retained their
last known state and moved to `internal-b`; the coordinator opened a single
not-reporting incident. Ownership returned after the process restarted.

### Mesh isolation and rejoin — pass

A temporary, automatically expiring firewall rule prevented `internal-a` from
reaching peer prober ports while preserving coordinator and administrative
access. The coordinator excluded its evidence, reassigned its checks, and did
not create a target-down incident. Normal ownership returned when connectivity
was restored.

### Internal target allowlist — pass

An authenticated monitor test requested a connection outside an internal
prober's configured target networks. The result was `unknown`, and packet
capture confirmed that no target connection was attempted.

### Notification durability and ordering — pass

An automatically expiring outbound firewall rule blocked the test webhook.
The down event remained queued across retries, and its recovery stayed behind
it. Both delivered in order after the rule was removed.

### Coordinator restart persistence — pass

Monitor, revision, identity, incident, history, and delivery counts matched
before and after a coordinator restart. Probers resumed reporting and the
standby resumed replication without a synthetic incident.

## Completion

- all stopped services were restored
- all temporary network rules and rollback timers were removed
- monitored targets were healthy with fresh results
- all probers reported healthy mesh visibility
- the notification queue was empty
- primary and standby services were healthy on the tested build

Keep the real record in a private operations repository when it contains host
names, internal networks, incident identifiers, or notification details.
