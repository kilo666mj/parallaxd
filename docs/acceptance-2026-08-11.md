# Operational acceptance record — 2026-08-11

## Scope

- Release: `d644a26`
- Operator: Michael Johnson with Codex
- Primary coordinator: `morty`
- Warm standby: `spike`
- Internal probers exercised: `lbc1n3`, `dnsc1n2`, `backup`
- Targets exercised: `internal-immich`, `internal-frigate`
- Notification destination: production Mattermost webhook

The coordinator was deployed standby-first to `spike` and then to `morty`.
GitHub build, test, and both CodeQL checks completed successfully before the
clean deployment.

## Results

### Target failure and recovery — pass

Only the Immich application container was stopped; its database and Redis
remained healthy.

- incident 9 opened at 11:04:47 CEST after three of three corroborating probers
  reported down
- one down notification and one recovery notification were observed
- Immich recovered at 11:05:47 CEST after the application container restarted
- repeated observations produced no duplicate transition
- the delivery queue returned to empty

### Assigned-prober loss and recovery — pass after defect correction

`parallaxd-probe` alone was stopped on `lbc1n3`.

- both internal checks stayed last-known-up and produced no target-down incident
- both checks failed over to `dnsc1n2`
- incident 10 grouped the two silent checks under `lbc1n3`
- the exercise exposed a failback deadlock: a silent preferred owner received
  no assignments and therefore could not submit the result required to clear
  its silence
- `d644a26` corrects this by treating a fresh authenticated mesh report as
  proof that the prober process has returned
- after deployment, both assignments returned to `lbc1n3` and incident 10
  resolved at 11:22:00 CEST

### Mesh isolation and rejoin — pass

A runtime-only OUTPUT rule on `lbc1n3` rejected new TCP/8973 peer connections
while preserving coordinator TCP/8972 and SSH connectivity. A five-minute
automatic rollback was armed before the rule was applied.

- `lbc1n3` continued reporting but could reach no peer
- the coordinator excluded its evidence and moved both internal checks to
  `dnsc1n2`
- no target-down incident was created
- incident 11 recorded the isolation from 11:34:25 to 11:35:30 CEST
- after removing the rule, all seven probers reported healthy mesh visibility
  and preferred ownership returned to `lbc1n3`

### Internal target allowlist — pass

An authenticated monitor test asked only `lbc1n3` to probe
`203.0.113.1:9`, outside its configured `192.168.252.0/23` target networks.
The result was `unknown` with the detail that the address was outside every
allowed network. No target connection was attempted.

### Notification durability and ordering — pass

An OUTPUT-only temporary nftables table on `morty` rejected the configured
webhook IP on TCP/443. An eight-minute automatic rollback was armed first.

- delivery 5 retained the Immich `down` event and its connection error across
  three failed attempts
- after Immich recovered, delivery 6 retained `recovered` behind delivery 5
  with zero attempts while delivery 5 remained pending
- after removing the webhook block, both events delivered in order and the
  queue returned to empty

An earlier attempt used `firewall-cmd --direct`. Its iptables compatibility
layer created an empty priority-zero `ip filter` FORWARD chain with policy
`drop`, temporarily blocking internal WireGuard peer forwarding ahead of
firewalld's trusted-zone rules. The compatibility table was removed; no direct
rules remain. `wg-parallaxd` remains persistently assigned to firewalld's
`trusted` zone with forwarding enabled, and internal peer connectivity was
reverified. The successful ordering test used an isolated nftables OUTPUT
table and did not affect forwarding.

### Coordinator restart persistence — pass

Before and after restarting the primary coordinator, the retained counts were:

| State | Before | After |
| --- | ---: | ---: |
| monitors | 18 | 18 |
| catalogue revisions | 5 | 5 |
| users | 1 | 1 |
| service tokens | 0 | 0 |
| incidents | 28 | 28 |
| silences | 0 | 0 |
| history summaries | 18 | 18 |
| pending deliveries | 0 | 0 |

All seven probers resumed mesh reporting, both internal checks produced fresh
post-restart up verdicts under `lbc1n3`, and no synthetic incident appeared.
The standby resumed replication with 178 ms reported apply lag.

## Completion

- all stopped services were restored
- all temporary firewall and nftables rules and rollback timers were removed
- Immich and Frigate were up with fresh results
- all seven probers reported healthy mesh visibility
- the notification queue was empty
- primary and standby coordinator services were healthy on `d644a26`

The fenced standby-promotion exercise remains separate and must be performed
in a declared maintenance window following [`ha-drill.md`](ha-drill.md).
