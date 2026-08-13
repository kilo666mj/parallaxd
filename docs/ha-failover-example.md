# Example HA failover and failback record

This anonymized record illustrates the evidence to retain when following the
[HA drill](ha-drill.md). Host names, addresses, times, and build identifiers
are deliberately fictional.

## Scope

- Starting active coordinator: `coordinator-a` (`10.77.0.1`)
- Starting warm standby: `coordinator-b` (`10.77.0.2`)
- Coordinator build: `example-build`
- Procedure: service fence plus persistent firewall fence
- Operators: deployment team

## Promotion

Fresh configuration and state backups were taken on both coordinators. The
standby reported sub-second apply lag, no active incidents, and an empty
delivery queue.

The primary service was stopped and disabled. A persistent start refusal and
network reject rule were installed, then independently verified over every
coordinator address. The guarded promotion command accepted the standby only
after the operator positively attested to the fence.

Internal and public probers moved to the promoted coordinator. Mesh state,
fresh check results, incident state, and notification delivery were verified.
The former primary was rebuilt as an inactive standby and replication resumed.

## Controlled failback

Both hosts were backed up again. The promoted coordinator had no active
incidents or pending deliveries, and the standby replica was current.

The active coordinator was fenced and independently verified before the
canonical primary was promoted. Probers returned to it, the temporary promotion
marker was cleared under the documented fencing rules, and the other host was
started as an inactive standby.

## Final state

- exactly one coordinator was active
- every prober reported fresh results and healthy mesh visibility
- there were no active incidents or pending deliveries
- standby replication was current and error-free
- temporary relays, firewall rules, and promotion markers were reconciled
- the private inventory described the final canonical roles

Keep site-specific addresses, provider names, backup paths, and firewall
details in a private operations record rather than this public repository.
