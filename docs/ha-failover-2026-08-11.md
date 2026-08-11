# HA failover and failback record — 2026-08-11

## Scope

- Starting active coordinator: `morty` (`10.77.0.1`)
- Starting warm standby: `spike` (`10.77.0.2`)
- Coordinator build at completion: `8411a9a`
- Procedure: service fence plus persistent Firewalld TCP/8972 fence
- Operators: Michael Johnson with Codex

The Cloudflare public hostname remained on Morty's tunnel. It was explicitly
outside the promotion acceptance criteria; raw coordinator addresses were used
while Spike was active.

## Promotion to Spike

Fresh archives of `/etc/parallaxd` and `/var/lib/parallaxd` were taken on both
coordinators. Immediately before promotion, Spike's replica apply lag was
177 ms, there were no active incidents, and the delivery queue was empty.

Morty's coordinator was stopped and disabled, a systemd
`RefuseManualStart=yes` drop-in was installed, and persistent plus runtime
Firewalld reject rules fenced TCP/8972. The fence was verified independently
over Morty's public and WireGuard addresses before Spike was promoted at
12:13:46 CEST by `ha-drill-2026-08-11`.

The three internal probers moved to `10.77.0.2:8972`. Public probe traffic
initially failed because Oracle Cloud allowed the prober control port 8973 but
not the coordinator port 8972. Adding source-restricted Oracle ingress for
TCP/8972 restored Fleeb, Glarb, and Hetz01; Firewalld already contained the
matching runtime and permanent rules.

The exercise exposed an alert state-machine defect: authenticated reports from
an isolated prober cleared its not-reporting state even though its monitoring
evidence was still excluded. The watchdog immediately reopened the state,
producing alternating alerts every 30 seconds. PR #42 fixed the transition,
added regression coverage, and changed the user-facing label from `SILENT` to
`NOT REPORTING` while retaining the internal `silent` kind for compatibility.

Morty was rebuilt as an inactive standby pulling from Spike. Replication
resumed with sub-second apply lag.

## Controlled failback to Morty

Before failback, both hosts were archived again at
`/var/backups/parallaxd/pre-failback-20260811-1350.tgz`. Spike had no active
incidents or pending deliveries, and Morty's last replica apply lag was
313 ms.

Spike's coordinator alone was stopped and disabled; its prober remained
running. A systemd start refusal and persistent Firewalld TCP/8972 rejects were
installed and verified from Fleeb and Morty. Morty promoted at 13:51:21 CEST
by `controlled-failback-2026-08-11` from state applied at 13:50:55 CEST, with
350 ms reported replication lag.

Public probers returned to `172.245.253.218:8972`; internal probers returned to
`10.77.0.1:8972`. Morty's old network fence was removed and its temporary
promotion marker was cleared after restoring its canonical `primary` role.
Spike's persisted
promotion marker was cleared only while its service and network were fenced,
then it was started from the merged build as an inactive standby pulling from
Morty. Its first verified replica apply lag was 413 ms.

## Final state

- Morty is the canonical active primary and retains the public tunnel.
- Spike is an inactive, unpromoted standby replicating from Morty.
- Both coordinator binaries report version `8411a9a`.
- All seven probers report to Morty; no checks are stale.
- There are no active incidents or pending deliveries.
- Spike retains the persistent TCP/8972 network fence; replication is outbound.
- The temporary Spike Nginx relay was removed and Nginx revalidated.
- The local gitignored Ansible inventory again describes Morty as primary and
  Spike as standby.

## Automation findings

An Ansible check-mode run was attempted after reconciliation. The three direct
internal hosts were reachable, but the public hosts' command-restricting SSH
gateway rejected Ansible interpreter discovery, pipelined Python modules, and
file transfer even though ordinary approved SSH commands work. The run made no
changes. It also found that `backup` does not run Firewalld and must override
`parallaxd_manage_firewalld` to `false` in the private inventory.

A guarded operator failover command remains follow-up work. Promotion must stay
manual and positively fenced; loss of reachability alone must never select the
authoritative coordinator.
