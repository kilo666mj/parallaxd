# Example standby rebuild rehearsal

This anonymized record shows the evidence to retain when rehearsing
[`ansible/ha-rebuild.yml`](../ansible/ha-rebuild.yml). Host names are
fictional; the sizes and timings are representative.

## Scope

- Active primary: `coordinator-a`, unchanged throughout
- Rebuild target: `coordinator-b`, already the warm standby, rebuilt as a
  standby of the same primary so that no roles change
- Retained history on the primary: about 318,000 observations (about 106 MB)
- Standby host: small ARM VM
- Effect: no standby cover for about ten minutes; the primary kept
  monitoring and alerting, and probers were unaffected

## Preparation

The default run wrote and validated
`/etc/parallaxd/coordinator.json.standby-candidate` without touching the
running service. For an existing standby the candidate matched the live
configuration.

## Failure paths

1. **Former coordinator still running.** Executing with the service active
   failed at "Refuse an active or restartable former primary". No mutation had
   started, so the rescue left the service running and no archive was created.
2. **Failure after mutations started.** With the service stopped and disabled,
   a plain file was put at `/var/lib/parallaxd-recovery` so that creating the
   archive failed. The rescue ran, the service stayed stopped and disabled, and
   the configuration and state checksums were unchanged.

## Successful rebuild, first attempt

The helper archived configuration, state and history with the actor record,
installed the standby configuration, removed the old state, started the
service and began verifying. Replication worked, but the first sync of an
empty standby copies all retained history. On this host that took more than
two minutes, during which local API requests timed out, and that sync
reported its duration as replication lag. The checker's two-minute objective
failed for all twelve five-second retries, so the rescue stopped and disabled
the standby as designed.

Starting the service again recovered it within ten seconds, because the history
was already in place: lag 0.6 s and the assurance checker passed. The standby's
scheduled assurance timer had fired an alert during the first sync and
resolved on its next successful run.

**Fix:** the verification step now retries for up to ten minutes (60 × 10 s),
which leaves time for the next, small sync to report the real lag.

## Successful rebuild with the fix

Run again from a stopped and disabled standby, the helper completed with no
failures. Verification passed after eight retries (about three minutes of
first sync). Final state:

- standby active and enabled, role `standby`, not promoted, lag under 1 s
- primary active with an empty result queue and no pending deliveries
- one archive per execution under `/var/lib/parallaxd-recovery/<timestamp>/`
  holding `coordinator.json`, `state.json`, `observations.jsonl` and
  `recovery.json` (about 106 MB each)

Remove the archives once the rebuilt standby has been verified and backed up.
The installed configuration is the candidate's JSON rendering; the next
ordinary deployment rewrites it from the template.

## Open observation

While a large replica is applied, the standby does not answer its own API in
time. That is acceptable for a standby but worth remembering when reading
check failures during a rebuild.
