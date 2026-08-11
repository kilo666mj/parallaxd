# Coordinator failover drill

The standby is deliberately manual. Promotion is one-way and must follow
positive fencing of the old primary; reachability loss alone is not fencing.
Run this drill in a maintenance window with console access to both hosts.

## Prepare

- [ ] Record the active commit, primary and standby hosts, coordinator service
      address, DNS/VIP TTL, operator, start time, and rollback owner.
- [ ] Confirm recent restorable backups of coordinator state, observation
      history, coordinator key, and required secret files.
- [ ] Verify `/v1/ha` reports the expected roles, a recent successful sync, no
      replication error, and acceptable lag.
- [ ] Verify the watcher is receiving heartbeats and probers are reporting.
- [ ] Open the standby dashboard and confirm its replicated catalogue,
      incidents, silences, history, users, and pending deliveries.
- [ ] Prepare the exact service-address move and its reversal before fencing.

Abort before promotion if replication is stale beyond the site's recovery
objective, required state is absent, the standby identity differs, or the old
primary cannot be positively fenced.

## Promote

1. Stop and disable or otherwise fence the old primary. Verify from an
   independent control path that it cannot restart or accept coordinator
   traffic.
2. Recheck the standby's final sync timestamp and record the recovery point.
   The guarded command performs this check without changing state:

   ```sh
   parallaxd-ha -target https://standby.internal:8972 -preflight-only
   ```

3. Promote with the guarded command after the independent fence verification:

   ```sh
   parallaxd-ha -target https://standby.internal:8972 \
     -token-file /secure/operator-token -actor drill-operator \
     -confirm-primary-fenced
   ```

   The equivalent authenticated API request is:

   ```sh
   curl -fsS -X POST https://standby.internal:8972/v1/ha/promote \
     -H "Authorization: Bearer $PARALLAXD_OPERATOR_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"actor":"drill-operator","confirm_primary_fenced":true}'
   ```

4. Move the coordinator service address to the promoted host.

Do not continue if promotion returns an error. Preserve both state files and
diagnostics for investigation; never start both coordinators as primary.

## Verify

- [ ] `/v1/ha` identifies the standby as promoted primary after a restart.
- [ ] Probers submit fresh results and fetch assignments through the service
      address.
- [ ] A disposable monitor completes a down/recovery cycle with one alert per
      transition.
- [ ] Existing incidents, silences, catalogue revisions, users, tokens,
      observation history, and pending deliveries are present.
- [ ] Pending notifications resume in order without duplicates.
- [ ] The watcher receives heartbeats from the promoted coordinator.
- [ ] Diagnostics show no sustained queue, rejection, or delivery failures.
- [ ] The measured recovery point and recovery time are recorded.

## Re-establish redundancy

Promotion is not reversed. Keep the former primary fenced until it has been
rebuilt as a standby following the current active coordinator.

- [ ] Preserve or archive its old state before reconfiguration.
- [ ] Configure it as standby with the current coordinator identity and
      replication credential through the normal secret-distribution path.
- [ ] Start it only after confirming standby role configuration.
- [ ] Verify a complete sync, acceptable lag, and read-only standby behavior.
- [ ] Update inventory/runbooks if the service address or host roles changed.

## Abort and recovery rules

- Before promotion, restore the original primary only after removing the
  condition that caused the drill to abort.
- After successful promotion, do not return the old primary to service as a
  primary. Recover availability on the promoted host and rebuild redundancy.
- If the promoted host fails before the address move, retain the old primary's
  fence until operators choose a single authoritative state. Never infer the
  winner from which host happens to answer.
