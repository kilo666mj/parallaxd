# Operational acceptance exercise

Run this checklist after a topology change and before declaring a release
operational. Use a disposable target and a maintenance window. Do not interrupt
a production dependency merely to test monitoring.

## Record

- Date, release commit, operator, and maintenance window:
- Coordinator, standby, watcher, and participating probers:
- Disposable public and internal monitor names:
- Alert destinations used:
- Start and finish dashboard/API snapshots:

Save the relevant `/v1/status`, `/v1/assignments`, `/v1/mesh`,
`/v1/diagnostics`, `/v1/incidents`, `/v1/deliveries`, and `/v1/ha` responses
with the exercise record. Remove credentials and sensitive monitor headers.

## Preconditions

- [ ] The worktree release matches the deployed binary versions.
- [ ] Coordinator, standby, watcher, and at least three eligible probers are
      healthy.
- [ ] Standby replication is current and has no reported error.
- [ ] Test monitors have an eligible pool large enough to preserve quorum when
      one prober is removed.
- [ ] Every network or service disruption below has a tested rollback command.
- [ ] Someone is watching the real alert destination during the exercise.

## Baseline

- [ ] Public HTTP or TCP, internal HTTP or TCP, and ICMP test monitors report
      `up` over several intervals.
- [ ] Assignments name eligible owners; the internal monitor is never assigned
      to a prober outside its configured pool.
- [ ] Mesh visibility is current and no unexpected prober is isolated.
- [ ] Diagnostics show no growing rejection, queue, replication, or delivery
      errors.

## Target failure and recovery

1. Stop only the disposable target or install a narrowly scoped temporary
   reject rule on that target.
2. Wait for its assigned prober to report failure and for corroboration to
   finish.
3. Restore the target immediately after collecting the failure evidence.

- [ ] Exactly one `down` transition is delivered.
- [ ] The verdict contains the expected vote and provider counts.
- [ ] One incident is retained with the suspicion and decision timestamps.
- [ ] Repeated failing intervals do not produce duplicate down alerts.
- [ ] Exactly one recovery transition is delivered after restoration.
- [ ] History contains scheduled and corroboration observations with the
      latter excluded from availability calculations.

## Assigned-prober loss

1. Record the test monitor's effective owner.
2. Stop only that prober service.
3. Wait past its assignment/heartbeat eligibility threshold.
4. Start it again after reassignment is visible.

- [ ] The monitor moves to another member of its eligible pool.
- [ ] The stopped prober produces a grouped `silent` alert and no target-down
      incident merely because it stopped reporting.
- [ ] Scheduled observations resume under the replacement owner.
- [ ] The returning prober produces the corresponding recovery transition.
- [ ] Assignment converges without restarting the coordinator.

## Mesh isolation

Use host-local, narrowly scoped rules that block only the chosen test prober's
mesh connections. Keep coordinator connectivity intact so it can report its
view. Apply and remove rules through the site's normal firewall tooling.

- [ ] The prober reports that it reached none of at least two peers.
- [ ] The coordinator marks it isolated and excludes its evidence.
- [ ] Its checks move to healthy eligible owners when capacity permits.
- [ ] Isolation does not manufacture target-down incidents.
- [ ] Removing the rules clears isolation after a fresh mesh report.

## Guardrails and delivery durability

- [ ] A test request outside an internal prober's `allow_targets` is `unknown`,
      not `down`, and opens no connection to the blocked address.
- [ ] A deliberately unavailable test webhook leaves a pending durable
      delivery with a useful diagnostic error.
- [ ] Restoring the webhook delivers queued `down` before a later `recovered`
      event and clears the queue.

## Restart persistence

Restart the coordinator normally; do not remove state or history files.

- [ ] Monitor catalogue and revision history survive.
- [ ] Incidents, acknowledgements, silences, users/tokens, and pending
      deliveries survive.
- [ ] Observation history remains queryable.
- [ ] Probers fetch assignments and resume reporting.
- [ ] Restart produces no synthetic recovery or duplicate incident alerts.
- [ ] Standby replication becomes current again.

## Completion

- [ ] All temporary services, monitors, firewall rules, routes, and silences
      have been removed or restored.
- [ ] Unexpected behavior has an issue with timestamps and redacted evidence.
- [ ] The exercise record states pass/fail and names any accepted exceptions.
