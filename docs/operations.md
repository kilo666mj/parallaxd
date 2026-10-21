# Recurring operations

## Automated assurance

`ansible/operations.yml` installs checks independently of application deployment:

- Every fifteen minutes, each coordinator checks its role, replication freshness
  and lag, result/delivery queues, delivery/history errors, and rejection-counter
  increases. The primary also checks fresh mesh reports for every configured
  prober, monitor ownership, stale observations, and MCP initialization/status.
  Result queue depth includes in-flight processing, so a nonempty snapshot is
  rechecked once per second up to 45 times before failing, allowing for the
  default two 20-second corroboration windows. A queue that drains
  during those rechecks passes; a persistent backlog, stale diagnostics, or a
  failed diagnostics request still fails. Other health failures are preserved.
- The watcher independently checks that it has received a fresh authenticated
  heartbeat. Its startup grace period alone does not count as healthy.
- On a site-selected backup host, daily jobs restore each coordinator's backup
  using disposable copies and the real coordinator restore code. Their systemd
  units disable networking and make the backup filesystem read-only.

Install the local checks from `ansible` with `ansible-playbook operations.yml`.
Use `--tags assurance-checker` to update only the Python checker without changing
units, timers, or the standalone verifier.
To include backup verification, first build a binary for the backup host:

```sh
CGO_ENABLED=0 go build -o /tmp/parallaxd-verify ./cmd/parallaxd
```

Keep the backup host and paths in a private variables file, for example:

```yaml
parallaxd_backup_verify_hosts: backup-admin
parallaxd_verify_binary: /tmp/parallaxd-verify
parallaxd_backup_roots:
  - name: primary
    root: /backups/remote/primary.example
  - name: standby
    root: /backups/remote/standby.example
parallaxd_backup_verify_calendar: '*-*-* 06:30:00'
```

Then run `ansible-playbook operations.yml -e @/secure/operations.yml` from
`ansible`. Set the calendar after the site's backup window. The verifier is
installed separately from the running coordinator; update it when the state
format changes. This playbook does not create backups or define retention.

The default local checker reads the existing operator credential from the
coordinator configuration, uses it only for reads, and never prints it. A
dedicated viewer token can be supplied with the checker's `--token-file` option.
MCP checks run only on the primary because the standby blocks POST requests.

Inspect the results with:

```sh
systemctl list-timers 'parallaxd-*'
cat /var/lib/parallaxd-operations/coordinator.json
journalctl -u parallaxd-verify-backup-primary.service
```

Failures return nonzero and appear as failed systemd units. To be told
immediately, set `parallaxd_assurance_alert_destination_name` to the name of a
Tintwire entry in `parallaxd_notification_destinations` and pass
`parallaxd_verify_binary` for every assurance host, not only the backup host.
It may include `{{ parallaxd_goarch }}` (`amd64`, `arm64`) when hosts differ:

```sh
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOARCH=$arch go build -o /tmp/parallaxd-verify-$arch ./cmd/parallaxd
done
# parallaxd_verify_binary: /tmp/parallaxd-verify-{{ parallaxd_goarch }}
```

Each assurance and backup-verification unit then gets `OnFailure=` and
`OnSuccess=` hooks that run the verifier binary with `-assurance-alert`: a
failure publishes a firing card (with the unit's last journal lines) through
Tintwire, falling back to the destination's Mattermost webhook, and the next
success resolves it. Successes with no open failure send nothing. To test the
path on one host:

```sh
systemctl start parallaxd-assurance-failed@parallaxd-operations-coordinator.service.service
systemctl start parallaxd-assurance-ok@parallaxd-operations-coordinator.service.service
```

The hooks do not cover a timer that stops firing or a host that is down; keep
report freshness in the site's independent monitoring. Rejection counters use the prior report as a baseline;
the first run establishes that baseline, and lower counts allow for restarts.

To verify a filesystem backup manually:

```sh
parallaxd -verify-backup /backups/remote/primary.example
```

The root must contain `/etc/parallaxd/coordinator.json`, every referenced key
and credential file, and the configured state and observation journal at their
original absolute paths. Missing files, escaping symlinks, malformed journal
records, unsupported state versions, and restore errors fail verification.
No listeners or workers start. Normal restore may compact expired observations
or bootstrap an administrator, so it operates only on private temporary copies.
Backup age, historic retention, off-host transfer, and end-to-end alert delivery
remain separate checks; a successful restore does not establish those properties.

## Targeted deployments

Run these commands from the repository's `ansible` directory. Use tags for
routine changes instead of reconciling the entire fleet:

```sh
# Catalogue, trust anchors, and service configuration
ansible-playbook playbook.yml --tags config

# Rebuild/install binaries and restart affected services
ansible-playbook playbook.yml --tags code

# WireGuard and firewall topology only
ansible-playbook playbook.yml --tags network

# First-install accounts, directories, firewalld, and signing keys
ansible-playbook playbook.yml --tags bootstrap
```

Run the untagged playbook for a full reconciliation. Code and configuration
tags include the service-specific plays so changed binaries restart only after
their configuration is present and validated.

The repository enables SSH connection multiplexing and Ansible pipelining.
Do not replace `ssh_args` without retaining `ControlMaster` and
`ControlPersist`; doing so creates a new SSH connection for nearly every task
and makes even configuration-only runs unnecessarily slow.

Automation should prove each layer independently. A green coordinator page is
not evidence that its backup restores, and a running standby process is not
evidence that it has a usable recovery point.

## Coordinator metrics

`GET /metrics` serves the coordinator's own health in the Prometheus text
format. It needs a `viewer` credential, like the rest of the operator API, and
works on the standby too, so scrape both coordinators. Labels name only
configured checks, probers and notification destinations, plus fixed rejection
reasons, so the number of series stays bounded.

| Metric | Meaning |
|---|---|
| `parallaxd_ha_active`, `parallaxd_ha_promoted`, `parallaxd_ha_role{role}` | Which coordinator is writing |
| `parallaxd_replication_lag_seconds`, `parallaxd_replication_last_sync_timestamp_seconds`, `parallaxd_replication_error` | Standby replication |
| `parallaxd_result_queue_depth`, `parallaxd_result_queue_capacity`, `parallaxd_results_rejected_total{reason}` | Result intake |
| `parallaxd_corroborations_total`, `parallaxd_corroborations_inconclusive_total`, `parallaxd_corroboration_duration_seconds_total` | Corroboration count, inconclusive rate and average latency |
| `parallaxd_notifications_pending`, `parallaxd_notifications_oldest_pending_age_seconds`, `parallaxd_notification_{attempts,failures}_total{destination}` | Alert delivery |
| `parallaxd_history_write_failures_total` | Observation journal |
| `parallaxd_incidents_active`, `parallaxd_incidents_suppressed` | Open incidents |
| `parallaxd_check_status{check,status}`, `parallaxd_check_stale`, `parallaxd_check_suspected`, `parallaxd_check_last_verdict_age_seconds` | Per-check state |
| `parallaxd_prober_mesh_report_age_seconds`, `parallaxd_prober_isolated`, `parallaxd_prober_silent` | Per-prober freshness |

Counters reset when the coordinator restarts. Average corroboration latency is
`rate(parallaxd_corroboration_duration_seconds_total[30m]) /
rate(parallaxd_corroborations_total[30m])`.

Store a dedicated viewer token on the Prometheus host and scrape over the same
private transport you use for the operator API:

```yaml
scrape_configs:
  - job_name: parallaxd
    metrics_path: /metrics
    authorization:
      credentials_file: /etc/prometheus/parallaxd-viewer.token
    static_configs:
      - targets: ["coordinator-a.example.com:8972", "coordinator-b.example.com:8972"]
```

Load [`docs/prometheus/parallaxd-alerts.yml`](prometheus/parallaxd-alerts.yml)
as a rule file. It covers what parallaxd cannot report through its own
notifications: no active coordinator or two at once, failing replication, an
undelivered alert backlog, a saturated result queue, journal write failures,
and corroboration that keeps ending inconclusive. Check it with
`promtool check rules` after editing.

## Uptime

`GET /v1/uptime` (viewer role) reports, for every check and component, the
share of a period spent outside a corroborated outage. The default period is
the last 30 days; pass `since` and `until` (RFC 3339) for another one, for
example a calendar month. The MCP tool `parallaxd_get_uptime` takes the same
parameters, the status export includes the last 30 days, and the dashboard's
History view shows it beside each check.

Uptime comes from durable `down` incidents, not from observation history,
which keeps at most `history_max_per_check` results and so may not reach back a
month. Only quorum-decided outages count: inconclusive or stale periods are
not downtime. Outage time that falls inside a matching maintenance window,
including each occurrence of a recurring one, is excluded from downtime and
reported as `maintenance_seconds`. A deleted maintenance window no longer
excludes anything. A check added part-way through the period is measured over
the whole period.

## Maintenance windows

During a maintenance window, matching alerts are recorded as suppressed
incidents but not delivered. If an incident is still active when the window
ends, or when the window is deleted or narrowed, it is delivered then. Scope a
window with `checks`, `components` and `probers`; leave all three empty to
cover the whole fleet.

Windows come from two places:

- `parallaxd_maintenance` in the coordinator configuration. These are
  read-only through the API and change only with an Ansible rollout.
- The operator API, MCP tools (`parallaxd_create_maintenance`,
  `parallaxd_update_maintenance`, `parallaxd_delete_maintenance`) or the
  dashboard's Incidents page. These are stored in coordinator state, replicated
  to the standby, and record who created and last changed them.

`every` repeats a window at a fixed period after `starts_at`, for example
`"24h"` or `"168h"`, and must be longer than the window itself. The period is a
fixed duration, so a weekly window keeps its UTC time and moves by an hour in
local time when daylight saving time changes.

```sh
curl -fsS -H "Authorization: Bearer $PARALLAXD_TOKEN" \
  -d '{"name":"os-patching","starts_at":"2026-11-01T03:00:00Z",
       "ends_at":"2026-11-01T04:00:00Z","every":"168h","probers":["probe-a"]}' \
  https://status.example.com/v1/maintenance
```

`PUT /v1/maintenance/{name}` replaces a managed window and `DELETE` removes it;
both require the `operator` role. A coordinator older than this feature refuses
to load state that contains managed windows, so upgrade the standby before
creating the first one.

## Status notices

Notices are operator-written posts for status pages: an incident with a
timeline of updates, or announced maintenance. They are presentation only.
They never change a corroborated status, open or close an automatic incident,
or suppress an alert; use a maintenance window or silence for that. Post a
maintenance notice and create a matching window when you want both.

| Kind | States, in order |
|---|---|
| `incident` | `investigating`, `identified`, `monitoring`, `resolved` |
| `maintenance` | `scheduled`, `in_progress`, `completed` |

Maintenance needs `starts_at` and `ends_at`; incidents have neither. Each
update adds a timeline entry and may change the state. Posting the last state
resolves the notice and any other state reopens it.

Only notices with `public: true` reach the signed export, and through it the
[status page](status-page.md): open ones, plus those resolved in the last
week. The export leaves out who wrote each update. It carries at most 20
notices, the 10 newest updates of each, and 128 KiB of text.

```sh
curl -fsS -H "Authorization: Bearer $PARALLAXD_TOKEN" \
  -d '{"kind":"incident","title":"Slow logins","public":true,
       "checks":["login"],"message":"We are investigating slow logins."}' \
  https://status.example.com/v1/notices
curl -fsS -H "Authorization: Bearer $PARALLAXD_TOKEN" \
  -d '{"state":"resolved","message":"A fix is deployed."}' \
  https://status.example.com/v1/notices/1/updates
```

`PUT /v1/notices/{id}` replaces the title, `public`, affected items and
schedule; `DELETE` removes a notice posted by mistake. All three need the
`operator` role, as do the MCP tools (`parallaxd_create_notice`,
`parallaxd_post_notice_update`, `parallaxd_edit_notice`,
`parallaxd_delete_notice`) and the dashboard's Incidents page. Notices are
stored in coordinator state and replicated to the standby. Resolved notices
are dropped 90 days after resolution. A coordinator older than this feature
refuses to load state that contains notices, so upgrade the standby before
posting the first one.

## Every day

- Confirm a dedicated viewer credential can initialize `/mcp` and call
  `parallaxd_get_status`; do not use an administrator token for this check.
- Check primary `/v1/diagnostics`: result queue depth and pending
  notifications are zero, no destination has a current error, and rejection
  counters have not unexpectedly increased.
- Check standby `/v1/ha`: role is `standby`, `active` and `promoted` are false,
  the last sync is recent, apply lag is within the recovery objective, and the
  replication error is empty.
- Check watcher `/v1/status`: its last authenticated heartbeat is inside the
  configured grace period.
- Confirm every expected prober appears in `/v1/export`, owns or is eligible
  for checks, and has fresh evidence.

## Every week

- Run `ansible-playbook --check --diff playbook.yml` from a transport path that
  permits Ansible (see below) and review all drift before applying it.
- Verify the latest archives on both coordinators include `/etc/parallaxd` and
  `/var/lib/parallaxd`, copy successfully off-host, and meet retention policy.
- Restore the newest archive into a disposable directory and parse the JSON
  state and observation journal. Archive existence alone is not a restore
  test.
- Check the deployed component versions against the expected source versions
  from `ansible/scripts/component-version.sh`.
- Review Firewalld runtime and permanent configuration together; a runtime-only
  rule will disappear at reboot.

## Every month

- Exercise one disposable down/recovery transition and verify Mattermost
  delivery into `#parallaxd` with the project name and icon.
- Rehearse `parallaxd-ha -preflight-only`; do not fence or promote outside an
  announced HA exercise.
- Review users, API tokens, external access policy, mTLS certificate expiry,
  and the operator/replication secret distribution path.
- Review MCP client credentials and revoke unused tokens. Confirm each client
  still has the minimum role and that `/mcp` remains behind the intended TLS,
  source allowlist, VPN, or private transport boundary.
- Restore a backup into a disposable coordinator and confirm incidents,
  silences, users, monitor revisions, history, and pending deliveries load.

GitHub runs dependency vulnerability scanning weekly and Dependabot checks Go
modules and Actions weekly. Production health, backup restores, delivery, and
configuration drift remain site checks because GitHub cannot reach the private
fleet and should not hold its credentials.

## Command-restricting SSH gateway

Normal Ansible execution requires a remote shell capable of running its Python
module wrapper and a transfer mechanism for module payloads and binaries.
If a command-restricting gateway permits selected interactive commands but
rejects these requirements, treat the failed Ansible preflight as a deployment
blocker.

If that access regresses, use one of these controlled paths:

1. Preferred: run Ansible from an internal administration host that reaches
   SSH directly, leaving the public command gateway restricted.
2. Add a separate, source-restricted deployment endpoint/account whose forced
   command admits Ansible's shell, Python, and transfer protocol, with its own
   audited key and no interactive use.

Do not broaden the ordinary gateway allowlist until arbitrary shell wrappers
work; that would effectively remove the restriction while presenting it as a
collection of individual exceptions. The inventory can select the deployment
path with `ansible_host`, `ansible_port`, and `ansible_user`; keep
`parallaxd_address` as the service address.
