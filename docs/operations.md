# Recurring operations

## Automated assurance

`ansible/operations.yml` installs checks independently of application deployment:

- Every fifteen minutes, each coordinator checks its role, replication freshness
  and lag, result/delivery queues, delivery/history errors, and rejection-counter
  increases. The primary also checks fresh mesh reports for every configured
  prober, monitor ownership, stale observations, and MCP initialization/status.
- The watcher independently checks that it has received a fresh authenticated
  heartbeat. Its startup grace period alone does not count as healthy.
- On a site-selected backup host, daily jobs restore each coordinator's backup
  using disposable copies and the real coordinator restore code. Their systemd
  units disable networking and make the backup filesystem read-only.

Install the local checks from `ansible` with `ansible-playbook operations.yml`.
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

Failures return nonzero and appear as failed systemd units. Connect those units
and report freshness to the site's independent monitoring; these checks do not
send messages themselves. Rejection counters use the prior report as a baseline;
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
