# Recurring operations

Automation should prove each layer independently. A green coordinator page is
not evidence that its backup restores, and a running standby process is not
evidence that it has a usable recovery point.

## Every day

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
- Restore a backup into a disposable coordinator and confirm incidents,
  silences, users, monitor revisions, history, and pending deliveries load.

GitHub runs dependency vulnerability scanning weekly and Dependabot checks Go
modules and Actions weekly. Production health, backup restores, delivery, and
configuration drift remain site checks because GitHub cannot reach the private
fleet and should not hold its credentials.

## Command-restricting SSH gateway

Normal Ansible execution requires a remote shell capable of running its Python
module wrapper and a transfer mechanism for module payloads and binaries. The
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
