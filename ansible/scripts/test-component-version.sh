#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

version_script=ansible/scripts/component-version.sh
coordinator_before=$($version_script parallaxd)
prober_before=$($version_script parallaxd-probe)
watcher_before=$($version_script parallaxd-watch)

for version in "$coordinator_before" "$prober_before" "$watcher_before"; do
  if [[ ! $version =~ ^[0-9a-f]+(-dirty)?$ ]]; then
    echo "invalid component version: $version" >&2
    exit 1
  fi
done

# An untracked sentinel makes the coordinator package dirty without modifying
# tracked source. The watcher imports that package; the prober does not.
sentinel=internal/coordinator/.component-version-test-$$
trap 'rm -f "$sentinel"' EXIT
touch "$sentinel"

coordinator_after=$($version_script parallaxd)
prober_after=$($version_script parallaxd-probe)
watcher_after=$($version_script parallaxd-watch)

[[ $coordinator_after == *-dirty ]] || {
  echo "coordinator did not notice a dirty dependency" >&2
  exit 1
}
[[ $watcher_after == *-dirty ]] || {
  echo "watcher did not notice its dirty coordinator dependency" >&2
  exit 1
}
[[ $prober_after == "$prober_before" ]] || {
  echo "coordinator-only change altered the prober version" >&2
  exit 1
}

printf 'coordinator=%s prober=%s watcher=%s\n' \
  "$coordinator_before" "$prober_before" "$watcher_before"
