#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <command-package>" >&2
  exit 2
fi

component=$1
repo_root=$(git rev-parse --show-toplevel)
package="./cmd/${component}"
dependency_paths=()

# go list is the authority on which project packages enter each binary. This
# keeps deployment selection correct when imports change without maintaining a
# second, inevitably stale dependency map in Ansible.
while IFS= read -r directory; do
  [[ -n $directory ]] || continue
  case "$directory" in
    "$repo_root"/*)
      dependency_paths+=("${directory#"$repo_root"/}")
      ;;
  esac
done < <(go list -deps -f '{{if .Module}}{{.Dir}}{{end}}' "$package")

if [[ ${#dependency_paths[@]} -eq 0 ]]; then
  echo "no project dependencies found for ${package}" >&2
  exit 1
fi

version=$(git log -1 --format=%h -- "${dependency_paths[@]}")
if [[ -z $version ]]; then
  version=dev
fi

# Only dirtiness in this component's transitive source set matters. Editing a
# README or coordinator-only package must not manufacture a new prober build.
if [[ -n $(git status --porcelain -- "${dependency_paths[@]}") ]]; then
  version="${version}-dirty"
fi

printf '%s\n' "$version"
