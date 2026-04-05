#!/bin/sh

set -eu

repo_root="$(git rev-parse --show-toplevel)"
hooks_dir="$repo_root/.git/hooks"

install -m 755 "$repo_root/scripts/commit-msg.sh" "$hooks_dir/commit-msg"
printf '%s\n' "Installed commit-msg hook at $hooks_dir/commit-msg"
