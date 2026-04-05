#!/bin/sh

set -eu

commit_msg_file="$1"
subject="$(head -n 1 "$commit_msg_file")"

case "$subject" in
  Merge\ *|Revert\ *)
    exit 0
    ;;
esac

if printf '%s\n' "$subject" | grep -Eq '^(feat|fix|docs|style|refactor|test|chore|build|ci|perf|revert)(\([A-Za-z0-9._-]+\))?!?: .+'; then
  exit 0
fi

printf '%s\n' "Invalid commit message: $subject" >&2
printf '%s\n' "Use Conventional Commits, e.g. 'fix: handle host rotation'" >&2
exit 1
