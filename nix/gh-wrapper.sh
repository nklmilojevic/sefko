#!/bin/sh
# gh with GH_TOKEN from sefko. The gh and sefko paths are filled in at build time.
if [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
  exec @gh@ "$@"
fi
GH_TOKEN=$(@sefko@ get github) || exit 1
export GH_TOKEN
@gh@ "$@"
rc=$?
[ "$rc" -eq 0 ] && exit 0
@sefko@ validate github >/dev/null 2>&1
if [ $? -eq 10 ]; then
  # A 401 means the first attempt changed nothing, so retrying is safe, but
  # piped stdin was already consumed.
  if [ -t 0 ]; then
    GH_TOKEN=$(@sefko@ get github) || exit "$rc"
    exec @gh@ "$@"
  fi
  echo "sefko: GitHub token was invalid and has been refreshed; re-run the command" >&2
fi
exit "$rc"
