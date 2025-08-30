#!/usr/bin/env bash
set -euo pipefail

kill_and_wait() {
  local name="$1"
  # Try to kill; ignore if not running
  pkill -x "$name" >/dev/null 2>&1 || true
  # Wait up to ~10s for exit
  for _ in $(seq 1 50); do
    pgrep -x "$name" >/dev/null 2>&1 || return 0
    sleep 0.2
  done
  # Still running; warn but continue
  if pgrep -x "$name" >/dev/null 2>&1; then
    echo "Warning: $name still running" >&2
  fi
}

for p in as signer client; do
  kill_and_wait "$p"
done

exit 0