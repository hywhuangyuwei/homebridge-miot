#!/usr/bin/env zsh

# Alternates between Node and Python commands every 3 seconds.
# Stop with Ctrl-C.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

INTERVAL_SEC=5

run_cmd() {
  local label="$1"
  shift
  local -a cmd=("$@")

  print -r -- "----"
  print -r -- "[$(date '+%Y-%m-%d %H:%M:%S')] $label"

  "${cmd[@]}"
  local rc=$?
  print -r -- "[$(date '+%Y-%m-%d %H:%M:%S')] exit=$rc"
  return 0
}

while true; do
  run_cmd "python algo action" python3 algo_min.py
  sleep "$INTERVAL_SEC"
done
