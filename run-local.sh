#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required. Install Go 1.26.4 or newer, then run this script again." >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "Node.js and npm are required. Install Node.js 20.19+ or 22.12+, then run this script again." >&2
  exit 1
fi

if [[ ! -d frontend/node_modules ]]; then
  echo "Installing dashboard dependencies..."
  (cd frontend && npm ci)
fi

backend_pid=""
frontend_pid=""
stop_children() {
  [[ -z "$backend_pid" ]] || kill "$backend_pid" 2>/dev/null || true
  [[ -z "$frontend_pid" ]] || kill "$frontend_pid" 2>/dev/null || true
  [[ -z "$backend_pid" ]] || wait "$backend_pid" 2>/dev/null || true
  [[ -z "$frontend_pid" ]] || wait "$frontend_pid" 2>/dev/null || true
}
trap stop_children EXIT INT TERM

echo "Starting Hive services on this computer only. Press Ctrl+C to stop."
go run ./cmd/hive &
backend_pid=$!
(cd frontend && npm run dev -- --host 127.0.0.1) &
frontend_pid=$!

set +e
wait -n "$backend_pid" "$frontend_pid"
status=$?
set -e
if [[ $status -ne 0 ]]; then
  echo "A Hive process stopped with an error. Check the messages above; a port may already be in use." >&2
fi
exit "$status"
