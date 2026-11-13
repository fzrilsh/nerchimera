#!/usr/bin/env bash
# Run target-lab, proxy and UI together for local development.
# Ctrl-C tears all three down cleanly.
set -u
cd "$(dirname "$0")/.."

pids=()
cleanup() {
  echo
  echo "stopping netchimera dev stack…"
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

./target-lab/target-lab &
pids+=($!)
sleep 0.4

./proxy/netchimera &
pids+=($!)
sleep 0.4

if [ -d ui/node_modules ]; then
  ( cd ui && npm run dev ) &
  pids+=($!)
else
  echo "ui/node_modules missing; run 'make ui-install' first. skipping UI." >&2
fi

echo "netchimera dev stack running:"
echo "  proxy      http://127.0.0.1:8080"
echo "  api / ws   http://127.0.0.1:8081  (ws://127.0.0.1:8081/ws)"
echo "  target-lab http://127.0.0.1:9190"
echo "  ui         http://localhost:3000"
echo "press Ctrl-C to stop."
wait
