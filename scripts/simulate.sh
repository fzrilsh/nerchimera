#!/usr/bin/env bash
# Replay NetChimera's attack scenarios through the proxy with curl.
# Mirrors the fixed scenario list in proxy/simulate.go so judges can trigger the
# full pipeline from a terminal. Watch the UI or the WebSocket feed while it runs.
set -u

PROXY="${PROXY_URL:-http://127.0.0.1:8080}"
PACE="${PACE:-0.15}"
COOKIE="Cookie: session=demo-session-value-1234"
BEARER="Authorization: Bearer q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA"

req() {
  local method="$1" path="$2" expect="$3"; shift 3
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" \
    -H "User-Agent: netchimera-simulator" -H "X-NetChimera-Scenario: ${expect}" \
    "$@" "${PROXY}${path}")
  printf '  %-4s %-42s -> HTTP %s   (%s)\n' "$method" "$path" "$code" "$expect"
  sleep "$PACE"
}

echo "NetChimera attack simulation via ${PROXY}"
req GET  /api/health                                 "benign"
req GET  /static/app.css                             "benign (WCD control)"
req GET  /account                          "benign (no-store)"     -H "$COOKIE"
req GET  /account/profile.css              "WEB_CACHE_DECEPTION"   -H "$COOKIE"
req GET  /account/avatar.png               "WEB_CACHE_DECEPTION"   -H "$COOKIE"
req GET  /api/config                                 "CREDENTIAL_LEAK"
req POST "/login?session=ATTACKER-FIXED-SESSION-0001" "SESSION_FIXATION"
req GET  /api/profile                      "benign (legit bearer)" -H "$BEARER"
echo "done"
