#!/usr/bin/env bash
# End-to-end check: start target-lab and proxy, run the attack scenarios, and
# assert the expected classification for each flagged scenario plus clean
# controls, by reading the WebSocket feed. Requires a built proxy and lab.
set -u
cd "$(dirname "$0")/.."

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:8080}"
API_ADDR="${API_ADDR:-127.0.0.1:8081}"
UPSTREAM="${UPSTREAM_URL:-http://127.0.0.1:9190}"

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

PROXY_ADDR="$PROXY_ADDR" API_ADDR="$API_ADDR" UPSTREAM_URL="$UPSTREAM" ./target-lab/target-lab >/tmp/e2e-lab.log 2>&1 &
pids+=($!)
sleep 0.4
PROXY_ADDR="$PROXY_ADDR" API_ADDR="$API_ADDR" UPSTREAM_URL="$UPSTREAM" ./proxy/netchimera >/tmp/e2e-proxy.log 2>&1 &
pids+=($!)
sleep 0.8

# A tiny Go WS collector verifies classifications. Built on the fly in a temp module.
work="$(mktemp -d)"
cat > "$work/main.go" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	api := os.Args[1]
	c, _, err := websocket.DefaultDialer.Dial("ws://"+api+"/ws", http.Header{"Origin": []string{"http://localhost:3000"}})
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(2)
	}
	want := map[string]string{
		"/account/profile.css": "WEB_CACHE_DECEPTION",
		"/account/avatar.png":  "WEB_CACHE_DECEPTION",
		"/api/config":          "CREDENTIAL_LEAK",
	}
	benign := map[string]bool{"/api/health": true, "/static/app.css": true, "/account": true, "/api/profile": true}
	got := map[string]string{}
	benignBad := []string{}
	fixation := false
	c.SetReadDeadline(time.Now().Add(12 * time.Second))
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		var env struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		json.Unmarshal(msg, &env)
		if env.Type != "TRANSACTION_EVENT" {
			continue
		}
		var ev struct {
			Path           string  `json:"path"`
			Classification *string `json:"classification"`
			WCD            int     `json:"cache_deception_flag"`
			Leak           int     `json:"secret_leak_flag"`
		}
		json.Unmarshal(env.Data, &ev)
		path := ev.Path
		if i := indexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if ev.Classification != nil {
			got[path] = *ev.Classification
			if path == "/login" && *ev.Classification == "SESSION_FIXATION" {
				fixation = true
			}
		}
		if benign[path] && (ev.WCD == 1 || ev.Leak == 1 || ev.Classification != nil) {
			benignBad = append(benignBad, path)
		}
	}
	fail := 0
	for p, w := range want {
		if got[p] != w {
			fmt.Printf("FAIL %s: want %s, got %q\n", p, w, got[p])
			fail++
		} else {
			fmt.Printf("ok   %s -> %s\n", p, w)
		}
	}
	if fixation {
		fmt.Println("ok   /login -> SESSION_FIXATION")
	} else {
		fmt.Println("FAIL /login: expected SESSION_FIXATION")
		fail++
	}
	if len(benignBad) > 0 {
		fmt.Printf("FAIL controls flagged: %v\n", benignBad)
		fail++
	} else {
		fmt.Println("ok   controls clean")
	}
	if fail > 0 {
		os.Exit(1)
	}
	fmt.Println("E2E PASSED")
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
GO

cp proxy/go.mod "$work/go.mod"
sed -i.bak 's#^module .*#module e2e#' "$work/go.mod" && rm -f "$work/go.mod.bak"
cp proxy/go.sum "$work/go.sum" 2>/dev/null || true
( cd "$work" && go mod tidy >/dev/null 2>&1 && go build -o e2e . ) || { echo "e2e build failed"; exit 1; }

"$work/e2e" "$API_ADDR" &
collector=$!
sleep 0.5
PROXY_URL="http://$PROXY_ADDR" ./scripts/simulate.sh >/dev/null 2>&1 || true
wait "$collector"
rc=$?
rm -rf "$work"
exit $rc
