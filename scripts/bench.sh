#!/usr/bin/env bash
# Latency benchmark: compare direct requests to the target-lab against proxied
# requests through NetChimera, and report the p50/p99 delta vs the 1ms budget.
set -u
cd "$(dirname "$0")/.."

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1:8080}"
TARGET_ADDR="${TARGET_ADDR:-127.0.0.1:9190}"
N="${N:-10000}"

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

TARGET_ADDR="$TARGET_ADDR" ./target-lab/target-lab >/tmp/bench-lab.log 2>&1 &
pids+=($!)
sleep 0.4
PROXY_ADDR="$PROXY_ADDR" UPSTREAM_URL="http://$TARGET_ADDR" ./proxy/netchimera >/tmp/bench-proxy.log 2>&1 &
pids+=($!)
sleep 0.8

work="$(mktemp -d)"
cat > "$work/main.go" <<'GO'
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

func measure(client *http.Client, url string, n int) []time.Duration {
	ds := make([]time.Duration, 0, n)
	for i := 0; i < n+300; i++ {
		t := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			panic(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if i >= 300 {
			ds = append(ds, time.Since(t))
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds
}

func q(ds []time.Duration, p float64) time.Duration { return ds[int(float64(len(ds)-1)*p)] }

func main() {
	proxyAddr, targetAddr := os.Args[1], os.Args[2]
	n, _ := strconv.Atoi(os.Args[3])
	tr := &http.Transport{MaxIdleConnsPerHost: 8, Proxy: nil}
	client := &http.Client{Transport: tr}
	direct := measure(client, "http://"+targetAddr+"/api/health", n)
	proxied := measure(client, "http://"+proxyAddr+"/api/health", n)
	fmt.Printf("requests per series: %d\n", n)
	fmt.Printf("direct   p50=%-10v p99=%v\n", q(direct, .5), q(direct, .99))
	fmt.Printf("proxied  p50=%-10v p99=%v\n", q(proxied, .5), q(proxied, .99))
	d50 := q(proxied, .5) - q(direct, .5)
	d99 := q(proxied, .99) - q(direct, .99)
	fmt.Printf("delta    p50=%-10v p99=%v\n", d50, d99)
	budget := time.Millisecond
	if d99 <= budget {
		fmt.Printf("PASS: p99 added latency %v within %v budget\n", d99, budget)
	} else {
		fmt.Printf("WARN: p99 added latency %v exceeds %v budget\n", d99, budget)
	}
}
GO

cp proxy/go.mod "$work/go.mod"
sed -i.bak 's#^module .*#module bench#' "$work/go.mod" && rm -f "$work/go.mod.bak"
( cd "$work" && go mod tidy >/dev/null 2>&1 && go build -o bench . ) || { echo "bench build failed"; exit 1; }
"$work/bench" "$PROXY_ADDR" "$TARGET_ADDR" "$N"
rc=$?
rm -rf "$work"
exit $rc
