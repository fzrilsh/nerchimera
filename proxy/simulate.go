package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	simulateCooldown = 5 * time.Second
	simulatePacing   = 150 * time.Millisecond
	simulateTimeout  = 30 * time.Second
)

// scenario is one request the simulator sends through the proxy's own listener.
type scenario struct {
	method  string
	path    string
	headers map[string]string
	expect  string
}

// simulationScenarios are fixed and server-defined. The endpoint never accepts
// a client-supplied URL, so it cannot be used as an open request generator.
var simulationScenarios = []scenario{
	{method: "GET", path: "/api/health", expect: "benign"},
	{method: "GET", path: "/static/app.css", expect: "benign (web cache deception control)"},
	{method: "GET", path: "/account", headers: map[string]string{"Cookie": "session=demo-session-value-1234"}, expect: "benign (no-store, private)"},
	{method: "GET", path: "/account/profile.css", headers: map[string]string{"Cookie": "session=demo-session-value-1234"}, expect: "WEB_CACHE_DECEPTION"},
	{method: "GET", path: "/account/avatar.png", headers: map[string]string{"Cookie": "session=demo-session-value-1234"}, expect: "WEB_CACHE_DECEPTION"},
	{method: "GET", path: "/api/config", expect: "CREDENTIAL_LEAK"},
	{method: "POST", path: "/login?session=ATTACKER-FIXED-SESSION-0001", expect: "SESSION_FIXATION"},
	{method: "GET", path: "/api/profile", headers: map[string]string{"Authorization": "Bearer q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA"}, expect: "benign (legit bearer below threshold)"},
}

// Simulator runs the fixed attack scenarios through the proxy listener.
type Simulator struct {
	proxyAddr string
	client    *http.Client
	hub       *Hub

	mu      sync.Mutex
	lastRun time.Time
	runSeq  int
}

func NewSimulator(proxyAddr string, hub *Hub) *Simulator {
	// A dedicated transport that always dials the proxy listener, ignoring the
	// request URL's host, so scenarios can target localhost by loopback.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, proxyAddr)
		},
		MaxIdleConns:    8,
		IdleConnTimeout: 10 * time.Second,
	}
	return &Simulator{
		proxyAddr: proxyAddr,
		client:    &http.Client{Transport: tr, Timeout: 5 * time.Second},
		hub:       hub,
	}
}

func (s *Simulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	since := time.Since(s.lastRun)
	if !s.lastRun.IsZero() && since < simulateCooldown {
		retry := int((simulateCooldown - since).Seconds()) + 1
		s.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":       "simulation is rate limited",
			"retry_after": retry,
		})
		return
	}
	s.lastRun = time.Now()
	s.runSeq++
	runID := fmt.Sprintf("sim-%d", s.runSeq)
	s.mu.Unlock()

	go s.run(runID)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":    runID,
		"scenarios": len(simulationScenarios),
		"status":    "started",
	})
}

func (s *Simulator) run(runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), simulateTimeout)
	defer cancel()
	s.hub.Telemetry("info", "pipeline", fmt.Sprintf("%s: replaying %d attack scenarios through the proxy", runID, len(simulationScenarios)))
	for i, sc := range simulationScenarios {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(simulatePacing):
			}
		}
		s.send(ctx, sc)
	}
	s.hub.Telemetry("info", "pipeline", runID+": attack simulation complete")
}

func (s *Simulator) send(ctx context.Context, sc scenario) {
	url := "http://" + s.proxyAddr + sc.path
	req, err := http.NewRequestWithContext(ctx, sc.method, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "netchimera-simulator")
	req.Header.Set("X-NetChimera-Scenario", strings.ReplaceAll(sc.expect, "\n", " "))
	for k, v := range sc.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		slog.Debug("simulator request failed", "path", sc.path, "err", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
