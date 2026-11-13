package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func originSet() map[string]struct{} {
	return map[string]struct{}{"http://localhost:3100": {}, "http://127.0.0.1:3100": {}}
}

func TestOriginAllowed(t *testing.T) {
	h := NewHub(originSet(), nil, nil)
	if !h.originAllowed("http://localhost:3100") {
		t.Error("allowed origin rejected")
	}
	if h.originAllowed("http://evil.example") {
		t.Error("disallowed origin accepted")
	}
	if h.originAllowed("") {
		t.Error("empty origin must be rejected for ws upgrades")
	}
}

func TestCorsAPI(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	handler := corsAPI(originSet(), next)

	// Disallowed origin -> 403.
	r := httptest.NewRequest("POST", "/api/simulate", nil)
	r.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST = %d, want 403", w.Code)
	}

	// Allowed origin -> passes with CORS headers.
	r = httptest.NewRequest("POST", "/api/simulate", nil)
	r.Header.Set("Origin", "http://localhost:3100")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Errorf("allowed POST = %d, want 202", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3100" {
		t.Error("missing Access-Control-Allow-Origin for allowed origin")
	}

	// Preflight -> 204.
	r = httptest.NewRequest("OPTIONS", "/api/simulate", nil)
	r.Header.Set("Origin", "http://localhost:3100")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("preflight = %d, want 204", w.Code)
	}

	// No Origin header (curl) -> allowed.
	r = httptest.NewRequest("POST", "/api/simulate", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Errorf("no-origin POST = %d, want 202", w.Code)
	}
}

func TestHandleInboundSetThreshold(t *testing.T) {
	g := NewGatekeeper(0.65, 8, time.Minute)
	h := NewHub(originSet(), nil, g.SetThreshold)

	h.handleInbound([]byte(`{"type":"SET_THRESHOLD","value":0.5}`))
	if g.Threshold() != 0.5 {
		t.Errorf("threshold = %v, want 0.5", g.Threshold())
	}
	if !drainFor(h, MsgConfigUpdated) {
		t.Error("expected a CONFIG_UPDATED broadcast")
	}

	// Invalid value: rejected, no CONFIG_UPDATED, threshold unchanged.
	h.handleInbound([]byte(`{"type":"SET_THRESHOLD","value":9}`))
	if g.Threshold() != 0.5 {
		t.Errorf("threshold changed on invalid input: %v", g.Threshold())
	}
	if drainFor(h, MsgConfigUpdated) {
		t.Error("invalid threshold should not broadcast CONFIG_UPDATED")
	}
}

func drainFor(h *Hub, typ MsgType) bool {
	for {
		select {
		case m := <-h.broadcast:
			var env Envelope
			if json.Unmarshal(m.data, &env) == nil && env.Type == typ {
				return true
			}
		default:
			return false
		}
	}
}

func TestFanoutEvictsSlowConsumer(t *testing.T) {
	h := NewHub(originSet(), nil, nil)
	slow := &wsClient{hub: h, send: make(chan []byte, 1), closeCode: websocket.CloseNormalClosure}
	fast := &wsClient{hub: h, send: make(chan []byte, 4), closeCode: websocket.CloseNormalClosure}
	h.clients[slow] = struct{}{}
	h.clients[fast] = struct{}{}
	slow.send <- []byte("prefill") // make slow client's buffer full

	h.fanout([]byte("broadcast"))

	if _, ok := h.clients[slow]; ok {
		t.Error("slow consumer should have been evicted")
	}
	if _, ok := h.clients[fast]; !ok {
		t.Error("fast consumer should remain connected")
	}
	if h.dropped.Load() == 0 {
		t.Error("expected a drop counter increment")
	}
	select {
	case <-fast.send:
	default:
		t.Error("fast consumer did not receive the broadcast")
	}
}

func TestRingReplay(t *testing.T) {
	h := NewHub(originSet(), nil, nil)
	for i := 0; i < 3; i++ {
		h.remember([]byte{byte('a' + i)})
	}
	c := &wsClient{hub: h, send: make(chan []byte, 8)}
	h.replayTo(c)
	got := ""
	for {
		select {
		case b := <-c.send:
			got += string(b)
			continue
		default:
		}
		break
	}
	if got != "abc" {
		t.Errorf("ring replay = %q, want abc (in order)", got)
	}
}

func TestServeWSRejectsBadOrigin(t *testing.T) {
	h := NewHub(originSet(), nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	_, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {"http://evil.example"}})
	if err == nil {
		t.Fatal("dial with bad origin should fail")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad-origin upgrade status = %v, want 403", resp)
	}
}

func TestServeWSAcceptsGoodOrigin(t *testing.T) {
	h := NewHub(originSet(), func() SystemStatus { return SystemStatus{} }, nil)
	go h.Run(testCtx(t))
	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {"http://localhost:3100"}})
	if err != nil {
		t.Fatalf("dial with good origin failed: %v (resp %v)", err, resp)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("good-origin upgrade status = %d, want 101", resp.StatusCode)
	}
}
