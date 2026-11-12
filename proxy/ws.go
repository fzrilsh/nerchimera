package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type MsgType string

const (
	MsgTransaction     MsgType = "TRANSACTION_EVENT"
	MsgEngineTelemetry MsgType = "ENGINE_TELEMETRY"
	MsgSystemStatus    MsgType = "SYSTEM_STATUS"
	MsgAIPatchStream   MsgType = "AI_PATCH_STREAM"
	MsgAIPatchEvent    MsgType = "AI_PATCH_EVENT"
	MsgConfigUpdated   MsgType = "CONFIG_UPDATED"
)

const (
	hubBroadcastCap  = 1024
	hubRegisterCap   = 16
	hubUnregisterCap = 64
	clientSendCap    = 256
	ringCap          = 200
	maxWSClients     = 32
	wsReadLimit      = 4096
	wsPingInterval   = 30 * time.Second
	wsPongWait       = 60 * time.Second
	wsWriteWait      = 10 * time.Second
	statusInterval   = time.Second
)

type Envelope struct {
	Type MsgType `json:"type"`
	TS   int64   `json:"ts"`
	Data any     `json:"data"`
}

type EngineTelemetry struct {
	Level  string `json:"level"`
	Source string `json:"source"`
	Msg    string `json:"msg"`
}

type ConfigUpdated struct {
	Threshold float64 `json:"threshold"`
}

type EngineStatus struct {
	Status  string  `json:"status"`
	Version string  `json:"version"`
	Calls   uint64  `json:"calls"`
	Errors  uint64  `json:"errors"`
	MeanUs  float64 `json:"mean_us"`
}

type PoolStatus struct {
	Workers  int     `json:"workers"`
	QueueLen int     `json:"queue_len"`
	QueueCap int     `json:"queue_cap"`
	Dropped  uint64  `json:"dropped"`
	Load     float64 `json:"load"`
}

type AIStatus struct {
	Mode      string `json:"mode"`
	Status    string `json:"status"`
	Model     string `json:"model"`
	QueueLen  int    `json:"queue_len"`
	QueueCap  int    `json:"queue_cap"`
	Processed uint64 `json:"processed"`
	Dropped   uint64 `json:"dropped"`
}

type HubStatus struct {
	Clients int64  `json:"clients"`
	Dropped uint64 `json:"dropped"`
}

type SystemStatus struct {
	Engine    EngineStatus `json:"engine"`
	Pool      PoolStatus   `json:"pool"`
	AI        AIStatus     `json:"ai"`
	Hub       HubStatus    `json:"hub"`
	Threshold float64      `json:"threshold"`
}

type hubMessage struct {
	data   []byte
	replay bool
}

// Hub fans messages out to WebSocket clients. The Run goroutine is the only
// owner of clients and the replay ring; everything else talks to it through
// bounded channels.
type Hub struct {
	origins        map[string]struct{}
	upgrader       websocket.Upgrader
	register       chan *wsClient
	unregister     chan *wsClient
	broadcast      chan hubMessage
	done           chan struct{}
	status         func() SystemStatus
	onSetThreshold func(float64) error

	clients  map[*wsClient]struct{}
	ring     [ringCap][]byte
	ringHead int
	ringLen  int

	dropped     atomic.Uint64
	clientCount atomic.Int64
}

type wsClient struct {
	hub       *Hub
	conn      *websocket.Conn
	send      chan []byte
	closeCode int
}

func NewHub(origins map[string]struct{}, status func() SystemStatus, onSetThreshold func(float64) error) *Hub {
	h := &Hub{
		origins:        origins,
		register:       make(chan *wsClient, hubRegisterCap),
		unregister:     make(chan *wsClient, hubUnregisterCap),
		broadcast:      make(chan hubMessage, hubBroadcastCap),
		done:           make(chan struct{}),
		status:         status,
		onSetThreshold: onSetThreshold,
		clients:        make(map[*wsClient]struct{}),
	}
	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 16384,
		CheckOrigin:     func(r *http.Request) bool { return h.originAllowed(r.Header.Get("Origin")) },
	}
	return h
}

func (h *Hub) originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	_, ok := h.origins[strings.ToLower(origin)]
	return ok
}

// Publish never blocks. When the broadcast buffer is full the message is dropped and counted.
func (h *Hub) Publish(t MsgType, data any) {
	b, err := json.Marshal(Envelope{Type: t, TS: time.Now().UnixMilli(), Data: data})
	if err != nil {
		slog.Error("hub: marshal envelope", "type", t, "err", err)
		return
	}
	select {
	case h.broadcast <- hubMessage{data: b, replay: t == MsgTransaction || t == MsgAIPatchEvent}:
	default:
		h.dropped.Add(1)
	}
}

func (h *Hub) Telemetry(level, source, msg string) {
	if level == "warn" || level == "error" {
		slog.Warn("telemetry", "level", level, "source", source, "msg", msg)
	}
	h.Publish(MsgEngineTelemetry, EngineTelemetry{Level: level, Source: source, Msg: msg})
}

func (h *Hub) Status() HubStatus {
	return HubStatus{Clients: h.clientCount.Load(), Dropped: h.dropped.Load()}
}

func (h *Hub) Run(ctx context.Context) {
	defer close(h.done)
	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			for c := range h.clients {
				h.remove(c, websocket.CloseGoingAway)
			}
			return
		case c := <-h.register:
			if len(h.clients) >= maxWSClients {
				c.closeCode = websocket.CloseTryAgainLater
				close(c.send)
				continue
			}
			h.clients[c] = struct{}{}
			h.clientCount.Store(int64(len(h.clients)))
			h.replayTo(c)
		case c := <-h.unregister:
			h.remove(c, websocket.CloseNormalClosure)
		case m := <-h.broadcast:
			if m.replay {
				h.remember(m.data)
			}
			h.fanout(m.data)
		case <-ticker.C:
			if h.status == nil {
				continue
			}
			b, err := json.Marshal(Envelope{Type: MsgSystemStatus, TS: time.Now().UnixMilli(), Data: h.status()})
			if err == nil {
				h.fanout(b)
			}
		}
	}
}

func (h *Hub) remove(c *wsClient, code int) {
	if _, ok := h.clients[c]; !ok {
		return
	}
	delete(h.clients, c)
	h.clientCount.Store(int64(len(h.clients)))
	c.closeCode = code
	close(c.send)
}

func (h *Hub) fanout(data []byte) {
	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			h.dropped.Add(1)
			h.remove(c, websocket.ClosePolicyViolation)
		}
	}
}

func (h *Hub) remember(data []byte) {
	h.ring[(h.ringHead+h.ringLen)%ringCap] = data
	if h.ringLen < ringCap {
		h.ringLen++
	} else {
		h.ringHead = (h.ringHead + 1) % ringCap
	}
}

func (h *Hub) replayTo(c *wsClient) {
	for i := 0; i < h.ringLen; i++ {
		select {
		case c.send <- h.ring[(h.ringHead+i)%ringCap]:
		default:
			return
		}
	}
}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if !h.originAllowed(r.Header.Get("Origin")) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if h.clientCount.Load() >= maxWSClients {
		http.Error(w, "too many websocket clients", http.StatusServiceUnavailable)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &wsClient{hub: h, conn: conn, send: make(chan []byte, clientSendCap), closeCode: websocket.CloseGoingAway}
	select {
	case h.register <- c:
	case <-h.done:
		_ = conn.Close()
		return
	}
	go c.writePump()
	go c.readPump()
}

// writePump exits when the hub closes c.send (eviction or shutdown) or a write fails.
func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingInterval)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(c.closeCode, ""))
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump exits when the connection fails or is closed by writePump.
func (c *wsClient) readPump() {
	defer func() {
		select {
		case c.hub.unregister <- c:
		case <-c.hub.done:
		}
		_ = c.conn.Close()
	}()
	c.conn.SetReadLimit(wsReadLimit)
	_ = c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
	for {
		kind, msg, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		if kind == websocket.TextMessage {
			c.hub.handleInbound(msg)
		}
	}
}

type inboundMessage struct {
	Type  string   `json:"type"`
	Value *float64 `json:"value"`
}

func (h *Hub) handleInbound(raw []byte) {
	var m inboundMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		h.Telemetry("warn", "hub", "ignored malformed client message")
		return
	}
	switch m.Type {
	case "SET_THRESHOLD":
		if m.Value == nil || h.onSetThreshold == nil {
			h.Telemetry("warn", "hub", "SET_THRESHOLD rejected: missing numeric value")
			return
		}
		if err := h.onSetThreshold(*m.Value); err != nil {
			h.Telemetry("warn", "gatekeeper", "SET_THRESHOLD rejected: "+err.Error())
			return
		}
		h.Publish(MsgConfigUpdated, ConfigUpdated{Threshold: *m.Value})
		h.Telemetry("info", "gatekeeper", "anomaly threshold set to "+formatFloat(*m.Value))
	}
}

// NewAPIHandler serves the hub and the JSON API on API_ADDR.
func NewAPIHandler(h *Hub, status func() SystemStatus, simulate http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", h.ServeWS)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, status())
	})
	mux.Handle("POST /api/simulate", simulate)
	return corsAPI(h.origins, mux)
}

// corsAPI applies the UI_ORIGINS allowlist to /api/*. Browser requests from
// other origins are rejected outright so simple cross-site POSTs cannot run.
func corsAPI(origins map[string]struct{}, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := origins[strings.ToLower(origin)]; !ok {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		slog.Debug("api: write json", "err", err)
	}
}
