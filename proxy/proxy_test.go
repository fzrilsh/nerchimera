package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// testConfig builds a validated Config pointing the reverse upstream at the
// given URL, using the real loader so every field is populated correctly.
func testConfig(t *testing.T, upstream string) Config {
	t.Helper()
	env := map[string]string{
		"PROXY_ADDR":   "127.0.0.1:18080",
		"API_ADDR":     "127.0.0.1:18081",
		"UPSTREAM_URL": upstream,
	}
	cfg, err := LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func newTestProxy(t *testing.T, upstream string, queueSize int) (*Proxy, *Pipeline) {
	t.Helper()
	cfg := testConfig(t, upstream)
	hub := NewHub(cfg.UIOrigins, nil, nil)
	gate := NewGatekeeper(cfg.Threshold, cfg.AIQueueSize, cfg.AIDedupeTTL)
	pipeline := NewPipeline(1, queueSize, hub, gate, true)
	return NewProxy(cfg, pipeline, hub), pipeline
}

func TestCaptureBody(t *testing.T) {
	var gotData []byte
	var gotTrunc bool
	calls := 0
	src := io.NopCloser(strings.NewReader("HELLO WORLD PAYLOAD"))
	cb := newCaptureBody(src, 5, func(c *captureBody) {
		buf, total, trunc := c.take()
		gotData = append([]byte(nil), buf.Bytes()...)
		gotTrunc = trunc
		_ = total
		calls++
	})

	out, _ := io.ReadAll(cb)
	if string(out) != "HELLO WORLD PAYLOAD" {
		t.Errorf("passthrough corrupted: %q", out)
	}
	_ = cb.Close()
	_ = cb.Close() // second close must not fire onClose again

	if calls != 1 {
		t.Errorf("onClose fired %d times, want 1", calls)
	}
	if string(gotData) != "HELLO" {
		t.Errorf("captured %q, want first 5 bytes HELLO", gotData)
	}
	if !gotTrunc {
		t.Error("expected truncated flag when body exceeds limit")
	}
}

func TestProxyConnectRejected(t *testing.T) {
	p, _ := newTestProxy(t, "http://127.0.0.1:9", 8)
	r := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("CONNECT = %d, want 405", w.Code)
	}
}

func TestProxyForwardDenied(t *testing.T) {
	p, _ := newTestProxy(t, "http://127.0.0.1:9", 8)
	r := httptest.NewRequest("GET", "http://example.com/x", nil) // absolute-form, not allowlisted
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("forward to non-allowlisted host = %d, want 403", w.Code)
	}
}

func TestProxyReverseStreamsAndSubmits(t *testing.T) {
	const body = "private-account-data-body"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	p, pipeline := newTestProxy(t, upstream.URL, 8)
	r := httptest.NewRequest("GET", "/account", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("reverse status = %d, want 200", w.Code)
	}
	if w.Body.String() != body {
		t.Errorf("response body = %q, want %q (must be unmodified)", w.Body.String(), body)
	}

	tx := waitForJob(t, pipeline)
	if string(tx.RespBody) != body {
		t.Errorf("captured body = %q, want %q", tx.RespBody, body)
	}
	if tx.Status != 200 || tx.Path != "/account" {
		t.Errorf("tx metadata wrong: status=%d path=%s", tx.Status, tx.Path)
	}
}

func TestProxyUpstreamDown502(t *testing.T) {
	p, pipeline := newTestProxy(t, "http://127.0.0.1:9", 8) // port 9 refuses connections
	r := httptest.NewRequest("GET", "/x", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Errorf("unreachable upstream = %d, want 502", w.Code)
	}
	tx := waitForJob(t, pipeline)
	if tx.Status != http.StatusBadGateway {
		t.Errorf("submitted tx status = %d, want 502", tx.Status)
	}
}

func TestProxyNonBlockingWhenQueueFull(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	p, pipeline := newTestProxy(t, upstream.URL, 1)
	// Fill the single job slot so the next Submit must drop.
	pipeline.jobs <- &Transaction{ID: "filler"}

	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)

	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Errorf("request should still succeed with a full queue: %d %q", w.Code, w.Body.String())
	}
	if pipeline.dropped.Load() == 0 {
		t.Error("expected the inspection to be dropped and counted")
	}
}

func waitForJob(t *testing.T, p *Pipeline) *Transaction {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case tx := <-p.jobs:
			return tx
		case <-deadline:
			t.Fatal("no transaction submitted to the pipeline")
			return nil
		case <-time.After(5 * time.Millisecond):
		}
	}
}
