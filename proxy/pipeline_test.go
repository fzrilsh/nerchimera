package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"net/http"
	"strings"
	"testing"
	"time"
)

func newGate(t *testing.T, threshold float64) *Gatekeeper {
	t.Helper()
	return NewGatekeeper(threshold, 8, 120*time.Second)
}

func txWith(path string, resp http.Header) *Transaction {
	return &Transaction{
		ID: "tx1", TS: time.Now(), Method: "GET", Host: "lab", Path: path,
		Status: 200, RespHeaders: resp,
	}
}

func TestGateTruthTable(t *testing.T) {
	cases := []struct {
		name      string
		res       InspectionResult
		wantQueue bool
	}{
		{"below threshold, no flags", InspectionResult{AnomalyScore: 0.5}, false},
		{"above threshold", InspectionResult{AnomalyScore: 0.7}, true},
		{"wcd flag only", InspectionResult{AnomalyScore: 0.1, CacheDeceptionFlag: 1}, true},
		{"leak flag only", InspectionResult{AnomalyScore: 0.1, SecretLeakFlag: 1}, true},
		{"exactly at threshold is not above", InspectionResult{AnomalyScore: 0.65}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGate(t, 0.65)
			class, status := g.Evaluate(txWith("/x", http.Header{}), c.res, "", nil)
			queued := class != "" && status == "queued"
			if queued != c.wantQueue {
				t.Errorf("gate queued=%v (status %q), want %v", queued, status, c.wantQueue)
			}
			if c.wantQueue {
				select {
				case <-g.Queue():
				default:
					t.Error("expected a job on aiQueue")
				}
			}
		})
	}
}

func TestClassifyPriority(t *testing.T) {
	cases := []struct {
		name      string
		tx        *Transaction
		res       InspectionResult
		wantClass string
		wantSev   string
	}{
		{
			"web cache deception wins",
			txWith("/account/x.css", http.Header{}),
			InspectionResult{CacheDeceptionFlag: 1, Findings: []Finding{{Type: "WEB_CACHE_DECEPTION"}, {Type: "INSECURE_COOKIE"}}},
			"WEB_CACHE_DECEPTION", "critical",
		},
		{
			"credential leak",
			txWith("/api/config", http.Header{}),
			InspectionResult{SecretLeakFlag: 1, Findings: []Finding{{Type: "JWT"}, {Type: "AWS_ACCESS_KEY"}}},
			"CREDENTIAL_LEAK", "critical",
		},
		{
			"high entropy string",
			txWith("/x", http.Header{}),
			InspectionResult{SecretLeakFlag: 1, Findings: []Finding{{Type: "HIGH_ENTROPY_STRING"}}},
			"HIGH_ENTROPY_SECRET_EXPOSURE", "high",
		},
		{
			"insecure cookie only",
			txWith("/x", http.Header{}),
			InspectionResult{Findings: []Finding{{Type: "INSECURE_COOKIE"}}},
			"INSECURE_SESSION_COOKIE", "medium",
		},
		{
			"anomalous entropy fallback",
			txWith("/x", http.Header{}),
			InspectionResult{AnomalyScore: 0.9},
			"ANOMALOUS_ENTROPY", "low",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			class, sev := classify(c.tx, c.res)
			if class != c.wantClass || sev != c.wantSev {
				t.Errorf("classify = (%q,%q), want (%q,%q)", class, sev, c.wantClass, c.wantSev)
			}
		})
	}
}

func TestClassifySessionFixation(t *testing.T) {
	resp := http.Header{"Set-Cookie": {"session=ATTACKER-FIXED-0001; Path=/"}}
	tx := txWith("/login?session=ATTACKER-FIXED-0001", resp)
	res := InspectionResult{SecretLeakFlag: 1, Findings: []Finding{{Type: "INSECURE_COOKIE"}, {Type: "JWT"}}}
	class, sev := classify(tx, res)
	if class != "SESSION_FIXATION" || sev != "high" {
		t.Errorf("classify = (%q,%q), want SESSION_FIXATION/high", class, sev)
	}
	// Without the matching query param it must not be session fixation.
	tx2 := txWith("/login", resp)
	if class, _ := classify(tx2, res); class == "SESSION_FIXATION" {
		t.Error("session fixation should require a matching request session param")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/account/profile.css":                      "/account/*.css",
		"/account/avatar.png":                       "/account/*.png",
		"/users/12345/orders":                       "/users/{id}/orders",
		"/obj/123e4567-e89b-12d3-a456-426614174000": "/obj/{id}",
		"/cache/9f86d081884c7d659a2feaa0c55ad015":   "/cache/{id}",
		"/api/config?x=1":                           "/api/config",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupe(t *testing.T) {
	g := newGate(t, 0.65)
	now := time.Now()
	g.now = func() time.Time { return now }
	res := InspectionResult{CacheDeceptionFlag: 1, Findings: []Finding{{Type: "WEB_CACHE_DECEPTION"}}}

	_, s1 := g.Evaluate(txWith("/account/a.css", http.Header{}), res, "", nil)
	if s1 != "queued" {
		t.Fatalf("first eval status = %q, want queued", s1)
	}
	// Same classification key (normalized path *.css) within TTL -> deduplicated.
	_, s2 := g.Evaluate(txWith("/account/b.css", http.Header{}), res, "", nil)
	if s2 != "deduplicated" {
		t.Errorf("second eval status = %q, want deduplicated", s2)
	}
	// After the TTL expires it is enqueued again.
	now = now.Add(121 * time.Second)
	_, s3 := g.Evaluate(txWith("/account/c.css", http.Header{}), res, "", nil)
	if s3 != "queued" {
		t.Errorf("post-TTL eval status = %q, want queued", s3)
	}
}

func TestSetThresholdValidation(t *testing.T) {
	g := newGate(t, 0.65)
	if err := g.SetThreshold(0.4); err != nil || g.Threshold() != 0.4 {
		t.Errorf("valid SetThreshold failed: err=%v threshold=%v", err, g.Threshold())
	}
	for _, bad := range []float64{-0.1, 1.5} {
		if err := g.SetThreshold(bad); err == nil {
			t.Errorf("SetThreshold(%v) should have failed", bad)
		}
	}
	if g.Threshold() != 0.4 {
		t.Errorf("threshold changed after invalid update: %v", g.Threshold())
	}
}

func TestDecodeBody(t *testing.T) {
	plain := []byte("hello world")

	if got, ok := decodeBody("", plain); !ok || !bytes.Equal(got, plain) {
		t.Errorf("identity decode = %q ok=%v", got, ok)
	}
	if _, ok := decodeBody("br", plain); ok {
		t.Error("unsupported encoding should report body_inspected=false")
	}

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(plain)
	_ = zw.Close()
	if got, ok := decodeBody("gzip", gz.Bytes()); !ok || !bytes.Equal(got, plain) {
		t.Errorf("gzip decode = %q ok=%v", got, ok)
	}

	var fl bytes.Buffer
	fw, _ := flate.NewWriter(&fl, flate.DefaultCompression)
	_, _ = fw.Write(plain)
	_ = fw.Close()
	if got, ok := decodeBody("deflate", fl.Bytes()); !ok || !bytes.Equal(got, plain) {
		t.Errorf("deflate decode = %q ok=%v", got, ok)
	}
}

func TestDecodeBodyZipBombBounded(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(bytes.Repeat([]byte("A"), 1<<20)) // 1 MiB in
	_ = zw.Close()
	got, ok := decodeBody("gzip", gz.Bytes())
	if !ok {
		t.Fatal("gzip decode failed")
	}
	if len(got) > decodeLimit {
		t.Errorf("decoded %d bytes, exceeds limit %d", len(got), decodeLimit)
	}
}

func TestRedactCompleteness(t *testing.T) {
	header := "> Authorization: Bearer q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA\n> Cookie: session=TOPSECRETVALUE12345\n< Set-Cookie: s=abc\n"
	body := []byte(`{"key":"AKIAIOSFODNN7EXAMPLE"}`)
	findings := []Finding{
		{Type: "AWS_ACCESS_KEY", Loc: "body", Off: bytes.Index(body, []byte("AKIA")), Len: 20},
	}
	rh, rb := Redact(header, body, findings)

	if strings.Contains(rh, "q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA") {
		t.Error("authorization credential not redacted")
	}
	if strings.Contains(rh, "TOPSECRETVALUE12345") {
		t.Error("cookie value not redacted")
	}
	if strings.Contains(string(rb), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("finding span not redacted in body")
	}
	if !strings.Contains(string(rb), "REDACTED") {
		t.Error("expected a REDACTED marker in body")
	}
	// The Authorization scheme is preserved.
	if !strings.Contains(rh, "Bearer ") {
		t.Error("authorization scheme should be preserved")
	}
}
