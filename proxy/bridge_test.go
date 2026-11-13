package main

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestEntropy(t *testing.T) {
	if got := Entropy([]byte("ab")); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("Entropy(ab) = %v, want 1.0", got)
	}
	if got := Entropy([]byte("aaaa")); got != 0 {
		t.Errorf("Entropy(aaaa) = %v, want 0", got)
	}
	if got := Entropy(nil); got != 0 {
		t.Errorf("Entropy(nil) = %v, want 0", got)
	}
}

func TestEngineVersion(t *testing.T) {
	if v := EngineVersion(); v == "" {
		t.Fatal("EngineVersion returned empty string")
	}
	if _, err := ProbeEngine(); err != nil {
		t.Fatalf("ProbeEngine failed: %v", err)
	}
}

func TestEngineInputNulAndTruncation(t *testing.T) {
	// NUL replaced by space, byte offsets preserved.
	in := "ab\x00cd"
	got := engineInput(in, maxHeadersLen)
	if got != "ab cd" {
		t.Errorf("engineInput NUL = %q, want %q", got, "ab cd")
	}
	if len(got) != len(in) {
		t.Errorf("engineInput changed length: %d vs %d", len(got), len(in))
	}
	// Truncation to bound.
	long := strings.Repeat("x", maxMethodLen+10)
	if got := engineInput(long, maxMethodLen); len(got) != maxMethodLen {
		t.Errorf("engineInput truncation len = %d, want %d", len(got), maxMethodLen)
	}
}

func TestInspectWebCacheDeception(t *testing.T) {
	headers := "> Cookie: session=abc123\n< :status: 200\n< Content-Type: application/json\n" +
		"< Cache-Control: public, max-age=3600\n< Set-Cookie: session=abc123; Path=/\n"
	res, err := Inspect("GET", "/account/profile.css", headers, []byte(`{"user":"alice"}`))
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if res.CacheDeceptionFlag != 1 {
		t.Errorf("cache_deception_flag = %d, want 1", res.CacheDeceptionFlag)
	}
	if res.AnomalyScore <= 0.65 {
		t.Errorf("anomaly_score = %v, want > 0.65", res.AnomalyScore)
	}
	if !hasFinding(res.Findings, "WEB_CACHE_DECEPTION") {
		t.Errorf("missing WEB_CACHE_DECEPTION finding: %+v", res.Findings)
	}
}

func TestInspectSecretLeakNoEcho(t *testing.T) {
	body := `{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE","database_url":"postgres://admin:S3cr3tPw@db:5432/prod"}`
	res, err := Inspect("GET", "/api/config", "< Content-Type: application/json\n", []byte(body))
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if res.SecretLeakFlag != 1 {
		t.Errorf("secret_leak_flag = %d, want 1", res.SecretLeakFlag)
	}
	if !hasFinding(res.Findings, "AWS_ACCESS_KEY") || !hasFinding(res.Findings, "DB_CREDENTIAL_URI") {
		t.Errorf("missing expected findings: %+v", res.Findings)
	}
	// Requirement 2.4: the engine never echoes input bytes into the result JSON.
	// The bridge carries only typed findings, never raw spans.
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "AKIA") || strings.Contains(f.Loc, "S3cr3t") {
			t.Errorf("finding leaked secret bytes: %+v", f)
		}
	}
}

func TestInspectBenign(t *testing.T) {
	res, err := Inspect("GET", "/api/health", "< Content-Type: application/json\n", []byte(`{"status":"ok"}`))
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if res.CacheDeceptionFlag != 0 || res.SecretLeakFlag != 0 || res.AnomalyScore != 0 {
		t.Errorf("benign request flagged: %+v", res)
	}
	if len(res.Findings) != 0 {
		t.Errorf("benign request produced findings: %+v", res.Findings)
	}
}

func TestInspectConcurrentDeterministic(t *testing.T) {
	headers := "> Authorization: Bearer q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA\n< Set-Cookie: s=1\n"
	body := []byte(`{"k":"AKIAIOSFODNN7EXAMPLE"}`)
	ref, err := Inspect("GET", "/account/x.js", headers, body)
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	var wg sync.WaitGroup
	var mismatch int
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r, err := Inspect("GET", "/account/x.js", headers, body)
				if err != nil || r.AnomalyScore != ref.AnomalyScore ||
					r.SecretLeakFlag != ref.SecretLeakFlag || len(r.Findings) != len(ref.Findings) {
					mu.Lock()
					mismatch++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if mismatch != 0 {
		t.Errorf("concurrent Inspect produced %d nondeterministic results", mismatch)
	}
}

func TestBuildHeaderBlock(t *testing.T) {
	req := http.Header{"Cookie": {"session=abc"}, "Host": {"localhost"}}
	resp := http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"s=1"}}
	block := BuildHeaderBlock(req, resp, 200)

	for _, want := range []string{"> Cookie: session=abc\n", "> Host: localhost\n", "< :status: 200\n", "< Content-Type: application/json\n", "< Set-Cookie: s=1\n"} {
		if !strings.Contains(block, want) {
			t.Errorf("header block missing %q\n%s", want, block)
		}
	}
	// Request headers must precede the status line, which precedes response headers.
	if strings.Index(block, "> ") > strings.Index(block, "< :status:") {
		t.Error("request headers should come before status line")
	}
}

func hasFinding(fs []Finding, typ string) bool {
	for _, f := range fs {
		if f.Type == typ {
			return true
		}
	}
	return false
}
