package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func labJob(class, severity, method, path string, findings []Finding) AIJob {
	return AIJob{
		TxID: "tx1", Method: method, Host: "target-lab", Path: path,
		Classification: class, Severity: severity,
		Result:      InspectionResult{Findings: findings, AnomalyScore: 0.9, EntropyScore: 5.4, SecretLeakFlag: 1},
		HeaderBlock: "> Host: target-lab\n< :status: 200\n< Content-Type: application/json\n",
	}
}

func TestMockDeterministic(t *testing.T) {
	job := labJob("CREDENTIAL_LEAK", "critical", "GET", "/api/config", []Finding{{Type: "JWT"}, {Type: "AWS_ACCESS_KEY"}})
	a := mockGenerate(job)
	b := mockGenerate(job)
	if a != b {
		t.Error("mockGenerate is not deterministic")
	}
	if !strings.Contains(a, "/api/config") {
		t.Error("advisory should reference the transaction path")
	}
	if !strings.Contains(a, "### PATCH") || !strings.Contains(a, "### CLASSIFICATION") {
		t.Error("advisory missing required sections")
	}
}

func TestParseAdvisoryValid(t *testing.T) {
	text := strings.Join([]string{
		"### CLASSIFICATION", "CREDENTIAL_LEAK", "",
		"### SEVERITY", "critical", "",
		"### TITLE", "Leaked secrets", "",
		"### ROOT_CAUSE", "The endpoint returns credentials.", "",
		"### PATCH", "```diff", "--- a/x.go", "+++ b/x.go", "@@ -1,2 +1,1 @@", "-secret", " ok", "```", "",
		"### NGINX_RULE", "```nginx", "location = /x { return 403; }", "```", "",
		"### CLOUDFLARE_RULE", "```", "block", "```",
	}, "\n")
	adv := parseAdvisory(text, labJob("X", "low", "GET", "/api/config", nil))
	if adv.Classification != "CREDENTIAL_LEAK" || adv.Severity != "critical" {
		t.Errorf("parsed class/sev = %q/%q", adv.Classification, adv.Severity)
	}
	if !adv.DiffValid {
		t.Errorf("valid diff marked invalid; diff=%q", adv.Diff)
	}
	if strings.Contains(adv.Diff, "```") {
		t.Error("code fences not stripped from diff")
	}
	if adv.NginxRule == "" || adv.CloudflareRule == "" {
		t.Error("nginx/cloudflare rules not parsed")
	}
	if adv.Raw != "" {
		t.Error("valid advisory should not retain raw text")
	}
}

func TestParseAdvisoryInvalidDiff(t *testing.T) {
	// Missing @@/---/+++ markers and no PATCH-worthy content.
	text := "### CLASSIFICATION\nANOMALOUS_ENTROPY\n\n### TITLE\nx\n\n### ROOT_CAUSE\ny\n\n### PATCH\nnot a real diff\n"
	adv := parseAdvisory(text, labJob("ANOMALOUS_ENTROPY", "low", "GET", "/x", nil))
	if adv.DiffValid {
		t.Error("diff without ---/+++/@@ should be invalid")
	}
	if adv.Raw == "" {
		t.Error("invalid advisory should retain raw text")
	}
}

func TestBuildUserPromptIsDelimited(t *testing.T) {
	job := labJob("CREDENTIAL_LEAK", "critical", "GET", "/api/config", []Finding{{Type: "JWT"}})
	job.Body = []byte(`{"k":"eyJ…[REDACTED:JWT:127]"}`)
	p := buildUserPrompt(job)
	if !strings.Contains(p, "<<<UNTRUSTED_HTTP_TRANSACTION>>>") || !strings.Contains(p, "<<<END_UNTRUSTED_HTTP_TRANSACTION>>>") {
		t.Error("prompt must delimit untrusted content")
	}
	if !strings.Contains(p, "classification hint") {
		t.Error("prompt should include the classification hint")
	}
}

func TestReadSSEAssembly(t *testing.T) {
	a := &Agent{hub: NewHub(originSet(), nil, nil)}
	sse := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n" +
		"data: [DONE]\n\n"
	text, err := a.readSSE(context.Background(), "adv-1", labJob("X", "low", "GET", "/x", nil), strings.NewReader(sse))
	if err != nil {
		t.Fatalf("readSSE error: %v", err)
	}
	if text != "Hello world" {
		t.Errorf("assembled = %q, want %q", text, "Hello world")
	}
}

func TestSynthesizeFallsBackOnProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"error":"boom"}`)
	}))
	defer srv.Close()

	cfg := Config{
		AIMode: "auto", AIBaseURL: srv.URL, AIAPIKey: "test-key", AIModel: "m",
		AITimeout: 2 * time.Second, AIWorkers: 1,
	}
	a := NewAgent(cfg, make(chan AIJob), 8, NewHub(originSet(), nil, nil))
	if !a.live {
		t.Fatal("agent should be in live mode")
	}
	_, source := a.synthesize(context.Background(), "adv-1", labJob("CREDENTIAL_LEAK", "critical", "GET", "/api/config", []Finding{{Type: "JWT"}}))
	if source != "fallback" {
		t.Errorf("source = %q, want fallback", source)
	}
}

// TestMockDiffsApply proves the "ready-to-apply" claim: every lab advisory's
// diff applies cleanly to target-lab/main.go with `git apply --check`.
func TestMockDiffsApply(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	labSrc := filepath.Join("..", "target-lab", "main.go")
	data, err := os.ReadFile(labSrc)
	if err != nil {
		t.Skipf("target-lab source not found: %v", err)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "target-lab"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target-lab", "main.go"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) error {
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		return cmd.Run()
	}
	if err := run("init", "-q"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	_ = run("add", "-A")
	if err := run("commit", "-qm", "base"); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	jobs := []AIJob{
		labJob("WEB_CACHE_DECEPTION", "critical", "GET", "/account/profile.css", []Finding{{Type: "WEB_CACHE_DECEPTION"}}),
		labJob("CREDENTIAL_LEAK", "critical", "GET", "/api/config", []Finding{{Type: "JWT"}}),
		labJob("SESSION_FIXATION", "high", "POST", "/login?session=X", []Finding{{Type: "INSECURE_COOKIE"}}),
	}
	for _, job := range jobs {
		adv := parseAdvisory(mockGenerate(job), job)
		if !adv.DiffValid {
			t.Errorf("%s: mock diff is not valid format", job.Classification)
			continue
		}
		patch := filepath.Join(dir, "p.diff")
		if err := os.WriteFile(patch, []byte(adv.Diff+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := run("apply", "--check", "p.diff"); err != nil {
			t.Errorf("%s: git apply --check failed: %v\n%s", job.Classification, err, adv.Diff)
		}
	}
}
