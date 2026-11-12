package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// target-lab is an intentionally vulnerable HTTP server used to demonstrate
// NetChimera. It binds to localhost by default and must never be exposed to a
// network. Every "secret" below is generated at startup or is a documented
// example value; no real credential ships in this repository.

const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// awsExampleKey is AWS's own published example access key id (not a real key).
const awsExampleKey = "AKIAIOSFODNN7EXAMPLE"

type secrets struct {
	jwt      string
	skKey    string
	dbURL    string
	awsKey   string
	sessADMN string
}

func randString(n int) string {
	var b strings.Builder
	b.Grow(n)
	max := big.NewInt(int64(len(base62)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b.WriteByte(base62[idx.Int64()])
	}
	return b.String()
}

// fakeJWT builds a syntactically valid but randomly signed HS256 token.
func fakeJWT(sub string) string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	payloadJSON := fmt.Sprintf(`{"sub":%q,"role":"admin","iat":%d}`, sub, time.Now().Unix())
	payload := b64url(payloadJSON)
	sig := randString(43)
	return header + "." + payload + "." + sig
}

func b64url(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var n uint32
		var pad int
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(data) {
				n |= uint32(data[i+j])
			} else {
				pad++
			}
		}
		for j := 0; j < 4-pad; j++ {
			out.WriteByte(alphabet[(n>>uint(18-6*j))&0x3f])
		}
	}
	return out.String()
}

func newSecrets() secrets {
	return secrets{
		jwt:      fakeJWT("svc-account"),
		skKey:    "sk-" + randString(32),
		dbURL:    "postgres://admin:" + randString(18) + "@db.internal:5432/production",
		awsKey:   awsExampleKey,
		sessADMN: randString(26),
	}
}

type server struct {
	sec secrets
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `<!doctype html><html><head><title>NetChimera Target Lab</title></head>
<body style="font-family:monospace;background:#08090c;color:#00ff9d">
<h1>NetChimera Target Lab</h1>
<p>Intentionally vulnerable. For local testing only.</p>
<ul>
<li>GET /api/health - benign control</li>
<li>GET /static/app.css - benign static control</li>
<li>GET /account - private, correctly no-store</li>
<li>GET /account/&lt;name&gt;.css - web cache deception</li>
<li>GET /api/config - secret leak</li>
<li>POST /login?session=&lt;id&gt; - session fixation + insecure cookie</li>
<li>GET /api/profile - requires Bearer, benign body</li>
</ul></body></html>`)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)})
}

func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, "body{background:#08090c;color:#00ff9d;font-family:monospace}\n.neon{text-shadow:0 0 6px #00ff9d}\n")
}

func (s *server) handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, private")
	writeJSON(w, s.accountBody())
}

// handleAccountWildcard serves the same private payload as /account but with a
// cacheable, static-looking URL and a session cookie: web cache deception.
func (s *server) handleAccountWildcard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.SetCookie(w, &http.Cookie{Name: "session", Value: s.sec.sessADMN, Path: "/"})
	writeJSON(w, s.accountBody())
}

func (s *server) accountBody() map[string]any {
	return map[string]any{
		"user":    "alice",
		"email":   "alice@corp.example",
		"role":    "admin",
		"balance": 48213.55,
		"ssn":     "000-00-0000",
	}
}

// handleConfig leaks several high-value secrets in one response body.
func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"service":           "billing-api",
		"jwt_signing_sample": s.sec.jwt,
		"aws_access_key_id":  s.sec.awsKey,
		"openai_api_key":     s.sec.skKey,
		"database_url":       s.sec.dbURL,
		"debug":              true,
	})
}

// handleLogin accepts a caller-supplied session id verbatim (fixation) and
// sets it as a cookie with no HttpOnly, Secure, or SameSite attributes.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	session := r.URL.Query().Get("session")
	if session == "" {
		session = randString(26)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Set-Cookie", "session="+session+"; Path=/")
	writeJSON(w, map[string]any{
		"access_token": fakeJWT("alice"),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (s *server) handleProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "missing bearer token"})
		return
	}
	writeJSON(w, map[string]any{"user": "alice", "plan": "pro", "region": "us-east-1"})
}

func writeJSON(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func main() {
	addr := os.Getenv("TARGET_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9190"
	}
	s := &server{sec: newSecrets()}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /static/app.css", s.handleStatic)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("GET /account/{rest...}", s.handleAccountWildcard)
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /api/profile", s.handleProfile)

	banner(addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func banner(addr string) {
	const red, reset = "\033[1;31m", "\033[0m"
	line := strings.Repeat("=", 64)
	fmt.Fprintf(os.Stderr, "%s%s\n", red, line)
	fmt.Fprintf(os.Stderr, "  NETCHIMERA TARGET LAB - INTENTIONALLY VULNERABLE\n")
	fmt.Fprintf(os.Stderr, "  Do NOT expose this server to any network.\n")
	fmt.Fprintf(os.Stderr, "  Listening on http://%s\n", addr)
	fmt.Fprintf(os.Stderr, "%s%s\n", line, reset)
}
