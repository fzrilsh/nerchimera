package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	respCaptureLimit = 64 << 10
	reqCaptureLimit  = 16 << 10
	decodeLimit      = 64 << 10
	bodyPreviewLimit = 2048
	aiBodyLimit      = 8 << 10
	drainTimeout     = 5 * time.Second
)

// Transaction is one captured request/response pair handed off by the hot path.
type Transaction struct {
	ID          string
	TS          time.Time
	Method      string
	Host        string
	Path        string
	Status      int
	LatencyMs   float64
	ReqHeaders  http.Header
	RespHeaders http.Header
	ReqBody     []byte
	RespBody    []byte
	Size        int64
	Truncated   bool

	release func()
}

func (tx *Transaction) Release() {
	if tx.release != nil {
		tx.release()
		tx.release = nil
	}
}

type TransactionEvent struct {
	ID                 string    `json:"id"`
	TS                 int64     `json:"ts"`
	Method             string    `json:"method"`
	Host               string    `json:"host"`
	Path               string    `json:"path"`
	Status             int       `json:"status"`
	LatencyMs          float64   `json:"latency_ms"`
	Size               int64     `json:"size"`
	Truncated          bool      `json:"truncated"`
	BodyInspected      bool      `json:"body_inspected"`
	EntropyScore       float64   `json:"entropy_score"`
	NormalizedEntropy  float64   `json:"normalized_entropy"`
	CacheDeceptionFlag int       `json:"cache_deception_flag"`
	SecretLeakFlag     int       `json:"secret_leak_flag"`
	AnomalyScore       float64   `json:"anomaly_score"`
	Findings           []Finding `json:"findings"`
	Classification     *string   `json:"classification"`
	AIStatus           string    `json:"ai_status"`
	HeaderBlock        string    `json:"header_block"`
	BodyPreviewB64     string    `json:"body_preview_b64"`
	EngineUs           float64   `json:"engine_us"`
	EngineError        string    `json:"engine_error,omitempty"`
}

// AIJob is the context handed to the AI agent. Header block and body are always redacted.
type AIJob struct {
	TxID           string
	Method         string
	Host           string
	Path           string
	Status         int
	Result         InspectionResult
	Classification string
	Severity       string
	DedupeKey      string
	HeaderBlock    string
	Body           []byte
}

type Pipeline struct {
	jobs      chan *Transaction
	workers   int
	hub       *Hub
	gate      *Gatekeeper
	redact    bool
	closing   atomic.Bool
	stop      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	dropped   atomic.Uint64
	processed atomic.Uint64
}

func NewPipeline(workers, queueSize int, hub *Hub, gate *Gatekeeper, redact bool) *Pipeline {
	return &Pipeline{
		jobs:    make(chan *Transaction, queueSize),
		workers: workers,
		hub:     hub,
		gate:    gate,
		redact:  redact,
		stop:    make(chan struct{}),
	}
}

// Submit is called on the request path. It never blocks.
func (p *Pipeline) Submit(tx *Transaction) bool {
	if p.closing.Load() {
		tx.Release()
		p.dropped.Add(1)
		return false
	}
	select {
	case p.jobs <- tx:
		return true
	default:
		tx.Release()
		p.dropped.Add(1)
		return false
	}
}

func (p *Pipeline) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// Stop refuses new jobs, lets workers drain the queue, and waits until ctx expires.
func (p *Pipeline) Stop(ctx context.Context) error {
	p.closing.Store(true)
	p.stopOnce.Do(func() { close(p.stop) })
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("pipeline drain: %w (%d jobs left)", ctx.Err(), len(p.jobs))
	}
}

func (p *Pipeline) worker() {
	defer p.wg.Done()
	for {
		select {
		case tx := <-p.jobs:
			p.process(tx)
		case <-p.stop:
			deadline := time.Now().Add(drainTimeout)
			for time.Now().Before(deadline) {
				select {
				case tx := <-p.jobs:
					p.process(tx)
				default:
					return
				}
			}
			return
		}
	}
}

func (p *Pipeline) Status() PoolStatus {
	n, c := len(p.jobs), cap(p.jobs)
	return PoolStatus{
		Workers:  p.workers,
		QueueLen: n,
		QueueCap: c,
		Dropped:  p.dropped.Load(),
		Load:     math.Round(float64(n)/float64(c)*1e4) / 1e4,
	}
}

func (p *Pipeline) process(tx *Transaction) {
	defer tx.Release()
	defer p.processed.Add(1)

	body, inspected := decodeBody(tx.RespHeaders.Get("Content-Encoding"), tx.RespBody)
	headerBlock := BuildHeaderBlock(tx.ReqHeaders, tx.RespHeaders, tx.Status)

	ev := TransactionEvent{
		ID:            tx.ID,
		TS:            tx.TS.UnixMilli(),
		Method:        tx.Method,
		Host:          tx.Host,
		Path:          tx.Path,
		Status:        tx.Status,
		LatencyMs:     math.Round(tx.LatencyMs*1000) / 1000,
		Size:          tx.Size,
		Truncated:     tx.Truncated,
		BodyInspected: inspected,
		Findings:      []Finding{},
		AIStatus:      "none",
	}

	res, err := Inspect(tx.Method, tx.Path, headerBlock, body)
	if err != nil {
		ev.EngineError = err.Error()
		hb, b := Redact(headerBlock, body, nil)
		ev.HeaderBlock, ev.BodyPreviewB64 = p.telemetryView(headerBlock, body, hb, b)
		p.hub.Publish(MsgTransaction, ev)
		p.hub.Telemetry("error", "cgo", fmt.Sprintf("tx=%s %s %s engine error: %v", tx.ID, tx.Method, tx.Path, err))
		return
	}

	ev.EntropyScore = res.EntropyScore
	ev.NormalizedEntropy = res.NormalizedEntropy
	ev.CacheDeceptionFlag = res.CacheDeceptionFlag
	ev.SecretLeakFlag = res.SecretLeakFlag
	ev.AnomalyScore = res.AnomalyScore
	ev.Findings = res.Findings
	ev.EngineUs = math.Round(res.EngineMicros*10) / 10

	redactedHeaders, redactedBody := Redact(headerBlock, body, res.Findings)
	ev.HeaderBlock, ev.BodyPreviewB64 = p.telemetryView(headerBlock, body, redactedHeaders, redactedBody)

	if class, status := p.gate.Evaluate(tx, res, redactedHeaders, redactedBody); class != "" {
		ev.Classification = &class
		ev.AIStatus = status
	}

	p.hub.Publish(MsgTransaction, ev)
	level := "info"
	if ev.Classification != nil {
		level = "warn"
	}
	p.hub.Telemetry(level, "cgo", fmt.Sprintf("tx=%s %s %s H=%.2f wcd=%d leak=%d S=%.4f in %.0fµs",
		tx.ID, tx.Method, tx.Path, res.EntropyScore, res.CacheDeceptionFlag, res.SecretLeakFlag, res.AnomalyScore, res.EngineMicros))
}

func (p *Pipeline) telemetryView(rawHeaders string, rawBody []byte, redactedHeaders string, redactedBody []byte) (string, string) {
	hb, b := rawHeaders, rawBody
	if p.redact {
		hb, b = redactedHeaders, redactedBody
	}
	if len(b) > bodyPreviewLimit {
		b = b[:bodyPreviewLimit]
	}
	return hb, base64.StdEncoding.EncodeToString(b)
}

// decodeBody undoes gzip/deflate with a hard output limit. Truncated streams
// decode as far as possible. Unsupported encodings are not inspected.
func decodeBody(encoding string, body []byte) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	switch enc {
	case "", "identity":
		return body, true
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		return readLimited(r), true
	case "deflate":
		if r, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			return readLimited(r), true
		}
		return readLimited(flate.NewReader(bytes.NewReader(body))), true
	default:
		return nil, false
	}
}

func readLimited(r io.ReadCloser) []byte {
	defer r.Close()
	out, _ := io.ReadAll(io.LimitReader(r, decodeLimit))
	return out
}

// Gatekeeper decides which transactions reach the AI agent.
type Gatekeeper struct {
	threshold atomic.Uint64
	queue     chan AIJob
	ttl       time.Duration
	enqueued  atomic.Uint64
	dropped   atomic.Uint64
	dedupes   atomic.Uint64
	onDrop    func(AIJob)

	mu        sync.Mutex
	seen      map[string]time.Time
	lastSweep time.Time
	now       func() time.Time
}

var errInvalidThreshold = errors.New("threshold must be a number in [0, 1]")

func NewGatekeeper(threshold float64, queueSize int, ttl time.Duration) *Gatekeeper {
	g := &Gatekeeper{
		queue: make(chan AIJob, queueSize),
		ttl:   ttl,
		seen:  make(map[string]time.Time),
		now:   time.Now,
	}
	g.threshold.Store(math.Float64bits(threshold))
	return g
}

func (g *Gatekeeper) Queue() <-chan AIJob { return g.queue }

func (g *Gatekeeper) Threshold() float64 { return math.Float64frombits(g.threshold.Load()) }

func (g *Gatekeeper) SetThreshold(v float64) error {
	if !validThreshold(v) {
		return errInvalidThreshold
	}
	g.threshold.Store(math.Float64bits(v))
	return nil
}

// Evaluate returns the classification and ai_status for gated transactions,
// or "" when the transaction does not pass the gate.
func (g *Gatekeeper) Evaluate(tx *Transaction, res InspectionResult, redactedHeaders string, redactedBody []byte) (string, string) {
	if !(res.AnomalyScore > g.Threshold() || res.CacheDeceptionFlag == 1 || res.SecretLeakFlag == 1) {
		return "", ""
	}
	class, severity := classify(tx, res)
	key := strings.Join([]string{class, tx.Method, strings.ToLower(tx.Host), normalizePath(tx.Path)}, "|")

	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if now.Sub(g.lastSweep) > time.Minute {
		for k, t := range g.seen {
			if now.Sub(t) > g.ttl {
				delete(g.seen, k)
			}
		}
		g.lastSweep = now
	}
	if t, ok := g.seen[key]; ok && now.Sub(t) <= g.ttl {
		g.dedupes.Add(1)
		return class, "deduplicated"
	}

	if len(redactedBody) > aiBodyLimit {
		redactedBody = redactedBody[:aiBodyLimit]
	}
	job := AIJob{
		TxID: tx.ID, Method: tx.Method, Host: tx.Host, Path: tx.Path, Status: tx.Status,
		Result: res, Classification: class, Severity: severity, DedupeKey: key,
		HeaderBlock: redactedHeaders, Body: append([]byte(nil), redactedBody...),
	}
	select {
	case g.queue <- job:
		g.seen[key] = now
		g.enqueued.Add(1)
		return class, "queued"
	default:
		g.dropped.Add(1)
		if g.onDrop != nil {
			g.onDrop(job)
		}
		return class, "dropped"
	}
}

var credentialFindings = map[string]bool{
	"JWT": true, "AWS_ACCESS_KEY": true, "API_KEY_SK": true, "GITHUB_TOKEN": true,
	"SLACK_TOKEN": true, "PRIVATE_KEY_PEM": true, "DB_CREDENTIAL_URI": true,
}

// classify applies the design's priority table; first match wins.
func classify(tx *Transaction, res InspectionResult) (string, string) {
	has := func(pred func(Finding) bool) bool {
		for _, f := range res.Findings {
			if pred(f) {
				return true
			}
		}
		return false
	}
	insecureCookie := has(func(f Finding) bool { return f.Type == "INSECURE_COOKIE" })
	switch {
	case res.CacheDeceptionFlag == 1:
		return "WEB_CACHE_DECEPTION", "critical"
	case insecureCookie && sessionFixated(tx):
		return "SESSION_FIXATION", "high"
	case has(func(f Finding) bool { return credentialFindings[f.Type] }):
		return "CREDENTIAL_LEAK", "critical"
	case has(func(f Finding) bool { return f.Type == "HIGH_ENTROPY_STRING" }):
		return "HIGH_ENTROPY_SECRET_EXPOSURE", "high"
	case insecureCookie:
		return "INSECURE_SESSION_COOKIE", "medium"
	default:
		return "ANOMALOUS_ENTROPY", "low"
	}
}

// sessionFixated reports whether a session id supplied in the query string was
// accepted verbatim as the response's session cookie.
func sessionFixated(tx *Transaction) bool {
	u, err := url.ParseRequestURI(tx.Path)
	if err != nil {
		return false
	}
	q := u.Query()
	var supplied []string
	for _, name := range []string{"session", "sid", "sessionid", "session_id"} {
		if v := q.Get(name); v != "" {
			supplied = append(supplied, v)
		}
	}
	if len(supplied) == 0 {
		return false
	}
	for _, c := range (&http.Response{Header: tx.RespHeaders}).Cookies() {
		for _, v := range supplied {
			if c.Value == v {
				return true
			}
		}
	}
	return false
}

var staticExtensions = []string{".css", ".js", ".png", ".ico", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2"}

// normalizePath collapses ids and static filenames so similar requests share a dedupe key.
func normalizePath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case s == "":
		case isAllDigits(s), isUUID(s), len(s) >= 16 && isHex(s):
			segs[i] = "{id}"
		case i == len(segs)-1:
			lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "%2e", "."), "%2E", "."))
			for _, ext := range staticExtensions {
				if strings.HasSuffix(lower, ext) && len(lower) > len(ext) {
					segs[i] = "*" + ext
					break
				}
			}
		}
	}
	return strings.Join(segs, "/")
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if !(s[i] >= '0' && s[i] <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

func isUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	return isHex(s[0:8]) && isHex(s[9:13]) && isHex(s[14:18]) && isHex(s[19:23]) && isHex(s[24:])
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}
