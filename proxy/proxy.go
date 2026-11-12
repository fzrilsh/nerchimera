package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxPooledBuffer = 128 << 10

var bufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func getBuffer() *bytes.Buffer {
	b := bufferPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

func putBuffer(b *bytes.Buffer) {
	if b != nil && b.Cap() <= maxPooledBuffer {
		bufferPool.Put(b)
	}
}

// captureBody passes reads through unchanged while copying at most limit bytes
// into a pooled buffer. onClose fires exactly once.
type captureBody struct {
	rc      io.ReadCloser
	limit   int
	onClose func(*captureBody)

	mu        sync.Mutex
	buf       *bytes.Buffer
	total     int64
	truncated bool
	closed    bool
}

func newCaptureBody(rc io.ReadCloser, limit int, onClose func(*captureBody)) *captureBody {
	return &captureBody{rc: rc, limit: limit, onClose: onClose, buf: getBuffer()}
}

func (c *captureBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.total += int64(n)
		if c.buf != nil {
			if room := c.limit - c.buf.Len(); room >= n {
				c.buf.Write(p[:n])
			} else {
				if room > 0 {
					c.buf.Write(p[:room])
				}
				c.truncated = true
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *captureBody) Close() error {
	err := c.rc.Close()
	c.mu.Lock()
	first := !c.closed
	c.closed = true
	c.mu.Unlock()
	if first && c.onClose != nil {
		c.onClose(c)
	}
	return err
}

// take transfers ownership of the captured buffer. Later reads are still passed
// through but no longer copied.
func (c *captureBody) take() (*bytes.Buffer, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := c.buf
	c.buf = nil
	return buf, c.total, c.truncated
}

type txStateKey struct{}

type txState struct {
	id         string
	start      time.Time
	method     string
	host       string
	path       string
	forward    bool
	reqHeaders http.Header
	reqCapture *captureBody
	submitted  atomic.Bool
}

func stateFrom(ctx context.Context) *txState {
	st, _ := ctx.Value(txStateKey{}).(*txState)
	return st
}

type Proxy struct {
	upstream  *url.URL
	allowed   map[string]struct{}
	selfAddrs []string
	pipeline  *Pipeline
	hub       *Hub
	rp        *httputil.ReverseProxy
	idPrefix  string
	seq       atomic.Uint64
}

func NewProxy(cfg Config, pipeline *Pipeline, hub *Hub) *Proxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 64

	prefix := make([]byte, 3)
	_, _ = rand.Read(prefix)

	p := &Proxy{
		upstream:  cfg.UpstreamURL,
		allowed:   cfg.ForwardAllowed,
		selfAddrs: []string{cfg.ProxyAddr, cfg.APIAddr},
		pipeline:  pipeline,
		hub:       hub,
		idPrefix:  hex.EncodeToString(prefix),
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		Transport:      transport,
		ErrorLog:       slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	return p
}

func (p *Proxy) nextID() string {
	return p.idPrefix + "." + strconv.FormatUint(p.seq.Add(1), 36)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT tunneling is not supported: NetChimera inspects plain HTTP only", http.StatusMethodNotAllowed)
		return
	}
	host := r.Host
	forward := r.URL.IsAbs()
	if forward {
		if r.URL.Scheme != "http" {
			http.Error(w, "forward mode supports http:// targets only", http.StatusBadRequest)
			return
		}
		if _, ok := p.allowed[strings.ToLower(r.URL.Hostname())]; !ok {
			http.Error(w, "forward target not in FORWARD_ALLOWED_HOSTS", http.StatusForbidden)
			return
		}
		if p.isSelf(r.URL) {
			http.Error(w, "refusing to proxy to NetChimera's own listeners", http.StatusForbidden)
			return
		}
		host = r.URL.Host
	}

	st := &txState{
		id:      p.nextID(),
		start:   time.Now(),
		method:  r.Method,
		host:    host,
		path:    r.URL.RequestURI(),
		forward: forward,
	}
	st.reqHeaders = r.Header.Clone()
	if st.reqHeaders == nil {
		st.reqHeaders = make(http.Header)
	}
	st.reqHeaders.Set("Host", host)
	p.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), txStateKey{}, st)))
}

func (p *Proxy) isSelf(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		port = "80"
	}
	target := net.JoinHostPort(u.Hostname(), port)
	for _, addr := range p.selfAddrs {
		if sameEndpoint(target, addr) {
			return true
		}
	}
	return false
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	st := stateFrom(pr.In.Context())
	if st == nil || !st.forward {
		pr.SetURL(p.upstream)
	}
	pr.SetXForwarded()
	if st != nil && pr.Out.Body != nil && pr.Out.Body != http.NoBody {
		st.reqCapture = newCaptureBody(pr.Out.Body, reqCaptureLimit, nil)
		pr.Out.Body = st.reqCapture
	}
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	st := stateFrom(resp.Request.Context())
	if st == nil {
		return nil
	}
	status := resp.StatusCode
	headers := resp.Header.Clone()
	latency := time.Since(st.start)
	if status == http.StatusSwitchingProtocols {
		p.submit(st, status, latency, headers, nil)
		return nil
	}
	resp.Body = newCaptureBody(resp.Body, respCaptureLimit, func(c *captureBody) {
		p.submit(st, status, latency, headers, c)
	})
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadGateway)
	st := stateFrom(r.Context())
	if st == nil {
		return
	}
	p.submit(st, http.StatusBadGateway, time.Since(st.start), http.Header{}, nil)
	if errors.Is(err, context.Canceled) {
		return
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	path := st.path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	p.hub.Telemetry("warn", "proxy", fmt.Sprintf("tx=%s %s %s upstream error: %v", st.id, st.method, path, err))
}

// submit builds the Transaction and hands it to the pipeline without blocking.
func (p *Proxy) submit(st *txState, status int, latency time.Duration, respHeaders http.Header, resp *captureBody) {
	if !st.submitted.CompareAndSwap(false, true) {
		return
	}
	tx := &Transaction{
		ID:          st.id,
		TS:          st.start,
		Method:      st.method,
		Host:        st.host,
		Path:        st.path,
		Status:      status,
		LatencyMs:   float64(latency.Microseconds()) / 1e3,
		ReqHeaders:  st.reqHeaders,
		RespHeaders: respHeaders,
	}
	var owned []*bytes.Buffer
	if resp != nil {
		buf, total, truncated := resp.take()
		if buf != nil {
			tx.RespBody = buf.Bytes()
			owned = append(owned, buf)
		}
		tx.Size, tx.Truncated = total, truncated
	}
	if st.reqCapture != nil {
		if buf, _, _ := st.reqCapture.take(); buf != nil {
			tx.ReqBody = buf.Bytes()
			owned = append(owned, buf)
		}
	}
	tx.release = func() {
		for _, b := range owned {
			putBuffer(b)
		}
	}
	p.pipeline.Submit(tx)
}
