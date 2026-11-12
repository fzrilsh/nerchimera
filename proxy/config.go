package main

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// secretString holds a credential. Every formatting path renders it redacted,
// so it cannot leak through fmt, slog, or JSON by accident.
type secretString string

func (s secretString) String() string               { return "[redacted]" }
func (s secretString) GoString() string             { return "[redacted]" }
func (s secretString) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (s secretString) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// Reveal returns the raw value. Only the outbound AI request may call it.
func (s secretString) Reveal() string { return string(s) }

type Config struct {
	ProxyAddr        string
	APIAddr          string
	UpstreamURL      *url.URL
	ForwardAllowed   map[string]struct{}
	UIOrigins        map[string]struct{}
	InspectWorkers   int
	InspectQueueSize int
	Threshold        float64
	RedactTelemetry  bool
	AIMode           string
	AIBaseURL        string
	AIAPIKey         secretString
	AIModel          string
	AITimeout        time.Duration
	AIWorkers        int
	AIQueueSize      int
	AIDedupeTTL      time.Duration
}

// AILive reports whether the agent should call the configured provider.
func (c Config) AILive() bool {
	return c.AIMode != "mock" && c.AIAPIKey != "" && c.AIModel != ""
}

// AIModeLabel is the mode reported in SYSTEM_STATUS.
func (c Config) AIModeLabel() string {
	if c.AILive() {
		return "live"
	}
	return "mock"
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("proxy_addr", c.ProxyAddr),
		slog.String("api_addr", c.APIAddr),
		slog.String("upstream_url", c.UpstreamURL.String()),
		slog.String("forward_allowed_hosts", strings.Join(sortedKeys(c.ForwardAllowed), ",")),
		slog.String("ui_origins", strings.Join(sortedKeys(c.UIOrigins), ",")),
		slog.Int("inspect_workers", c.InspectWorkers),
		slog.Int("inspect_queue_size", c.InspectQueueSize),
		slog.Float64("anomaly_threshold", c.Threshold),
		slog.Bool("redact_telemetry", c.RedactTelemetry),
		slog.String("ai_mode", c.AIModeLabel()),
		slog.String("ai_base_url", c.AIBaseURL),
		slog.Bool("ai_api_key_set", c.AIAPIKey != ""),
		slog.String("ai_model", c.AIModel),
		slog.Duration("ai_timeout", c.AITimeout),
		slog.Int("ai_workers", c.AIWorkers),
		slog.Int("ai_queue_size", c.AIQueueSize),
		slog.Duration("ai_dedupe_ttl", c.AIDedupeTTL),
	)
}

// LoadConfig reads and validates every setting. All problems are reported at once.
func LoadConfig(getenv func(string) string) (Config, error) {
	env := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	fail := func(key string, err error) { errs = append(errs, fmt.Errorf("%s: %w", key, err)) }

	c := Config{
		ProxyAddr: env("PROXY_ADDR", "127.0.0.1:8080"),
		APIAddr:   env("API_ADDR", "127.0.0.1:8081"),
		AIMode:    strings.ToLower(env("AI_MODE", "auto")),
		AIBaseURL: strings.TrimRight(env("AI_BASE_URL", "https://api.openai.com/v1"), "/"),
		AIAPIKey:  secretString(strings.TrimSpace(getenv("AI_API_KEY"))),
		AIModel:   env("AI_MODEL", ""),
	}

	for key, addr := range map[string]string{"PROXY_ADDR": c.ProxyAddr, "API_ADDR": c.APIAddr} {
		if _, port, err := net.SplitHostPort(addr); err != nil {
			fail(key, err)
		} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			fail(key, fmt.Errorf("invalid port %q", port))
		}
	}
	if c.ProxyAddr == c.APIAddr {
		fail("API_ADDR", errors.New("must differ from PROXY_ADDR"))
	}

	if u, err := parseHTTPURL(env("UPSTREAM_URL", "http://127.0.0.1:9190")); err != nil {
		fail("UPSTREAM_URL", err)
	} else {
		c.UpstreamURL = u
		if sameEndpoint(u.Host, c.ProxyAddr) || sameEndpoint(u.Host, c.APIAddr) {
			fail("UPSTREAM_URL", errors.New("must not point at the proxy's own listeners"))
		}
	}

	c.ForwardAllowed = make(map[string]struct{})
	for _, h := range splitList(env("FORWARD_ALLOWED_HOSTS", "localhost,127.0.0.1,target-lab")) {
		c.ForwardAllowed[strings.ToLower(h)] = struct{}{}
	}

	c.UIOrigins = make(map[string]struct{})
	for _, o := range splitList(env("UI_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")) {
		u, err := parseHTTPURL(o)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			fail("UI_ORIGINS", fmt.Errorf("invalid origin %q", o))
			continue
		}
		c.UIOrigins[strings.ToLower(u.Scheme+"://"+u.Host)] = struct{}{}
	}
	if len(c.UIOrigins) == 0 {
		fail("UI_ORIGINS", errors.New("at least one origin is required"))
	}

	c.InspectWorkers = parsePositiveInt(env("INSPECT_WORKERS", strconv.Itoa(runtime.NumCPU())), "INSPECT_WORKERS", fail)
	c.InspectQueueSize = parsePositiveInt(env("INSPECT_QUEUE_SIZE", "4096"), "INSPECT_QUEUE_SIZE", fail)
	c.AIWorkers = parsePositiveInt(env("AI_WORKERS", "2"), "AI_WORKERS", fail)
	c.AIQueueSize = parsePositiveInt(env("AI_QUEUE_SIZE", "64"), "AI_QUEUE_SIZE", fail)
	c.AITimeout = parsePositiveDuration(env("AI_TIMEOUT", "45s"), "AI_TIMEOUT", fail)
	c.AIDedupeTTL = parsePositiveDuration(env("AI_DEDUPE_TTL", "120s"), "AI_DEDUPE_TTL", fail)

	if t, err := strconv.ParseFloat(env("ANOMALY_THRESHOLD", "0.65"), 64); err != nil || !validThreshold(t) {
		fail("ANOMALY_THRESHOLD", errors.New("must be a number in [0, 1]"))
	} else {
		c.Threshold = t
	}

	if b, err := strconv.ParseBool(env("REDACT_TELEMETRY", "true")); err != nil {
		fail("REDACT_TELEMETRY", errors.New("must be true or false"))
	} else {
		c.RedactTelemetry = b
	}

	if c.AIMode != "auto" && c.AIMode != "mock" {
		fail("AI_MODE", errors.New("must be auto or mock"))
	}
	if _, err := parseHTTPURL(c.AIBaseURL); err != nil {
		fail("AI_BASE_URL", err)
	}

	return c, errors.Join(errs...)
}

func validThreshold(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1
}

func parseHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%q must use http or https", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q has no host", raw)
	}
	return u, nil
}

func parsePositiveInt(raw, key string, fail func(string, error)) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		fail(key, errors.New("must be a positive integer"))
		return 1
	}
	return n
}

func parsePositiveDuration(raw, key string, fail func(string, error)) time.Duration {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		fail(key, errors.New("must be a positive duration such as 30s"))
		return time.Second
	}
	return d
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sameEndpoint reports whether hostport targets the listener bound at listenAddr.
func sameEndpoint(hostport, listenAddr string) bool {
	h1, p1, err1 := net.SplitHostPort(hostport)
	h2, p2, err2 := net.SplitHostPort(listenAddr)
	if err1 != nil || err2 != nil || p1 != p2 {
		return false
	}
	return strings.EqualFold(h1, h2) || (isLocalHost(h1) && isLocalHost(h2))
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isLocalHost(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "" || h == "localhost" || h == "0.0.0.0" || h == "::" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
