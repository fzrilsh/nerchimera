package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

func main() {
	os.Exit(run())
}

func run() int {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := LoadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		return 2
	}

	version, probeErr := ProbeEngine()
	health := &engineHealth{version: version, probeOK: probeErr == nil}
	if probeErr != nil {
		slog.Error("engine probe failed; traffic will be forwarded without inspection guarantees", "err", probeErr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gate := NewGatekeeper(cfg.Threshold, cfg.AIQueueSize, cfg.AIDedupeTTL)
	var (
		hub      *Hub
		pipeline *Pipeline
		agent    *Agent
	)
	status := func() SystemStatus {
		return SystemStatus{
			Engine:    health.snapshot(),
			Pool:      pipeline.Status(),
			AI:        agent.Status(gate.dropped.Load()),
			Hub:       hub.Status(),
			Threshold: gate.Threshold(),
		}
	}
	hub = NewHub(cfg.UIOrigins, status, gate.SetThreshold)
	gate.onDrop = func(job AIJob) {
		hub.Telemetry("warn", "gatekeeper", fmt.Sprintf("aiQueue full; dropped tx=%s %s", job.TxID, job.Classification))
	}
	pipeline = NewPipeline(cfg.InspectWorkers, cfg.InspectQueueSize, hub, gate, cfg.RedactTelemetry)
	agent = NewAgent(cfg, gate.Queue(), cfg.AIQueueSize, hub)
	proxy := NewProxy(cfg, pipeline, hub)

	proxyLn, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		slog.Error("listen proxy", "addr", cfg.ProxyAddr, "err", err)
		return 1
	}
	apiLn, err := net.Listen("tcp", cfg.APIAddr)
	if err != nil {
		_ = proxyLn.Close()
		slog.Error("listen api", "addr", cfg.APIAddr, "err", err)
		return 1
	}

	hubCtx, cancelHub := context.WithCancel(context.Background())
	defer cancelHub()
	go hub.Run(hubCtx)
	pipeline.Start()
	agentCtx, cancelAgent := context.WithCancel(context.Background())
	defer cancelAgent()
	agent.Start(agentCtx)

	proxySrv := &http.Server{Handler: proxy, ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout}
	apiSrv := &http.Server{
		Handler:           NewAPIHandler(hub, status, NewSimulator(cfg.ProxyAddr, hub)),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	serveErr := make(chan error, 2)
	go func() { serveErr <- serve(proxySrv, proxyLn) }()
	go func() { serveErr <- serve(apiSrv, apiLn) }()

	slog.Info("netchimera started", "config", cfg, "engine_version", version)
	hub.Telemetry("info", "pipeline", fmt.Sprintf("engine %s online; %d inspection workers; threshold %.2f; ai mode %s",
		version, cfg.InspectWorkers, cfg.Threshold, cfg.AIModeLabel()))

	exit := 0
	select {
	case <-ctx.Done():
		slog.Info("shutdown requested")
	case err := <-serveErr:
		slog.Error("server failed", "err", err)
		exit = 1
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("proxy shutdown", "err", err)
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), drainTimeout)
	defer cancelDrain()
	if err := pipeline.Stop(drainCtx); err != nil {
		slog.Warn("pipeline drain incomplete", "err", err)
	}
	cancelAgent()
	agent.Wait()
	cancelHub()
	select {
	case <-hub.done:
	case <-time.After(time.Second):
	}
	if err := apiSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("api shutdown", "err", err)
	}
	slog.Info("netchimera stopped")
	return exit
}

func serve(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// engineHealth derives the engine status from the error rate since the previous sample.
type engineHealth struct {
	version string
	probeOK bool

	mu         sync.Mutex
	lastCalls  uint64
	lastErrors uint64
	state      string
}

func (e *engineHealth) snapshot() EngineStatus {
	s := ReadEngineStats()
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case !e.probeOK:
		e.state = "offline"
	case e.state == "":
		e.state = "online"
	}
	if e.probeOK && s.Calls > e.lastCalls {
		rate := float64(s.Errors-e.lastErrors) / float64(s.Calls-e.lastCalls)
		if rate < 0.01 {
			e.state = "online"
		} else {
			e.state = "degraded"
		}
		e.lastCalls, e.lastErrors = s.Calls, s.Errors
	}
	return EngineStatus{
		Status:  e.state,
		Version: e.version,
		Calls:   s.Calls,
		Errors:  s.Errors,
		MeanUs:  float64(int64(s.MeanMicros*10)) / 10,
	}
}
