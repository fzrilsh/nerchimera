package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Agent consumes gated anomalies from aiQueue.
//
// This is the task 7.3 placeholder consumer: it drains the queue and reports
// each job so the pipeline can be exercised end to end. Task 10 replaces the
// worker body with prompt building, the live provider client, and the mock
// generator.
type Agent struct {
	queue     <-chan AIJob
	queueCap  int
	hub       *Hub
	workers   int
	mode      string
	model     string
	processed atomic.Uint64
	busy      atomic.Int32
	wg        sync.WaitGroup
}

func NewAgent(cfg Config, queue <-chan AIJob, queueCap int, hub *Hub) *Agent {
	return &Agent{
		queue:    queue,
		queueCap: queueCap,
		hub:      hub,
		workers:  cfg.AIWorkers,
		mode:     cfg.AIModeLabel(),
		model:    cfg.AIModel,
	}
}

func (a *Agent) Start(ctx context.Context) {
	for i := 0; i < a.workers; i++ {
		a.wg.Add(1)
		go a.worker(ctx)
	}
}

func (a *Agent) Wait() { a.wg.Wait() }

func (a *Agent) worker(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.queue:
			a.busy.Add(1)
			a.processed.Add(1)
			a.hub.Telemetry("info", "agent", fmt.Sprintf("tx=%s %s (%s) received; advisory synthesis arrives in task 10",
				job.TxID, job.Classification, job.Severity))
			a.busy.Add(-1)
		}
	}
}

func (a *Agent) Status(dropped uint64) AIStatus {
	status := "idle"
	if a.busy.Load() > 0 {
		status = "busy"
	}
	return AIStatus{
		Mode:      a.mode,
		Status:    status,
		Model:     a.model,
		QueueLen:  len(a.queue),
		QueueCap:  a.queueCap,
		Processed: a.processed.Load(),
		Dropped:   dropped,
	}
}
