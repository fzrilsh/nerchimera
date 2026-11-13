# NetChimera Architecture and Conventions

NetChimera is a real-time HTTP security analysis proxy for the Kiroween Hackathon (Frankenstein category). It joins a C++17 engine, a Go proxy/orchestrator, an LLM agent, and a Next.js terminal UI into one pipeline. The full spec lives in `.kiro/specs/netchimera/` (`requirements.md`, `design.md`, `tasks.md`). Read the relevant design section before implementing a task.

## Pipeline

```
client → :8080 Proxy hot path → upstream (target-lab :9190)
              │ capped copy, non-blocking send
              ▼
        jobs chan (4096) → worker pool → Bridge (CGO) → C++ Engine
                               │
                               ├─ every tx → Hub :8081/ws → UI :3100
                               └─ Gatekeeper (score > θ or flag) → aiQueue (64) → AI Agent → Hub
```

## Components and Ownership

| Path | Language | Responsibility |
|---|---|---|
| `engine/` | C++17 | `inspector.h` / `inspector.cpp`: entropy, WCD, secret detection; JSON result buffer |
| `proxy/bridge.go` | Go + cgo | The only file that imports `"C"` |
| `proxy/proxy.go` | Go | Hot path: routing, `httputil.ReverseProxy`, `captureBody` |
| `proxy/pipeline.go` | Go | Job queue, workers, gatekeeper, classification, dedupe |
| `proxy/ws.go` | Go | Hub, ring buffer, envelopes, status ticker, `SET_THRESHOLD` |
| `proxy/agent.go`, `proxy/mock.go` | Go | LLM client, SSE parsing, section parser, deterministic mock |
| `proxy/redact.go` | Go | Finding-span and credential-header redaction |
| `proxy/simulate.go` | Go | `/api/simulate` fixed scenarios |
| `proxy/config.go`, `proxy/main.go` | Go | Env config, wiring, servers, graceful shutdown |
| `target-lab/` | Go stdlib | Intentionally vulnerable demo upstream |
| `ui/` | TypeScript | Next.js 14 App Router, Tailwind, lucide-react, @xterm/xterm |

## Ports

`8080` proxy, `8081` hub/API (`/ws`, `/api/simulate`, `/api/status`, `/healthz`), `9190` target-lab, `3100` UI. All bind `127.0.0.1` by default.

## Conventions

### C++ (`engine/`)
- C++17, standard library only, no third-party headers.
- **No comments of any kind in `.h` or `.cpp` files.** Document behavior in the spec instead.
- Public surface is only the four `extern "C"` functions in `inspector.h`. Everything else goes in an anonymous namespace.
- Use `std::string_view` for parsing and `std::string` for building output; one `std::malloc` for the returned buffer.
- No `std::regex`, no locale-dependent functions (`printf("%f")`, `std::tolower` with locale, `isalpha`). Use ASCII helpers.
- Must compile with `-std=c++17 -Wall -Wextra -Wpedantic -Werror` on Apple clang and gcc.

### Go (`proxy/`, `target-lab/`)
- Go 1.25, one module per directory, `go.work` at the root. `package main` in both modules.
- `proxy` may depend only on `github.com/gorilla/websocket`. `target-lab` is stdlib only.
- Format with `gofmt`; errors wrapped with `fmt.Errorf("...: %w", err)`; structured logs via `log/slog`.
- Counters use `sync/atomic` types (`atomic.Uint64`, `atomic.Int64`); the threshold is `atomic.Uint64` of `math.Float64bits`.
- Every channel is bounded. Producers on the hot path, the pipeline, and the hub use `select { case ch <- v: default: drops.Add(1) }`.
- JSON wire fields are `snake_case` and must match `ui/lib/types.ts`.

### TypeScript (`ui/`)
- Next.js 14 App Router, strict TypeScript, Tailwind 3, functional components.
- Client components are marked `"use client"`. Xterm is imported only through `next/dynamic` with `ssr: false`.
- State goes through `ui/lib/store.ts` (`useSyncExternalStore`), with no extra state libraries.
- Palette tokens: `void #08090c`, `neon #00ff9d`, `amber #ffb800`, `crimson #ff0055`, `panel #0d0f14`, `grid #1a1d24`. Monospace everywhere.

## Build and Run

| Command | Effect |
|---|---|
| `make engine` | `engine/build/libinspector.a` |
| `make engine-test` | ASan/UBSan harness |
| `make proxy` | Engine, then `CGO_ENABLED=1 go build` → `proxy/netchimera` |
| `make lab` | `target-lab/target-lab` |
| `make ui` | `npm ci && npm run build` in `ui/` |
| `make build` | engine → proxy → lab → ui |
| `make dev` | Run lab, proxy, UI together |
| `make test` | engine harness + `go test ./...` |
| `make simulate` | curl attack scenarios through `:8080` |
| `docker compose up --build` | Full stack on 127.0.0.1 |

The system must run end to end with zero env vars (mock AI). Live AI needs `AI_API_KEY` and `AI_MODEL`, with `AI_BASE_URL` pointing at OpenAI, Ollama (`http://localhost:11434/v1`, key `ollama`), or DeepSeek.

## Task Execution

Implement tasks from `.kiro/specs/netchimera/tasks.md` in order, one task at a time. Reference requirement numbers in commit messages (for example `engine: add WCD detection (R3.1-3.6)`). When the design and the brief disagree, the design wins; flag the conflict to the user rather than silently changing either.
