# NetChimera

A real-time HTTP security analysis proxy stitched together from four technologies: a C++17 inspection engine (via CGO), a Go proxy and AI orchestrator, an LLM security agent, and a Next.js tactical terminal UI. Built for the Kiroween Hackathon, Frankenstein category.

> Work in progress. See `.kiro/specs/netchimera/tasks.md` for implementation status.

## Quick start

```sh
make build   # engine -> proxy -> target-lab -> ui
make dev     # run target-lab, proxy and UI locally
# open http://localhost:3000 and click "Simulate Attack Traffic"
```

Or with Docker:

```sh
docker compose up --build
```

No configuration is required: without an API key the AI agent uses a deterministic offline generator. To use a live model, copy `.env.example` to `.env` and fill in one of the provider presets.

## Requirements

- Go 1.25+
- A C++17 compiler: Apple clang (macOS) or g++ (Linux)
- Node.js 20+ for the UI
- Docker (optional)

## Layout

| Path | Contents |
|---|---|
| `engine/` | C++17 inspection engine, built as `engine/build/libinspector.a` |
| `proxy/` | Go proxy, CGO bridge, worker pool, WebSocket hub, AI agent |
| `target-lab/` | Intentionally vulnerable demo server (localhost only) |
| `ui/` | Next.js 14 dashboard |
| `.kiro/` | Kiro specs, steering and hooks used to build the project |

## Security note

`target-lab` is intentionally vulnerable. It binds to `127.0.0.1` by default. Do not expose it to a network.
