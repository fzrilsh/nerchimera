# NetChimera

> A real-time HTTP security analysis proxy stitched together from four distinct technologies into one seamless pipeline. Built for the **Kiroween Hackathon — Frankenstein category.**

NetChimera sits in front of an HTTP service, inspects every request/response pair in real time, scores it for anomalies, and — when something looks wrong — has an autonomous LLM agent synthesize a classified security advisory with a **ready-to-apply unified diff**. A retro-futuristic tactical terminal UI shows the whole thing live.

The four stitched-together subsystems (the "limbs" of the monster):

| Limb | Technology | Role |
|---|---|---|
| 🧠 The Nerves | **C++17** inspection engine (no deps), linked via **CGO** | Shannon entropy, Web Cache Deception & secret detection |
| 💪 The Muscle | **Go** concurrent proxy, worker pool, WebSocket hub | Non-blocking interception, inspection pipeline, gatekeeper |
| 🧬 The Brain | **LLM agent** (OpenAI-compatible / Ollama / DeepSeek) + deterministic offline mock | Advisory + patch synthesis |
| 🦾 The Face | **Next.js 14** + Tailwind + Xterm.js | Live tactical terminal dashboard |

It runs **fully offline with zero configuration**: with no API key, the AI agent uses a deterministic mock generator, so the entire pipeline works for judging without any network access.

## Architecture

```
          ┌───────────────────────── Go process (proxy/) ─────────────────────────┐
 client   │  hot path            jobs chan        worker pool        gatekeeper    │
 curl ───►│  :8080  ──clone 64KiB──►  (4096)  ──►  N × CGO  ──►  score>θ or flag ──►│──► aiQueue (64)
   ▲      │   │ stream through                      │                              │        │
   │      │   ▼                                     ▼  extern "C"                  │        ▼
   └──────│  upstream (target-lab :9190)      C++17 engine (libinspector.a)        │   AI agent ×2
          │           every tx + telemetry ──► WebSocket hub :8081/ws              │   llm / mock
          └──────────────────────────────────────────┬───────────────────────────┘        │
                                                      ▼                                     │
                                             Next.js UI :3100  ◄──── AI_PATCH_STREAM / EVENT ┘
```

See [`.kiro/specs/netchimera/design.md`](.kiro/specs/netchimera/design.md) for the full design, CGO memory contract, threat model, and message protocol.

## Quick start

### Requirements
- Go 1.25+
- A C++17 compiler: Apple clang (macOS) or g++ (Linux)
- Node.js 20+
- Docker (optional, for the containerized path)

### Local (one toolchain)

```sh
make build        # engine → proxy → target-lab → ui
make dev          # runs target-lab, proxy and UI together (Ctrl-C stops all)
# open http://localhost:3100  and click "SIMULATE ATTACK"
```

`make dev` needs the UI dependencies once: `make ui-install`.

### Docker

```sh
make up           # docker compose up --build  (all ports on 127.0.0.1 only)
# open http://localhost:3100
make down
```

### Trigger traffic without the UI

```sh
make simulate     # replays the attack scenarios through the proxy with curl
```

## What a judge sees

1. Open the dashboard. The top bar shows four stitched subsystem badges — **C++ engine**, **Go pool**, **AI agent**, **WS link** — plus a live anomaly-threshold slider.
2. Click **SIMULATE ATTACK**. The proxy replays eight fixed scenarios against the target lab.
3. The **left pane** fills with transactions, each with a Shannon-entropy bar (marked at the 4.3-bit secret line) and a colour-coded anomaly badge.
4. Click any row: the **centre pane** (Xterm.js) shows a hex dump of the exact bytes the engine saw, and streams CGO telemetry.
5. The **right pane** streams an AI advisory for each real anomaly — classification, severity, root cause, a syntax-highlighted unified diff, and Nginx/Cloudflare rules. **Copy Patch** puts the diff on your clipboard.

The four attack scenarios and their detections:

| Scenario | Detection |
|---|---|
| `GET /account/profile.css` (+ session cookie) | **Web Cache Deception** |
| `GET /api/config` | **Credential Leak** (JWT, AWS key, `sk-` key, DB URI) |
| `POST /login?session=…` | **Session Fixation** + insecure cookie |
| `GET /api/profile` (random Bearer) | benign — scores ~0.50, below the 0.65 gate |

The patches the mock generator emits for the lab endpoints pass `git apply --check` against `target-lab/main.go` directly.

## Using a live LLM

Copy `.env.example` to `.env` and set one provider block. With `AI_API_KEY` and `AI_MODEL` set, the agent streams from the provider; any error falls back to the mock.

| Provider | `AI_BASE_URL` | notes |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | set `AI_MODEL` to a chat model on your account |
| Ollama | `http://localhost:11434/v1` | `AI_API_KEY=ollama`; from Docker use `http://host.docker.internal:11434/v1` |
| DeepSeek | `https://api.deepseek.com/v1` | `AI_MODEL=deepseek-chat` |

The API key is only ever sent in the outbound `Authorization` header. It is never logged, and captured secrets are redacted before any prompt is built.

## Make targets

| Target | Effect |
|---|---|
| `make engine` | build `engine/build/libinspector.a` |
| `make engine-test` | C++ harness under AddressSanitizer + UBSan |
| `make proxy` | build the Go proxy (links the engine) |
| `make lab` | build the target lab |
| `make ui` / `make ui-install` | build the UI / install its deps |
| `make build` | build everything |
| `make dev` | run lab + proxy + UI locally |
| `make test` | engine sanitizer harness + `go vet` + `go test -race` |
| `make simulate` | replay attacks with curl |
| `make e2e` | start the stack, run attacks, assert every classification |
| `make bench` | direct vs proxied latency vs the 1 ms budget |
| `make up` / `make down` | docker compose up --build / down |

## Security notes

- **`target-lab/` is intentionally vulnerable.** It binds to `127.0.0.1` and prints a warning banner. Never expose it to a network. Its "secrets" are generated at startup (`crypto/rand`) or are AWS's documented example key; no real credential ships in this repo.
- Everything binds to `127.0.0.1` by default; Docker publishes only on `127.0.0.1`.
- The forward proxy only reaches hosts in `FORWARD_ALLOWED_HOSTS`; `CONNECT` is refused. The WebSocket hub and `/api/*` enforce an `Origin` allowlist. Captured traffic is treated as untrusted data in LLM prompts and is control-character-stripped before it touches the terminal; AI output is display-only and never executed.
- Port `3100` is the default UI port (moved off `3000`, which is commonly occupied). If another local process holds it, change the UI port in `ui/package.json`, `docker-compose.yml`, and `UI_ORIGINS`.
- The UI's `npm audit` reports advisories against Next.js that are only fixed in Next 16 (a major upgrade) and concern features this static, loopback-only dashboard does not use (image optimization, server actions, middleware rewrites). They are accepted for the demo.

## How Kiro built this

This project was built spec-first with Kiro. The [`.kiro/`](.kiro) directory contains:

- **`specs/netchimera/`** — `requirements.md` (EARS acceptance criteria), `design.md` (architecture diagrams, the CGO memory contract, threat model, and 14 testable correctness properties), and `tasks.md` (the sequenced implementation plan). Each task references the requirements it satisfies.
- **`steering/`** — `architecture.md` and `security-rules.md`, always-on context that pins the conventions and the non-negotiable CGO/concurrency/secret rules.
- **`hooks/cgo-safety-check.json`** — an agent hook that fires on every save of an engine or proxy file and audits it against the memory contract and concurrency rules, then runs `make engine` / `go vet`.

The build order follows `tasks.md`: C++ engine → Go CGO bridge → proxy/hub/pipeline → target lab → AI agent → simulator → UI → containers.
