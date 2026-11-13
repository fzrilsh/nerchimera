# Implementation Plan

Tasks run in order. Each task builds on the previous ones and ends with the code wired in, with no orphaned modules. Tasks marked `*` are optional test tasks: they are recommended for judging quality but are not required for a working demo.

- [x] 1. Repository foundation
  - [x] 1.1 Create root files: `.gitignore` (`engine/build/`, `proxy/netchimera`, `target-lab/target-lab`, `ui/node_modules/`, `ui/.next/`, `.env`), `.env.example` with all variables from the design Configuration Reference and the OpenAI / Ollama / DeepSeek presets, and a `README.md` stub with quick start
    - _Requirements: 12.1, 21.5_
  - [x] 1.2 Create `Makefile` skeleton with variables (`CXX ?= c++`, `CXXFLAGS`, `UNAME_S`) and placeholder targets `engine`, `engine-shared`, `engine-test`, `proxy`, `lab`, `ui`, `build`, `dev`, `test`, `simulate`, `bench`, `e2e`, `up`, `down`, `clean`
    - _Requirements: 21.1, 21.6_

- [x] 2. C++17 inspection engine
  - [x] 2.1 Write `engine/inspector.h` with the exact `extern "C"` ABI from the design (`CalculateShannonEntropy`, `InspectHTTPPayload`, `FreeInspectionResult`, `NetChimeraEngineVersion`), include guards, no comments
    - _Requirements: 6.1, 6.6, 6.9_
  - [x] 2.2 Implement in `engine/inspector.cpp`: export visibility macro, `bounded_len`, `entropy_bytes` (256-bucket histogram), and `CalculateShannonEntropy` with null/length guards and `try/catch(...)`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 6.3, 6.4_
  - [x] 2.3 Implement Header Block parsing (`parse_header_block` → `HeaderView` with value offsets), ASCII case helpers, and credential token extraction from `Authorization`, `Cookie`, and `Set-Cookie`
    - _Requirements: 2.2, 2.5_
  - [x] 2.4 Implement body analysis: `tokenize_body`, `json_token_fields` for sensitive keys, and the `HIGH_ENTROPY_STRING` rule (length 20–512, entropy > 4.3)
    - _Requirements: 2.2, 4.1, 4.2, 4.5_
  - [x] 2.5 Implement linear-time pattern matchers `match_jwt`, `match_aws`, `match_sk`, `match_github`, `match_slack`, `match_pem`, `match_db_uri`; merge overlapping Findings (pattern wins), cap at 64
    - _Requirements: 4.3, 4.4_
  - [x] 2.6 Implement `detect_cache_deception` (query/fragment strip, `%2e` decode, lowercase, Static Extension list, cacheability, session indicators) and `detect_insecure_cookies`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 5.1, 5.2_
  - [x] 2.7 Implement scoring (`N`, `F`, `round4`), the locale-independent `JsonWriter` (integer `std::to_chars`), `InspectHTTPPayload` with input bounds and boundary `try/catch`, the preformatted error-JSON fallback, `FreeInspectionResult`, and `NetChimeraEngineVersion`
    - _Requirements: 2.1, 2.3, 2.4, 2.6, 6.2, 6.3, 6.4, 6.5_
  - [x] 2.8 Fill in the Makefile targets `engine` (compile with the design CXXFLAGS, `ar rcs engine/build/libinspector.a`) and `engine-shared`; verify `make engine` builds warning-free with Apple clang
    - _Requirements: 6.6, 6.7, 21.1, 21.6_
  - [x]* 2.9 Write `engine/tests/harness.cpp`: golden vectors for each lab endpoint and control, correctness properties 1–10 from the design, null/empty/unterminated-buffer cases; add `engine-test` target with `-fsanitize=address,undefined`
    - _Requirements: 1.4, 2.3, 2.6, 6.8_

- [x] 3. Checkpoint: engine
  - Run `make engine` (and `make engine-test` if 2.9 was done). Confirm zero warnings, zero sanitizer reports, and the expected flags on golden vectors. Ask the user if anything is unclear before continuing.

- [x] 4. Go module, configuration, and CGO bridge
  - [x] 4.1 Initialize `proxy/go.mod` (`module netchimera/proxy`, `go 1.25`, `github.com/gorilla/websocket`), and add a root `go.work` including `proxy` (task 9.1 adds `target-lab` once its module exists)
    - _Requirements: 21.1_
  - [x] 4.2 Implement `proxy/config.go`: parse and validate every environment variable from the design with defaults; fail fast with clear messages; compute AI mode (`live` vs `mock`); never print `AI_API_KEY`
    - _Requirements: 8.1, 8.2, 8.3, 9.1, 10.3, 11.1, 11.2, 12.1, 12.2, 12.5_
  - [x] 4.3 Implement `proxy/bridge.go`: cgo preamble with per-OS LDFLAGS, `Finding` / `InspectionResult` types, `Inspect` (NUL→space, bound truncation, `C.CString` + deferred `C.free`, nil check, deferred `FreeInspectionResult`, `C.GoString`, unmarshal, `error` field check), `Entropy`, `EngineVersion`, atomic counters, and `EngineStats`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
  - [x] 4.4 Implement `BuildHeaderBlock(reqHeaders, respHeaders, status)` with deterministic sorted ordering and the `> ` / `< ` / `< :status:` format
    - _Requirements: 2.2, 7.4_
  - [x]* 4.5 Write `bridge_test.go`: round-trip against lab-style fixtures, NUL injection case, error path, 10k-call loop under `GODEBUG=cgocheck=1`, and concurrent calls from 8 goroutines
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 5. WebSocket hub and API server
  - [x] 5.1 Implement `proxy/ws.go`: envelope type and constructors for all six message types, `Hub` goroutine with register/unregister/broadcast (cap 1024, non-blocking `Publish`), per-client `send` cap 256 with slow-consumer eviction, read/write pumps (4 KiB read limit, 30 s ping, 60 s pong deadline), and an origin check against `UI_ORIGINS`
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.7_
  - [x] 5.2 Add the 200-entry ring buffer of `TRANSACTION_EVENT` and `AI_PATCH_EVENT` with replay on connect, and the 1 s `SYSTEM_STATUS` ticker reading engine, pool, AI, and hub counters
    - _Requirements: 11.5, 11.6_
  - [x] 5.3 Handle inbound `SET_THRESHOLD`: validate range and type, store atomically, broadcast `CONFIG_UPDATED`, publish a telemetry warning on invalid input
    - _Requirements: 10.3, 10.5_
  - [x] 5.4 Build the API mux on `API_ADDR`: `/ws`, `/api/status` (GET JSON of the current status), `/healthz`, and the CORS middleware for `/api/*` restricted to `UI_ORIGINS`
    - _Requirements: 11.1, 19.4_
  - [x]* 5.5 Write `ws_test.go`: origin rejection, slow consumer eviction without blocking others, ring replay order, threshold validation
    - _Requirements: 11.2, 11.4, 11.5, 10.3_

- [x] 6. Redaction, pipeline, and gatekeeper
  - [x] 6.1 Implement `proxy/redact.go`: Finding-span and credential-header redaction applied in descending offset order, Authorization scheme preserved
    - _Requirements: 11.8, 14.1_
  - [x] 6.2 Implement `proxy/pipeline.go`: `Transaction` type, bounded `jobs` channel, non-blocking `Submit` with drop counter, `INSPECT_WORKERS` workers, gzip/deflate decode with a 64 KiB `LimitReader`, `body_inspected` handling, bridge call, `TRANSACTION_EVENT` + `ENGINE_TELEMETRY` publishing with optional redaction and 2 KiB base64 body preview, and pooled-buffer return
    - _Requirements: 8.6, 9.1, 9.2, 9.3, 9.4, 11.8_
  - [x] 6.3 Implement the Gatekeeper: atomic threshold, the gate rule, classification priority table (including Go-side session-fixation correlation), path normalization, dedupe map with TTL sweeper, non-blocking `aiQueue` send with drop counter and telemetry, and `ai_status` on the event
    - _Requirements: 10.1, 10.2, 10.3, 10.4_
  - [x]* 6.4 Write `pipeline_test.go`: gate truth table, classification priority, path normalization, dedupe TTL, redaction completeness (property 12), zip bomb bound
    - _Requirements: 10.1, 10.4, 14.1, 9.2_

- [x] 7. Proxy hot path and process wiring
  - [x] 7.1 Implement `captureBody` in `proxy/proxy.go` (limit, truncation flag, single `onClose` via `sync.Once`, `sync.Pool` buffers)
    - _Requirements: 8.5_
  - [x] 7.2 Implement the router and `httputil.ReverseProxy` (`Rewrite` for reverse and allowlisted forward modes, `CONNECT` → 405, non-allowlisted → 403, self-loop refusal), `txState` in the request context, `ModifyResponse` capture and submit, and an `ErrorHandler` that returns 502 and submits a 502 Transaction
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.8, 8.9_
  - [x] 7.3 Implement `proxy/main.go`: load config, probe `EngineVersion`, construct Hub, Pipeline, Agent (placeholder consumer until task 10), and Simulator (stub until task 10); start both servers with `ReadHeaderTimeout`; graceful shutdown on SIGINT/SIGTERM with a 5 s drain and WS close code 1001
    - _Requirements: 8.1, 9.5, 11.1_
  - [x] 7.4 Fill in the Makefile `proxy` target (`CGO_ENABLED=1 go build -o proxy/netchimera ./proxy` after `engine`)
    - _Requirements: 21.1_
  - [x]* 7.5 Write `proxy_test.go`: streaming passthrough, body unmodified, capture limit, forward allowlist, CONNECT 405, 502 path, non-blocking behavior with a full queue (property 11)
    - _Requirements: 8.3, 8.4, 8.5, 8.6, 8.8, 8.9_

- [x] 8. Checkpoint: engine + bridge + proxy
  - Run the proxy against a throwaway upstream (or the lab, once task 9 exists), connect with `websocat ws://127.0.0.1:8081/ws -H 'Origin: http://localhost:3000'`, send a few `curl -x` and reverse requests, and confirm `TRANSACTION_EVENT`, `ENGINE_TELEMETRY`, and `SYSTEM_STATUS` messages. Run `go test ./...` if test tasks were done.

- [x] 9. Target lab
  - [x] 9.1 Initialize `target-lab/go.mod` (stdlib only), add it to `go.work`, and implement `target-lab/main.go` with every route and handler name from the design table, startup secret generation (`crypto/rand`, base62), `AKIAIOSFODNN7EXAMPLE`, a localhost default bind, and the red vulnerability banner
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7_
  - [x] 9.2 Fill in the Makefile `lab` target
    - _Requirements: 21.1_
  - [x] 9.3 Verify via the proxy with `curl` that each vulnerable route raises its expected flag and both control routes raise none
    - _Requirements: 3.5, 20.5_

- [x] 10. AI agent and mock generator
  - [x] 10.1 Implement `proxy/mock.go`: deterministic templates for all six classifications in the shared section format, with diffs anchored to the `target-lab/main.go` handlers and a generic middleware diff for other hosts, plus Nginx and Cloudflare rules; add a chunked streaming helper (48 bytes, 12 ms)
    - _Requirements: 13.1, 13.5, 21.5_
  - [x] 10.2 Implement the prompt builder in `proxy/agent.go`: system prompt with untrusted-data instructions, delimited user block with redacted Header Block, ≤ 8 KiB redacted body, scores, Findings, and classification hint
    - _Requirements: 14.1, 14.2, 14.4_
  - [x] 10.3 Implement the live client: `chat/completions` with `stream: true`, SSE parsing (1 MiB scanner, `[DONE]`), 50 ms delta coalescing into `AI_PATCH_STREAM`, `AI_TIMEOUT` context, and key-safe error reporting
    - _Requirements: 12.3, 12.5, 13.2_
  - [x] 10.4 Implement the section parser and diff validation, `Advisory` assembly, `AI_PATCH_EVENT` publishing, mock fallback with `source: "fallback"`, AI status/processed counters, and `AI_WORKERS` consumers of `aiQueue`; replace the stub from 7.3
    - _Requirements: 12.2, 12.4, 13.1, 13.3, 13.4, 14.3_
  - [x]* 10.5 Write `agent_test.go`: SSE parser edge cases with an `httptest` fake provider, fallback on 500/timeout, parser on missing sections, mock determinism (property 13), and `git apply --check` of mock diffs against a temp copy of `target-lab/`
    - _Requirements: 12.4, 13.4, 13.5_

- [x] 11. Attack simulator
  - [x] 11.1 Implement `proxy/simulate.go`: `POST /api/simulate` with the fixed scenario table from the design, run asynchronously through the proxy listener with 150 ms pacing, `202` response, 5 s rate limit with `429` and `Retry-After`; replace the stub from 7.3
    - _Requirements: 19.2, 19.3, 19.4_
  - [x] 11.2 Write `scripts/simulate.sh` mirroring the scenarios with `curl`, and fill in the Makefile `simulate` target
    - _Requirements: 19.5_

- [x] 12. Checkpoint: backend complete
  - With `make lab` and `make proxy` running and no env vars set, run `make simulate` and confirm via `websocat` that `AI_PATCH_STREAM` and `AI_PATCH_EVENT` (mock source) arrive for the WCD, credential leak, and session fixation scenarios, and that the controls produce no advisories.

- [x] 13. UI foundation
  - [x] 13.1 Scaffold `ui/` with Next.js 14 App Router + TypeScript + Tailwind 3; add `lucide-react`, `@xterm/xterm`, `@xterm/addon-fit`; set `output: "standalone"`; configure the theme palette, fonts, scanline overlay, and neon utilities in `tailwind.config.ts` and `globals.css`
    - _Requirements: 15.1, 15.2_
  - [x] 13.2 Implement `ui/lib/types.ts` mirroring the wire protocol, `ui/lib/sanitize.ts` (`stripControls`), and `ui/lib/hexdump.ts`
    - _Requirements: 17.1, 17.4_
  - [x] 13.3 Implement `ui/lib/ws.ts` (backoff with jitter, typed dispatch, `send`) and `ui/lib/store.ts` (`useSyncExternalStore`, rAF batching, 500-row and 100-advisory caps, streaming map)
    - _Requirements: 15.6, 16.3_

- [x] 14. UI panes
  - [x] 14.1 Implement `TopBar` with the Engine / Pool / AI / WS status pills, threshold slider with `SET_THRESHOLD` on release and `CONFIG_UPDATED` confirmation, and `SimulateButton` (POST, cooldown, 429 handling)
    - _Requirements: 15.3, 15.4, 19.1_
  - [x] 14.2 Implement `PacketStream` with `EntropyBar` (0–8 scale, 4.3 marker) and `AnomalyBadge` (green / amber / crimson rules), plus row selection
    - _Requirements: 16.1, 16.2, 16.3, 16.4_
  - [x] 14.3 Implement `Inspector` (client-only dynamic import, `FitAddon`, `ResizeObserver`, dispose on unmount): hex dump of the selected Transaction and color-coded telemetry, with every payload string passed through `stripControls`
    - _Requirements: 17.1, 17.2, 17.3, 17.4_
  - [x] 14.4 Implement `RemediationConsole` and `DiffView`: live streaming text, classification/severity/source chips, root cause, line-colored diff, Nginx and Cloudflare blocks, and "Copy Patch" with a 2 s confirmation; text nodes only
    - _Requirements: 18.1, 18.2, 18.3, 18.4_
  - [x] 14.5 Compose `app/page.tsx` into the three-pane layout (side by side at ≥ 1280 px, stacked below) and fill in the Makefile `ui` target
    - _Requirements: 15.5, 21.1_

- [x] 15. Build, containers, and run workflows
  - [x] 15.1 Write `proxy.Dockerfile` (`golang:1.25-bookworm` with `g++`, build engine + proxy, runtime `debian:bookworm-slim` with `libstdc++6` and `ca-certificates`, non-root user), `target-lab.Dockerfile`, and `ui/Dockerfile` (Node LTS, standalone output, non-root)
    - _Requirements: 21.3, 21.6_
  - [x] 15.2 Write `docker-compose.yml`: `target-lab`, `proxy` (`UPSTREAM_URL=http://target-lab:9190`, binds `0.0.0.0` inside the container, `env_file: .env` optional), and `ui`; all ports published on `127.0.0.1`; health checks and `depends_on`
    - _Requirements: 21.3, 21.5_
  - [x] 15.3 Complete the Makefile `build`, `dev` (parallel lab + proxy + UI with clean Ctrl-C teardown), `test`, `up`, `down`, and `clean` targets
    - _Requirements: 21.1, 21.2, 21.4_
  - [x]* 15.4 Add `make bench` (direct vs proxied p50/p99 latency report against the 1 ms budget) and `make e2e` (lab + proxy + simulate + WS assertions)
    - _Requirements: 8.7_

- [x] 16. Final verification and documentation
  - [x] 16.1 From a clean checkout with no env vars: run `make build`, `make dev`, open `http://localhost:3000`, click "Simulate Attack Traffic", and confirm rows, hex dump, telemetry, and mock advisories with a working "Copy Patch"; repeat with `docker compose up --build`
    - _Requirements: 21.1, 21.2, 21.3, 21.5_
  - [x] 16.2 Complete `README.md`: architecture diagram, quick start, provider setup (OpenAI / Ollama / DeepSeek), demo script for judges, security notes about the lab, and how Kiro specs, steering, and hooks were used
    - _Requirements: 20.7, 21.5_
