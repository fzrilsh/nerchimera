# Requirements Document

## Introduction

NetChimera is a real-time HTTP security analysis proxy built from four technologies joined into one pipeline:

1. A C++17 native inspection engine, compiled to a static library and called from Go through CGO.
2. A Go reverse/forward proxy with an asynchronous inspection worker pool, a WebSocket hub, and an AI orchestrator.
3. An LLM security agent that talks to any OpenAI-compatible chat completion API (OpenAI, Ollama, DeepSeek) and falls back to a deterministic offline generator.
4. A Next.js 14 tactical terminal UI (Tailwind CSS, Lucide icons, Xterm.js) that renders live traffic, engine telemetry, and AI remediation patches.

A bundled `target-lab` server exposes intentionally vulnerable endpoints (Web Cache Deception, leaked API/Bearer tokens, insecure and fixable session cookies) so the whole pipeline can be demonstrated with one click or one `curl`.

The project targets the Kiroween Hackathon, Frankenstein category. It must run fully offline with zero configuration.

## Glossary

- **Engine**: The C++17 inspection library in `engine/` (`inspector.h`, `inspector.cpp`).
- **Bridge**: The Go CGO wrapper in `proxy/bridge.go` that calls the Engine.
- **Proxy**: The Go HTTP proxy in `proxy/proxy.go`, listening on `:8080`.
- **Pipeline**: The bounded job queue and inspection worker pool inside the Proxy process.
- **Gatekeeper**: The Pipeline logic that decides whether a transaction is forwarded to the AI Agent.
- **aiQueue**: The bounded, buffered Go channel between the Gatekeeper and the AI Agent.
- **Hub**: The WebSocket broadcast hub in `proxy/ws.go`, serving `:8081/ws`.
- **AI Agent**: The advisory generator in `proxy/agent.go`.
- **Mock Generator**: The deterministic, offline advisory generator used when no API key is configured or the provider fails.
- **Advisory**: The structured AI output: classification, severity, root cause, unified diff, and proxy rules.
- **Transaction**: One captured HTTP request/response pair.
- **UI**: The Next.js 14 App Router application in `ui/`.
- **Target Lab**: The intentionally vulnerable Go server in `target-lab/`.
- **Header Block**: The serialized header string passed to the Engine. Request headers are prefixed with `> ` and response headers with `< `, one header per line, `\n` separated.
- **Finding**: A typed detection emitted by the Engine (for example `JWT`, `AWS_ACCESS_KEY`, `HIGH_ENTROPY_STRING`, `INSECURE_COOKIE`).
- **Static Extension**: One of `.css`, `.js`, `.png`, `.ico`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.woff`, `.woff2`.
- **Threshold**: The runtime-adjustable anomaly score cutoff for the Gatekeeper, default `0.65`.

## Requirements

### Requirement 1: Shannon Entropy Calculation

**User Story:** As a security analyst, I want the Engine to measure the Shannon entropy of byte sequences, so that random-looking secrets can be told apart from ordinary text.

#### Acceptance Criteria

1. WHEN `CalculateShannonEntropy(const char* data, int length)` is called with a non-null `data` and `length > 0`, THE Engine SHALL return `H(X) = -sum(P(x_i) * log2(P(x_i)))` computed over the frequency distribution of byte values in the first `length` bytes.
2. IF `data` is null or `length <= 0`, THEN THE Engine SHALL return `0.0` without dereferencing `data`.
3. THE Engine SHALL treat input as unsigned bytes and SHALL count embedded NUL bytes within `length` instead of stopping at them.
4. THE Engine SHALL return a value in the closed range `[0.0, 8.0]`, and SHALL return `0.0` for any input consisting of one repeated byte value.
5. THE Engine SHALL compute entropy in O(n) time using a fixed 256-entry frequency table and no heap allocation.

### Requirement 2: HTTP Payload Inspection Result

**User Story:** As the Go Pipeline, I want one Engine call per Transaction that returns all scores in a structured buffer, so that inspection crosses the CGO boundary only once.

#### Acceptance Criteria

1. WHEN `InspectHTTPPayload(const char* method, const char* path, const char* headers, const char* body)` is called, THE Engine SHALL return a heap-allocated, NUL-terminated JSON object containing `entropy_score` (double), `normalized_entropy` (double), `cache_deception_flag` (int 0/1), `secret_leak_flag` (int 0/1), `anomaly_score` (double), `findings` (array), `engine_version` (string), and `error` (string or null).
2. THE Engine SHALL compute `entropy_score` as the maximum Shannon entropy among candidate tokens taken from: the credential part of request `Authorization` headers, `Cookie` and `Set-Cookie` values, and body values of JSON fields whose key contains `token`, `secret`, `key`, `password`, `passwd`, `auth`, `session`, `jwt`, or `credential` (case-insensitive), plus candidate tokens evaluated under Requirement 4.
3. THE Engine SHALL compute `anomaly_score` as `S = (0.6 * N) + (0.4 * F)`, where `N = min(entropy_score / 6.0, 1.0)` and `F = max(cache_deception_flag, secret_leak_flag)`, rounded to 4 decimal places, so that `S` lies in `[0.0, 1.0]`.
4. THE Engine SHALL NOT copy any input bytes into the output JSON; each Finding SHALL contain only a type enum, a location enum (`header` or `body`), a byte offset, a byte length, and an entropy value.
5. WHEN any input pointer is null, THE Engine SHALL treat that input as an empty string.
6. THE Engine SHALL produce identical output for identical input (deterministic, no clocks, no randomness).

### Requirement 3: Web Cache Deception Detection

**User Story:** As a security analyst, I want the Engine to flag responses where private content is served on a cacheable static-looking path, so that Web Cache Deception is caught before a CDN stores it.

#### Acceptance Criteria

1. THE Engine SHALL evaluate the extension of the final path segment after removing the query string and fragment, percent-decoding `%2e`/`%2E`, and lowercasing.
2. WHEN the path ends with a Static Extension AND the response is cacheable (no `Cache-Control` directive `no-store` or `private` is present in the response headers) AND the response contains a `Set-Cookie` header, THE Engine SHALL set `cache_deception_flag` to `1`.
3. WHEN the path ends with a Static Extension AND the response is cacheable AND the response `Content-Type` is `text/html` or `application/json` AND the request carried a `Cookie` or `Authorization` header, THE Engine SHALL set `cache_deception_flag` to `1`.
4. WHEN the path does not end with a Static Extension, or the request method is not `GET` or `HEAD` (an empty method is treated as `GET`), THE Engine SHALL set `cache_deception_flag` to `0`, because shared caches store only `GET`/`HEAD` responses.
5. WHEN a static asset is served with a matching static `Content-Type` and no `Set-Cookie` header, THE Engine SHALL set `cache_deception_flag` to `0` even if `Cache-Control: no-store` is absent.
6. WHEN `cache_deception_flag` is `1`, THE Engine SHALL add a `WEB_CACHE_DECEPTION` Finding with location `header`.

### Requirement 4: Secret Leak Detection

**User Story:** As a security analyst, I want the Engine to detect API keys, JWTs, and database credentials in response bodies, so that secret exposure is caught as it happens.

#### Acceptance Criteria

1. THE Engine SHALL split the response body into candidate tokens made of the characters `[A-Za-z0-9+/=_\-.~]`.
2. WHEN a candidate token has length between 20 and 512 bytes inclusive AND contains at least one uppercase letter, one lowercase letter, and one digit AND has entropy greater than `4.3` bits per character, THE Engine SHALL set `secret_leak_flag` to `1` and add a `HIGH_ENTROPY_STRING` Finding. Only tokens meeting the length and character-class conditions contribute to `entropy_score`.
3. WHEN the response body contains a JWT (`eyJ` + base64url segment of at least 10 characters + `.` + segment of at least 10 + `.` + segment of at least 16), an AWS access key ID (`AKIA` or `ASIA` + 16 uppercase alphanumerics), an `sk-`/`sk_live_`/`sk_test_` key with at least 20 trailing key characters including at least one digit, a GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + at least 36 alphanumerics), a Slack token (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-` + at least 10 characters), a PEM private key header (`-----BEGIN` ... `PRIVATE KEY-----` on one line), or a database URI with an embedded password (`postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://` followed by `user:password@` with a non-empty password), THE Engine SHALL set `secret_leak_flag` to `1` and add a Finding of the matching type.
4. THE Engine SHALL implement all pattern matching with hand-written linear-time scanners and SHALL NOT use `std::regex`.
5. WHEN the response body contains no qualifying token or pattern, THE Engine SHALL set `secret_leak_flag` to `0`.

### Requirement 5: Insecure Session Cookie Findings

**User Story:** As a security analyst, I want weak cookie attributes reported, so that the AI Agent can classify session fixation and insecure session handling.

#### Acceptance Criteria

1. WHEN a response `Set-Cookie` header lacks `HttpOnly`, `Secure`, or `SameSite`, THE Engine SHALL add an `INSECURE_COOKIE` Finding with location `header`.
2. THE Engine SHALL NOT change `cache_deception_flag`, `secret_leak_flag`, or `anomaly_score` because of `INSECURE_COOKIE` Findings.

### Requirement 6: Engine ABI and Memory Safety

**User Story:** As a systems engineer, I want a strict C ABI and memory contract, so that the Go runtime can call the Engine concurrently without leaks, crashes, or undefined behavior.

#### Acceptance Criteria

1. THE Engine SHALL expose its public functions only through `extern "C"` declarations in `inspector.h` using C-compatible types.
2. THE Engine SHALL allocate each result buffer with `std::malloc`, and `FreeInspectionResult(char* ptr)` SHALL release it with `std::free`; WHEN `ptr` is null, `FreeInspectionResult` SHALL do nothing.
3. THE Engine SHALL catch every C++ exception inside each exported function; IF an internal error occurs, THEN THE Engine SHALL return a JSON result whose `error` field is set and whose scores are `0`; IF the result buffer itself cannot be allocated, THEN THE Engine SHALL return null.
4. THE Engine SHALL bound every input read: `method` to 16 bytes, `path` to 8192 bytes, `headers` to 65536 bytes, and `body` to 65536 bytes.
5. THE Engine SHALL hold no mutable global or static state, so that concurrent calls from multiple OS threads are safe.
6. THE Engine SHALL use only the C++17 standard library, SHALL have no third-party dependencies, and its source files SHALL contain no code comments.
7. THE Engine SHALL compile without warnings under `-std=c++17 -Wall -Wextra -Wpedantic -Werror` with both clang/libc++ (macOS) and gcc/libstdc++ (Linux).
8. WHEN built with `-fsanitize=address,undefined` and run against the Engine test harness, THE Engine SHALL report zero leaks and zero sanitizer errors.
9. THE Engine SHALL expose `const char* NetChimeraEngineVersion(void)` returning a pointer to static storage that callers SHALL NOT free.

### Requirement 7: Go CGO Bridge

**User Story:** As a Go developer, I want a safe Go wrapper around the Engine, so that the rest of the codebase never handles C memory.

#### Acceptance Criteria

1. THE Bridge SHALL copy each Go input into C memory and SHALL release every C allocation it creates with `defer C.free(...)` on all return paths.
2. WHEN the Engine returns a non-null result, THE Bridge SHALL copy it into Go memory with `C.GoString` and SHALL call `FreeInspectionResult` exactly once, via `defer`, before returning.
3. IF the Engine returns null, or returns JSON with a non-null `error`, or returns invalid JSON, THEN THE Bridge SHALL return a Go error and increment the engine error counter.
4. THE Bridge SHALL replace every NUL byte in the Header Block and body with `0x20` before the call, preserving byte offsets, so that NUL injection cannot hide content from the Engine.
5. THE Bridge SHALL NOT retain any C pointer after the call returns and SHALL NOT pass Go pointers to C, so that it complies with the cgo pointer-passing rules under `GODEBUG=cgocheck=1`.
6. THE Bridge SHALL record total calls, error count, and mean call duration in microseconds, readable concurrently through atomic counters.

### Requirement 8: Proxy Interception Hot Path

**User Story:** As an operator, I want traffic proxied with no noticeable delay, so that inspection never degrades the applications behind NetChimera.

#### Acceptance Criteria

1. THE Proxy SHALL listen on `PROXY_ADDR`, default `127.0.0.1:8080`.
2. WHEN a request uses origin-form (`GET /path`), THE Proxy SHALL forward it to `UPSTREAM_URL`, default `http://127.0.0.1:9190` (reverse mode).
3. WHEN a request uses absolute-form (`GET http://host/path`), THE Proxy SHALL forward it only if the host is listed in `FORWARD_ALLOWED_HOSTS` (default `localhost,127.0.0.1,target-lab`); otherwise THE Proxy SHALL respond `403`.
4. WHEN a request uses the `CONNECT` method, THE Proxy SHALL respond `405`, because TLS interception is out of scope.
5. THE Proxy SHALL stream response bodies to the client without buffering the full body, while capturing a copy of at most 65536 bytes of the response body and at most 16384 bytes of the request body.
6. WHEN the captured response body is closed, THE Proxy SHALL hand the Transaction to the Pipeline with a non-blocking send; IF the job queue is full, THEN THE Proxy SHALL drop the inspection, increment a drop counter, and SHALL NOT delay the response.
7. THE Proxy SHALL add no more than 1 ms of p99 latency compared with direct requests to the Target Lab, measured by the latency benchmark task.
8. IF the upstream is unreachable, THEN THE Proxy SHALL respond `502` and still publish a Transaction event with status `502`.
9. THE Proxy SHALL NOT modify request or response bodies.

### Requirement 9: Asynchronous Inspection Worker Pool

**User Story:** As a systems engineer, I want inspection performed by a bounded worker pool, so that CGO cost and bursts are isolated from request handling.

#### Acceptance Criteria

1. THE Pipeline SHALL run `INSPECT_WORKERS` workers (default `runtime.NumCPU()`) consuming a job channel of capacity `INSPECT_QUEUE_SIZE` (default 4096).
2. WHEN a worker receives a Transaction with `Content-Encoding: gzip` or `deflate`, THE worker SHALL decompress the captured body with an output limit of 65536 bytes before inspection.
3. WHEN a Transaction uses an unsupported content encoding, THE worker SHALL inspect headers only and set `body_inspected` to `false`.
4. WHEN inspection completes, THE worker SHALL publish a `TRANSACTION_EVENT` and an `ENGINE_TELEMETRY` message to the Hub.
5. WHEN the process receives SIGINT or SIGTERM, THE Pipeline SHALL stop accepting new jobs and drain in-flight jobs within 5 seconds before exit.

### Requirement 10: Mathematical Gatekeeper

**User Story:** As an operator, I want only meaningful anomalies sent to the LLM, so that AI cost and latency stay bounded.

#### Acceptance Criteria

1. WHEN `anomaly_score > Threshold` OR `cache_deception_flag == 1` OR `secret_leak_flag == 1`, THE Gatekeeper SHALL push the Transaction context onto `aiQueue` (capacity `AI_QUEUE_SIZE`, default 64) with a non-blocking send.
2. IF `aiQueue` is full, THEN THE Gatekeeper SHALL drop the item, increment the AI drop counter, and publish an `ENGINE_TELEMETRY` warning.
3. THE Gatekeeper SHALL use a Threshold of `0.65` by default and SHALL accept runtime updates through the `SET_THRESHOLD` WebSocket message; IF the value is outside `[0.0, 1.0]` or not a number, THEN THE Gatekeeper SHALL reject it and keep the current value.
4. WHEN a Transaction with the same classification key (primary Finding type, method, host, normalized path) was enqueued within `AI_DEDUPE_TTL` (default 120 s), THE Gatekeeper SHALL skip enqueueing and mark the event `ai_status: "deduplicated"`.
5. WHEN the Threshold changes, THE Hub SHALL broadcast `CONFIG_UPDATED` to all clients.

### Requirement 11: WebSocket Telemetry Hub

**User Story:** As a UI client, I want every transaction and advisory pushed in real time, so that the dashboard reflects live traffic.

#### Acceptance Criteria

1. THE Hub SHALL serve WebSocket connections at `API_ADDR` (default `127.0.0.1:8081`) on path `/ws`.
2. THE Hub SHALL reject WebSocket upgrades whose `Origin` is not listed in `UI_ORIGINS` (default `http://localhost:3000,http://127.0.0.1:3000,http://localhost:3100,http://127.0.0.1:3100`).
3. THE Hub SHALL send every message as a JSON envelope `{ "type", "ts", "data" }` with `type` one of `TRANSACTION_EVENT`, `ENGINE_TELEMETRY`, `SYSTEM_STATUS`, `AI_PATCH_STREAM`, `AI_PATCH_EVENT`, `CONFIG_UPDATED`.
4. THE Hub SHALL give each client a send buffer of 256 messages; IF a client's buffer is full, THEN THE Hub SHALL disconnect that client without blocking other clients or the Pipeline.
5. WHEN a client connects, THE Hub SHALL replay the most recent 200 `TRANSACTION_EVENT` and `AI_PATCH_EVENT` messages from a ring buffer.
6. THE Hub SHALL broadcast `SYSTEM_STATUS` every 1 second.
7. THE Hub SHALL limit inbound client messages to 4096 bytes and SHALL send pings every 30 seconds, closing connections that miss a pong for 60 seconds.
8. WHILE `REDACT_TELEMETRY` is `true` (default), THE Hub SHALL mask Finding spans and `Authorization`, `Cookie`, and `Set-Cookie` values in published events, keeping only the first 4 characters and the original length.

### Requirement 12: AI Provider Configuration and Fallback

**User Story:** As a hackathon judge, I want the AI Agent to work with any OpenAI-compatible provider and also fully offline, so that the demo works with or without an API key.

#### Acceptance Criteria

1. THE AI Agent SHALL read `AI_BASE_URL` (default `https://api.openai.com/v1`), `AI_API_KEY`, `AI_MODEL`, `AI_MODE` (`auto` or `mock`, default `auto`), `AI_TIMEOUT` (default 45 s), and `AI_WORKERS` (default 2) from the environment.
2. WHEN `AI_API_KEY` is empty, `AI_MODEL` is empty, or `AI_MODE=mock`, THE AI Agent SHALL use the Mock Generator and report mode `mock` in `SYSTEM_STATUS`.
3. WHILE in live mode, THE AI Agent SHALL call `POST {AI_BASE_URL}/chat/completions` with `stream: true` and parse the server-sent event stream.
4. IF the provider returns an error, times out, or produces an unparseable stream, THEN THE AI Agent SHALL generate that Advisory with the Mock Generator, set `source: "fallback"`, and publish an `ENGINE_TELEMETRY` error.
5. THE AI Agent SHALL never log or broadcast `AI_API_KEY`.

### Requirement 13: Security Advisory Content and Streaming

**User Story:** As a developer, I want each anomaly turned into a classified advisory with a ready-to-apply patch, so that I can fix the vulnerability right away.

#### Acceptance Criteria

1. THE AI Agent SHALL produce an Advisory with: a classification from `WEB_CACHE_DECEPTION`, `HIGH_ENTROPY_SECRET_EXPOSURE`, `CREDENTIAL_LEAK`, `SESSION_FIXATION`, `INSECURE_SESSION_COOKIE`, or `ANOMALOUS_ENTROPY`; a severity (`low`, `medium`, `high`, `critical`); a root cause analysis that names the specific path, headers, and Findings of the Transaction; a unified diff in `git diff` format; an Nginx rule; and a Cloudflare rule.
2. WHILE an Advisory is being generated, THE AI Agent SHALL publish `AI_PATCH_STREAM` messages containing the advisory id, transaction id, and text delta.
3. WHEN generation completes, THE AI Agent SHALL publish one `AI_PATCH_EVENT` containing the parsed Advisory sections and its `source` (`llm`, `mock`, or `fallback`).
4. IF the generated text lacks a required section, or the diff lacks `---`, `+++`, and `@@` lines, THEN THE AI Agent SHALL set `diff_valid: false` and include the raw text.
5. WHEN the Mock Generator receives the same Transaction context, THE Mock Generator SHALL produce byte-identical Advisory text that references the Transaction's actual path, header names, and Finding types, and SHALL stream it in chunks.

### Requirement 14: AI Data Protection

**User Story:** As a security architect, I want secrets and attacker-controlled content handled safely in AI prompts, so that the analyzer does not leak secrets or get hijacked.

#### Acceptance Criteria

1. THE AI Agent SHALL redact every Finding span and every `Authorization`, `Cookie`, and `Set-Cookie` value before building a prompt, keeping only the Finding type, length, and first 4 characters.
2. THE AI Agent SHALL place Transaction content inside a delimited untrusted-data block and SHALL instruct the model in the system prompt to treat that block as data, never as instructions.
3. THE System SHALL NOT execute, apply, or evaluate any LLM output; Advisories SHALL be displayed only.
4. THE AI Agent SHALL include at most 8192 bytes of response body in a prompt.

### Requirement 15: UI Shell, Theme, and Status Bar

**User Story:** As a judge, I want a dark tactical terminal interface showing system health at a glance, so that the pipeline's state is obvious.

#### Acceptance Criteria

1. THE UI SHALL be a Next.js 14 App Router application using Tailwind CSS, `lucide-react`, and `@xterm/xterm`.
2. THE UI SHALL use background `#08090c`, primary neon green `#00ff9d`, warning amber `#ffb800`, critical crimson `#ff0055`, and a monospace font stack.
3. THE UI SHALL show a top bar with Engine status and version, worker pool load (queue length / capacity and drops), AI Agent status and mode, WebSocket connection state, and a Threshold slider from `0.00` to `1.00` in `0.01` steps.
4. WHEN the Threshold slider is released, THE UI SHALL send `SET_THRESHOLD` and display the value confirmed by `CONFIG_UPDATED`.
5. WHILE the viewport is at least 1280 px wide, THE UI SHALL show the Packet Stream, Inspector, and Remediation Console as three side-by-side panes; below that width it SHALL stack them vertically.
6. WHEN the WebSocket disconnects, THE UI SHALL reconnect with exponential backoff from 0.5 s up to 10 s and show a disconnected indicator.

### Requirement 16: Live Packet Stream

**User Story:** As an analyst, I want a live table of transactions with entropy and anomaly scores, so that suspicious traffic stands out.

#### Acceptance Criteria

1. THE UI SHALL show each Transaction as a row with method, path, status, a Shannon entropy bar scaled `0` to `8` bits with a marker at `4.3`, and an anomaly score badge.
2. THE UI SHALL color the anomaly badge green below `0.40`, amber from `0.40` up to the Threshold, and crimson above the Threshold or when any flag is `1`.
3. THE UI SHALL keep at most 500 rows, newest first, and SHALL batch incoming events into at most one render per animation frame.
4. WHEN the user selects a row, THE UI SHALL load that Transaction into the Inspector.

### Requirement 17: Xterm.js Packet Inspector and Telemetry

**User Story:** As an analyst, I want a hex/raw view of packets and a live engine log, so that I can see exactly what the Engine saw.

#### Acceptance Criteria

1. WHEN a Transaction is selected, THE UI SHALL write a hex dump (offset, 16 bytes of hex, ASCII column) of its Header Block and body preview to the Xterm.js terminal.
2. THE UI SHALL stream `ENGINE_TELEMETRY` lines into the terminal, colored by level (`info` green, `warn` amber, `error` crimson).
3. THE UI SHALL load Xterm.js only on the client (no server-side rendering), fit it to its container on resize, and dispose it on unmount.
4. THE UI SHALL strip ESC (`0x1b`) and other C0/C1 control characters from all network-derived text before writing it to the terminal, so that captured traffic cannot inject terminal escape sequences.

### Requirement 18: AI Remediation Console

**User Story:** As a developer, I want to read the AI root cause and copy the patch with one click, so that remediation is fast.

#### Acceptance Criteria

1. THE UI SHALL list Advisories newest first and SHALL render `AI_PATCH_STREAM` text live while an Advisory is generating.
2. THE UI SHALL display classification, severity, source, root cause, the unified diff with line coloring (`+` green, `-` crimson, `@@` amber), the Nginx rule, and the Cloudflare rule.
3. WHEN the user clicks "Copy Patch", THE UI SHALL copy the exact diff text to the clipboard and show a confirmation for 2 seconds.
4. THE UI SHALL render all AI and network-derived text as React text nodes and SHALL NOT use `dangerouslySetInnerHTML`.

### Requirement 19: One-Click Attack Simulation

**User Story:** As a judge, I want one button that generates attack traffic, so that I can see the full pipeline without a terminal.

#### Acceptance Criteria

1. WHEN the user clicks "Simulate Attack Traffic", THE UI SHALL send `POST {API_URL}/api/simulate`.
2. WHEN `/api/simulate` is called, THE Proxy SHALL run a fixed, server-defined scenario list through its own listener against the Target Lab and respond `202`; THE endpoint SHALL NOT accept client-supplied URLs.
3. IF `/api/simulate` is called again within 5 seconds, THEN THE Proxy SHALL respond `429`.
4. THE Proxy SHALL restrict CORS on `/api/*` to `UI_ORIGINS`.
5. THE repository SHALL provide `make simulate`, which sends the same scenarios with `curl`.

### Requirement 20: Vulnerable Target Lab

**User Story:** As a demo presenter, I want a local vulnerable server, so that every detection path can be triggered on demand.

#### Acceptance Criteria

1. THE Target Lab SHALL be a Go standard-library-only server listening on `TARGET_ADDR`, default `127.0.0.1:9190`.
2. THE Target Lab SHALL expose `/account/<anything>.css`, which serves private account JSON with `Cache-Control: public, max-age=3600` and a `Set-Cookie` session header (Web Cache Deception).
3. THE Target Lab SHALL expose `/api/config`, which returns JSON containing a JWT, an AWS-format access key, an `sk-` style key, and a database URI with an embedded password (secret leak).
4. THE Target Lab SHALL expose `/login`, which accepts a `session` query parameter and sets it as the session cookie without `HttpOnly`, `Secure`, or `SameSite`, and returns a Bearer token in the body (session fixation and insecure cookie).
5. THE Target Lab SHALL expose benign control endpoints `/static/app.css` and `/api/health` that SHALL NOT raise any flag.
6. THE Target Lab SHALL generate fake secret values at startup (or use documented example values such as `AKIAIOSFODNN7EXAMPLE`) and SHALL NOT contain real credentials in the repository.
7. WHEN the Target Lab starts, THE Target Lab SHALL log a warning that it is intentionally vulnerable and must not be exposed publicly.

### Requirement 21: Build and Run Workflow

**User Story:** As a judge, I want one command to build and run everything, so that evaluation takes minutes.

#### Acceptance Criteria

1. THE repository SHALL provide `make build`, which builds the Engine static library, the Proxy, the Target Lab, and the UI, in that order.
2. THE repository SHALL provide `make dev`, which runs the Target Lab, Proxy, and UI locally.
3. THE repository SHALL provide `docker compose up --build`, which runs all three services and publishes ports `8080`, `8081`, `9190`, and `3100` on `127.0.0.1` only.
4. THE repository SHALL provide `make test`, which runs the Engine sanitizer harness and `go test ./...` for the Proxy.
5. WHEN no environment variables are set, THE System SHALL start with the Mock Generator and complete the full pipeline offline.
6. THE build SHALL work on macOS (Apple clang, libc++) and Linux (gcc, libstdc++).
