# NetChimera Security Rules

These rules are mandatory. NetChimera processes hostile traffic, crosses a C/Go memory boundary, and sends data to third-party LLMs. A change that violates a rule needs an explicit design update first.

## 1. CGO Memory Contract

1. `proxy/bridge.go` is the only file allowed to `import "C"`.
2. Each side frees only what it allocated:
   - Inputs: `C.CString(...)` is immediately followed by `defer C.free(unsafe.Pointer(p))`.
   - Result: after the nil check, `defer C.FreeInspectionResult(res)` runs exactly once. Never `C.free` an Engine result. Never free `NetChimeraEngineVersion()`.
3. Copy results to Go memory with `C.GoString` before the deferred free runs. Never store a C pointer in a struct, slice, map, channel, closure, or global.
4. Never pass a Go pointer to C. All inputs are copied.
5. Replace NUL bytes with `0x20` in header and body inputs before the call, and truncate to the engine bounds (method 16, path 8192, headers 65536, body 65536).
6. Tests run with `GODEBUG=cgocheck=1`.

## 2. C++ Engine Safety

1. No exception may cross the `extern "C"` boundary. Every exported function body is wrapped in `try { } catch (...) { }`.
2. Every input read is bounded with a capped length scan. Never call `strlen` on inputs.
3. Use `unsigned char` when indexing frequency tables. Never index with a plain (possibly signed) `char`.
4. Check every `offset + length` against the region size before access. Prefer `std::string_view::substr` with checked positions over raw pointer arithmetic.
5. No mutable global or `static` local state, no `thread_local`. The engine must be reentrant.
6. No `std::regex`, no recursion over input-dependent depth, no allocation proportional to anything other than bounded input size.
7. Output JSON contains only fixed keys, enum strings, and numbers. Never copy input bytes into the output.
8. Return buffers come from `std::malloc` and are released only by `FreeInspectionResult` via `std::free`. `FreeInspectionResult(nullptr)` is a no-op.
9. Engine changes must pass `make engine-test` (ASan + UBSan) with zero reports.

## 3. Go Concurrency and Hot Path

1. The request goroutine must not block on inspection, the Hub, or the AI. All hand-offs are non-blocking `select` with `default` and a drop counter.
2. Every channel has an explicit capacity. No unbounded goroutine spawning per request; work goes to fixed worker pools.
3. Shared mutable state is guarded by a mutex or atomic and is owned by exactly one component. The Hub goroutine is the only writer of its `clients` map.
4. Every goroutine has a shutdown path tied to the root `context.Context`.
5. Capture limits are fixed: 64 KiB response body, 16 KiB request body. Decompression is wrapped in `io.LimitReader(…, 65536)`.
6. Never modify proxied bodies. Header changes are limited to what `httputil.ReverseProxy` and `SetXForwarded` do.
7. Run `go test -race ./...` before marking Go tasks complete.

## 4. Network Exposure

1. Default binds are `127.0.0.1`. Only Docker overrides them to `0.0.0.0`, and Compose publishes on `127.0.0.1`.
2. Forward-proxy mode only reaches hosts in `FORWARD_ALLOWED_HOSTS`. `CONNECT` returns 405. Requests targeting the proxy's own listener are refused.
3. WebSocket upgrades require an exact `Origin` match against `UI_ORIGINS`. CORS on `/api/*` uses the same allowlist.
4. `/api/simulate` accepts no request parameters that influence targets. Scenarios are compiled in. It is rate-limited to one run per 5 s.
5. Servers set `ReadHeaderTimeout`. Client WS messages are capped at 4 KiB.

## 5. AI and Secrets

1. `AI_API_KEY` appears only in the outbound `Authorization` header. Never log it, never include it in errors, telemetry, or WS messages. On provider errors, log the HTTP status only, not the response body.
2. Always run `Redact` over the Header Block and body before building a prompt, regardless of `REDACT_TELEMETRY`. Cap prompt bodies at 8 KiB.
3. Captured traffic goes inside the `<<<UNTRUSTED_HTTP_TRANSACTION>>>` delimiters, and the system prompt states it is data only.
4. LLM output is display-only. Never execute it, `git apply` it, evaluate it, or use it to change proxy configuration.
5. No real secrets in the repository. The target-lab generates fake secrets at startup with `crypto/rand` or uses documented example values (`AKIAIOSFODNN7EXAMPLE`). `.env` is gitignored; only `.env.example` is committed.

## 6. UI Rendering

1. Never use `dangerouslySetInnerHTML`, `innerHTML`, or markdown-to-HTML rendering for network or AI data. Render as React text nodes.
2. Pass every network-derived string through `stripControls` before `terminal.write`. Only ANSI codes the UI creates itself may reach xterm.
3. The UI never builds request URLs from WS data. The only outbound calls are the configured WS URL and `POST {API_URL}/api/simulate`.
4. Clipboard writes use `navigator.clipboard.writeText` with the exact stored diff string.

## 7. Target Lab

1. The lab is intentionally vulnerable. Keep the vulnerabilities limited to those listed in the design (WCD, secret leak, session fixation, insecure cookies). Do not add RCE, file read, or SSRF behaviors.
2. It binds `127.0.0.1` by default and prints a warning banner on start.
