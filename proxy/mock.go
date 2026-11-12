package main

import (
	"fmt"
	"sort"
	"strings"
)

// The mock generator produces advisories offline. Its output is a pure function
// of the job's classification, method, host, normalized path, sorted finding
// types, and sorted header names, so the same anomaly always yields byte-
// identical text. It uses the same section format as the live model, so one
// parser handles both. No clocks, randomness, or map iteration order are used.

func mockGenerate(job AIJob) string {
	findingTypes := sortedFindingTypes(job.Result.Findings)
	headerNames := headerNamesFromBlock(job.HeaderBlock)
	tmpl := mockTemplate(job.Classification)

	var b strings.Builder
	section(&b, "CLASSIFICATION", job.Classification)
	section(&b, "SEVERITY", job.Severity)
	section(&b, "TITLE", tmpl.title)
	section(&b, "ROOT_CAUSE", tmpl.rootCause(job, findingTypes, headerNames))
	sectionRaw(&b, "PATCH", "```diff\n"+tmpl.diff(job)+"```")
	sectionRaw(&b, "NGINX_RULE", "```nginx\n"+tmpl.nginx(job)+"```")
	sectionRaw(&b, "CLOUDFLARE_RULE", "```\n"+tmpl.cloudflare(job)+"```")
	return b.String()
}

func section(b *strings.Builder, name, body string) {
	fmt.Fprintf(b, "### %s\n%s\n\n", name, strings.TrimSpace(body))
}

func sectionRaw(b *strings.Builder, name, body string) {
	fmt.Fprintf(b, "### %s\n%s\n\n", name, body)
}

type mockTmpl struct {
	title      string
	rootCause  func(AIJob, []string, []string) string
	diff       func(AIJob) string
	nginx      func(AIJob) string
	cloudflare func(AIJob) string
}

func mockTemplate(class string) mockTmpl {
	switch class {
	case "WEB_CACHE_DECEPTION":
		return mockTmpl{
			title: "Private response served on a cacheable static path",
			rootCause: func(job AIJob, ft, hn []string) string {
				return fmt.Sprintf(
					"The response to %s %s is cacheable (no Cache-Control: no-store or private) yet it "+
						"carries session state (findings: %s; request/response headers: %s). A shared cache or CDN "+
						"can store the authenticated body under the static-looking URL and replay it to other users. "+
						"The fix forces no-store on dynamic responses even when the path ends in a static extension.",
					job.Method, pathOnly(job.Path), joinOr(ft, "none"), joinOr(hn, "none"))
			},
			diff:       diffCacheControl,
			nginx:      nginxNoStoreDynamic,
			cloudflare: cfBypassCacheCookie,
		}
	case "CREDENTIAL_LEAK":
		return mockTmpl{
			title: "High-value credentials returned in a response body",
			rootCause: func(job AIJob, ft, hn []string) string {
				return fmt.Sprintf(
					"The response to %s %s exposes live credential material in its body. NetChimera matched %s. "+
						"Secrets must never be serialized to clients; they belong in a server-side secret store and "+
						"should be scrubbed from any config or debug endpoint. Rotate every exposed secret immediately.",
					job.Method, pathOnly(job.Path), joinOr(ft, "high-entropy tokens"))
			},
			diff:       diffRemoveSecrets,
			nginx:      nginxBlockConfigPath,
			cloudflare: cfBlockPath,
		}
	case "HIGH_ENTROPY_SECRET_EXPOSURE":
		return mockTmpl{
			title: "High-entropy token exposed in a response body",
			rootCause: func(job AIJob, ft, hn []string) string {
				return fmt.Sprintf(
					"The response to %s %s contains a high-entropy string (findings: %s) above NetChimera's 4.3 "+
						"bits/char threshold, consistent with an API key or token. Remove the value from the body or "+
						"replace it with an opaque, server-side reference.",
					job.Method, pathOnly(job.Path), joinOr(ft, "HIGH_ENTROPY_STRING"))
			},
			diff:       diffRemoveSecrets,
			nginx:      nginxBlockConfigPath,
			cloudflare: cfBlockPath,
		}
	case "SESSION_FIXATION":
		return mockTmpl{
			title: "Session id accepted from the request and set verbatim",
			rootCause: func(job AIJob, ft, hn []string) string {
				return fmt.Sprintf(
					"%s %s takes a caller-supplied session identifier and installs it as the session cookie without "+
						"regenerating it after authentication, and the cookie lacks HttpOnly, Secure, and SameSite "+
						"(findings: %s). An attacker can fix a victim's session id ahead of login and then reuse it. "+
						"The fix generates a fresh id server-side and hardens the cookie attributes.",
					job.Method, pathOnly(job.Path), joinOr(ft, "INSECURE_COOKIE"))
			},
			diff:       diffSessionFixation,
			nginx:      nginxHardenCookie,
			cloudflare: cfBlockQueryParam,
		}
	case "INSECURE_SESSION_COOKIE":
		return mockTmpl{
			title: "Session cookie missing HttpOnly, Secure, or SameSite",
			rootCause: func(job AIJob, ft, hn []string) string {
				return fmt.Sprintf(
					"The response to %s %s sets a session cookie without the full set of protective attributes "+
						"(findings: %s). Without HttpOnly the cookie is readable from JavaScript, without Secure it "+
						"travels over plaintext, and without SameSite it is sent on cross-site requests.",
					job.Method, pathOnly(job.Path), joinOr(ft, "INSECURE_COOKIE"))
			},
			diff:       diffHardenCookie,
			nginx:      nginxHardenCookie,
			cloudflare: cfBlockPath,
		}
	default:
		return mockTmpl{
			title: "Anomalous entropy in an HTTP transaction",
			rootCause: func(job AIJob, ft, hn []string) string {
				return fmt.Sprintf(
					"NetChimera scored %s %s at anomaly %.4f (entropy %.2f bits/char), above the active threshold. "+
						"Findings: %s. Review whether this endpoint should return high-entropy data to clients.",
					job.Method, pathOnly(job.Path), job.Result.AnomalyScore, job.Result.EntropyScore, joinOr(ft, "none"))
			},
			diff:       diffGenericMiddleware,
			nginx:      nginxNoStoreDynamic,
			cloudflare: cfBlockPath,
		}
	}
}

// isLabPath reports whether the path maps to a known target-lab handler, so the
// mock can emit a diff that actually applies to target-lab/main.go.
func isLabPath(job AIJob) bool {
	p := pathOnly(job.Path)
	switch {
	case strings.HasPrefix(p, "/account/"):
		return true
	case p == "/api/config", p == "/login":
		return true
	}
	return false
}

func diffCacheControl(job AIJob) string {
	if !isLabPath(job) {
		return diffGenericMiddleware(job)
	}
	return "--- a/target-lab/main.go\n" +
		"+++ b/target-lab/main.go\n" +
		"@@ -135,4 +135,4 @@ func (s *server) handleAccountWildcard(w http.ResponseWriter, r *http.Request) {\n" +
		" \tw.Header().Set(\"Content-Type\", \"application/json\")\n" +
		"-\tw.Header().Set(\"Cache-Control\", \"public, max-age=3600\")\n" +
		"+\tw.Header().Set(\"Cache-Control\", \"no-store, private\")\n" +
		" \thttp.SetCookie(w, &http.Cookie{Name: \"session\", Value: s.sec.sessADMN, Path: \"/\"})\n" +
		" \twriteJSON(w, s.accountBody())\n"
}

func diffRemoveSecrets(job AIJob) string {
	if pathOnly(job.Path) != "/api/config" {
		return diffGenericMiddleware(job)
	}
	return "--- a/target-lab/main.go\n" +
		"+++ b/target-lab/main.go\n" +
		"@@ -156,7 +156,3 @@ func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {\n" +
		" \t\t\"service\":           \"billing-api\",\n" +
		"-\t\t\"jwt_signing_sample\": s.sec.jwt,\n" +
		"-\t\t\"aws_access_key_id\":  s.sec.awsKey,\n" +
		"-\t\t\"openai_api_key\":     s.sec.skKey,\n" +
		"-\t\t\"database_url\":       s.sec.dbURL,\n" +
		"-\t\t\"debug\":              true,\n" +
		"+\t\t\"debug\":              false,\n" +
		" \t})\n"
}

func diffSessionFixation(job AIJob) string {
	if pathOnly(job.Path) != "/login" {
		return diffGenericMiddleware(job)
	}
	return "--- a/target-lab/main.go\n" +
		"+++ b/target-lab/main.go\n" +
		"@@ -168,8 +168,12 @@ func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {\n" +
		"-\tsession := r.URL.Query().Get(\"session\")\n" +
		"-\tif session == \"\" {\n" +
		"-\t\tsession = randString(26)\n" +
		"-\t}\n" +
		"+\tsession := randString(26)\n" +
		" \tw.Header().Set(\"Content-Type\", \"application/json\")\n" +
		" \tw.Header().Set(\"Cache-Control\", \"no-store\")\n" +
		"-\tw.Header().Add(\"Set-Cookie\", \"session=\"+session+\"; Path=/\")\n" +
		"+\thttp.SetCookie(w, &http.Cookie{\n" +
		"+\t\tName:     \"session\",\n" +
		"+\t\tValue:    session,\n" +
		"+\t\tPath:     \"/\",\n" +
		"+\t\tHttpOnly: true,\n" +
		"+\t\tSecure:   true,\n" +
		"+\t\tSameSite: http.SameSiteStrictMode,\n" +
		"+\t})\n" +
		" \twriteJSON(w, map[string]any{\n"
}

func diffHardenCookie(job AIJob) string {
	return diffSessionFixation(job)
}

func diffGenericMiddleware(_ AIJob) string {
	return "--- a/server/middleware.go\n" +
		"+++ b/server/middleware.go\n" +
		"@@ -6,6 +6,8 @@ func SecurityHeaders(next http.Handler) http.Handler {\n" +
		" func SecurityHeaders(next http.Handler) http.Handler {\n" +
		" \treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" +
		"+\t\tw.Header().Set(\"Cache-Control\", \"no-store, private\")\n" +
		"+\t\tw.Header().Set(\"Vary\", \"Cookie, Authorization\")\n" +
		" \t\tnext.ServeHTTP(w, r)\n" +
		" \t})\n" +
		" }\n"
}

func nginxNoStoreDynamic(job AIJob) string {
	return fmt.Sprintf(`location = %s {
    proxy_pass http://upstream;
    proxy_hide_header Cache-Control;
    add_header Cache-Control "no-store, private" always;
    proxy_cache off;
}`, pathOnly(job.Path))
}

func nginxBlockConfigPath(job AIJob) string {
	return fmt.Sprintf(`location = %s {
    return 403;
}`, pathOnly(job.Path))
}

func nginxHardenCookie(job AIJob) string {
	return `proxy_cookie_flags session httponly secure samesite=strict;`
}

func cfBypassCacheCookie(job AIJob) string {
	return fmt.Sprintf(`# Cache Rule: Bypass cache when a session cookie is present
(http.request.uri.path eq "%s" and any(http.request.cookies["session"][*] ne ""))
=> Bypass cache`, pathOnly(job.Path))
}

func cfBlockPath(job AIJob) string {
	return fmt.Sprintf(`# WAF custom rule
(http.request.uri.path eq "%s")
=> Block`, pathOnly(job.Path))
}

func cfBlockQueryParam(job AIJob) string {
	return `# WAF custom rule: reject caller-supplied session id
(len(http.request.uri.query) > 0 and http.request.uri.query contains "session=")
=> Managed Challenge`
}

func sortedFindingTypes(findings []Finding) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range findings {
		if _, ok := seen[f.Type]; !ok {
			seen[f.Type] = struct{}{}
			out = append(out, f.Type)
		}
	}
	sort.Strings(out)
	return out
}

func headerNamesFromBlock(block string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(block, "\n") {
		if len(line) < 3 || (line[0] != '>' && line[0] != '<') || line[1] != ' ' {
			continue
		}
		rest := line[2:]
		colon := strings.IndexByte(rest, ':')
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(rest[:colon])
		if name == "" || name == ":status" {
			continue
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func pathOnly(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

func joinOr(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	return strings.Join(items, ", ")
}
