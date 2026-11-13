#include "inspector.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace {

struct Tally {
    int checks = 0;
    int failures = 0;

    void check(bool ok, const std::string& name) {
        ++checks;
        if (!ok) {
            ++failures;
            std::printf("FAIL  %s\n", name.c_str());
        }
    }
};

struct ParsedFinding {
    std::string type;
    std::string loc;
    std::size_t off = 0;
    std::size_t len = 0;
};

constexpr char kBase62[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
constexpr char kFuzzAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.~:;\"'{}[], \n<>@%\\";

std::string inspect(const char* method, const char* path, const char* headers, const char* body) {
    char* raw = InspectHTTPPayload(method, path, headers, body);
    if (raw == nullptr) {
        return std::string();
    }
    std::string out(raw);
    FreeInspectionResult(raw);
    return out;
}

bool contains(const std::string& s, const std::string& sub) {
    return s.find(sub) != std::string::npos;
}

double field(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    const std::size_t p = json.find(needle);
    if (p == std::string::npos) {
        return -1.0;
    }
    return std::strtod(json.c_str() + p + needle.size(), nullptr);
}

std::string string_field(const std::string& json, std::size_t from, const std::string& key, std::size_t& next) {
    const std::string needle = "\"" + key + "\":\"";
    const std::size_t p = json.find(needle, from);
    if (p == std::string::npos) {
        next = std::string::npos;
        return std::string();
    }
    const std::size_t start = p + needle.size();
    const std::size_t end = json.find('"', start);
    next = end;
    return json.substr(start, end - start);
}

std::size_t uint_field(const std::string& json, std::size_t from, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    const std::size_t p = json.find(needle, from);
    if (p == std::string::npos) {
        return 0;
    }
    return static_cast<std::size_t>(std::strtoull(json.c_str() + p + needle.size(), nullptr, 10));
}

std::vector<ParsedFinding> parse_findings(const std::string& json) {
    std::vector<ParsedFinding> out;
    std::size_t pos = json.find("\"findings\":[");
    while (pos != std::string::npos) {
        const std::size_t obj = json.find("{\"type\":\"", pos);
        if (obj == std::string::npos) {
            break;
        }
        ParsedFinding f;
        std::size_t next = 0;
        f.type = string_field(json, obj, "type", next);
        f.loc = string_field(json, next, "loc", next);
        f.off = uint_field(json, next, "off");
        f.len = uint_field(json, next, "len");
        out.push_back(f);
        pos = json.find('}', obj);
    }
    return out;
}

bool has_finding(const std::string& json, const std::string& type) {
    for (const ParsedFinding& f : parse_findings(json)) {
        if (f.type == type) {
            return true;
        }
    }
    return false;
}

std::size_t count_finding(const std::string& json, const std::string& type) {
    std::size_t n = 0;
    for (const ParsedFinding& f : parse_findings(json)) {
        if (f.type == type) {
            ++n;
        }
    }
    return n;
}

double round4(double x) {
    return std::round(x * 10000.0) / 10000.0;
}

double expected_score(const std::string& json) {
    const double entropy = field(json, "entropy_score");
    const double flag = std::max(field(json, "cache_deception_flag"), field(json, "secret_leak_flag"));
    return round4(0.6 * std::min(entropy / 6.0, 1.0) + 0.4 * flag);
}

std::string random_string(std::mt19937_64& rng, std::size_t len, const char* alphabet, std::size_t alphabet_len) {
    std::string s;
    s.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        s.push_back(alphabet[rng() % alphabet_len]);
    }
    return s;
}

std::string random_secret(std::mt19937_64& rng, std::size_t len) {
    for (;;) {
        std::string s = random_string(rng, len, kBase62, sizeof(kBase62) - 1);
        const bool upper = std::any_of(s.begin(), s.end(), [](char c) { return c >= 'A' && c <= 'Z'; });
        const bool lower = std::any_of(s.begin(), s.end(), [](char c) { return c >= 'a' && c <= 'z'; });
        const bool digit = std::any_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
        if (upper && lower && digit) {
            return s;
        }
    }
}

void test_entropy(Tally& t) {
    t.check(CalculateShannonEntropy(nullptr, 5) == 0.0, "entropy: null data returns 0");
    t.check(CalculateShannonEntropy("abc", 0) == 0.0, "entropy: zero length returns 0");
    t.check(CalculateShannonEntropy("abc", -3) == 0.0, "entropy: negative length returns 0");
    t.check(CalculateShannonEntropy("aaaa", 4) == 0.0, "entropy: repeated byte is 0");
    t.check(std::fabs(CalculateShannonEntropy("ab", 2) - 1.0) < 1e-12, "entropy: two symbols is 1 bit");
    t.check(std::fabs(CalculateShannonEntropy("a\0b\0", 4) - 1.5) < 1e-12, "entropy: embedded NUL bytes are counted");

    char all[256];
    for (int i = 0; i < 256; ++i) {
        all[i] = static_cast<char>(i);
    }
    t.check(std::fabs(CalculateShannonEntropy(all, 256) - 8.0) < 1e-9, "entropy: 256 distinct bytes is 8 bits");

    std::mt19937_64 rng(1);
    bool bounds_ok = true;
    bool permutation_ok = true;
    for (int it = 0; it < 2000; ++it) {
        const std::size_t len = 1 + rng() % 512;
        std::string s;
        s.reserve(len);
        for (std::size_t i = 0; i < len; ++i) {
            s.push_back(static_cast<char>(rng() & 0xff));
        }
        const double h = CalculateShannonEntropy(s.data(), static_cast<int>(s.size()));
        const double ceiling = std::log2(static_cast<double>(std::min<std::size_t>(256, len)));
        bounds_ok = bounds_ok && h >= 0.0 && h <= ceiling + 1e-12;
        std::shuffle(s.begin(), s.end(), rng);
        const double h2 = CalculateShannonEntropy(s.data(), static_cast<int>(s.size()));
        permutation_ok = permutation_ok && std::fabs(h - h2) < 1e-12;
    }
    t.check(bounds_ok, "property 1: 0 <= H <= log2(min(256, len))");
    t.check(permutation_ok, "property 2: entropy is permutation invariant");

    bool uniform_ok = true;
    for (int k = 1; k <= 256; ++k) {
        const int reps = 1 + static_cast<int>(rng() % 5);
        std::string s;
        for (int r = 0; r < reps; ++r) {
            for (int b = 0; b < k; ++b) {
                s.push_back(static_cast<char>(b));
            }
        }
        const double h = CalculateShannonEntropy(s.data(), static_cast<int>(s.size()));
        uniform_ok = uniform_ok && std::fabs(h - std::log2(static_cast<double>(k))) < 1e-9;
    }
    t.check(uniform_ok, "property 3: k equiprobable symbols give log2(k)");
}

void test_cache_deception(Tally& t) {
    const char* wcd_headers =
        "> Cookie: session=abc123\n"
        "> Host: localhost:8080\n"
        "< :status: 200\n"
        "< Cache-Control: public, max-age=3600\n"
        "< Content-Type: application/json\n"
        "< Set-Cookie: session=abc123; Path=/\n";

    std::string r = inspect("GET", "/account/profile.css", wcd_headers, "{\"user\":\"alice\",\"email\":\"alice@example.com\"}");
    t.check(field(r, "cache_deception_flag") == 1.0, "wcd: /account/profile.css with Set-Cookie is flagged");
    t.check(has_finding(r, "WEB_CACHE_DECEPTION"), "wcd: WEB_CACHE_DECEPTION finding emitted");
    t.check(field(r, "anomaly_score") > 0.65, "wcd: score passes default threshold");
    t.check(has_finding(r, "INSECURE_COOKIE"), "wcd: cookie without flags yields INSECURE_COOKIE");

    r = inspect("GET", "/account/avatar.png", wcd_headers, "{}");
    t.check(field(r, "cache_deception_flag") == 1.0, "wcd: .png extension is flagged");

    r = inspect("GET", "/account/x%2Ecss?v=1#top",
                "> Authorization: Bearer abc\n< Content-Type: text/html; charset=utf-8\n< Cache-Control: max-age=60\n",
                "<html></html>");
    t.check(field(r, "cache_deception_flag") == 1.0, "wcd: %2E decoding, dynamic type and request credentials");

    r = inspect("GET", "/account/profile.CSS", wcd_headers, "{}");
    t.check(field(r, "cache_deception_flag") == 1.0, "wcd: extension match is case-insensitive");

    r = inspect("GET", "/static/app.css",
                "> Host: localhost:8080\n< :status: 200\n< Content-Type: text/css\n< Cache-Control: public, max-age=86400\n",
                "body{color:#00ff9d;background:#08090c}");
    t.check(field(r, "cache_deception_flag") == 0.0 && field(r, "secret_leak_flag") == 0.0 && field(r, "anomaly_score") == 0.0,
            "wcd control: /static/app.css is fully benign");

    r = inspect("GET", "/static/app.css", "> Cookie: session=abc\n< Content-Type: text/css\n", "body{}");
    t.check(field(r, "cache_deception_flag") == 0.0, "wcd control: static type with request cookie but no Set-Cookie");

    r = inspect("GET", "/account/profile.css",
                "> Cookie: s=1\n< Cache-Control: no-store, private\n< Set-Cookie: s=1; HttpOnly; Secure; SameSite=Lax\n", "{}");
    t.check(field(r, "cache_deception_flag") == 0.0, "wcd: no-store blocks the flag");
    t.check(!has_finding(r, "INSECURE_COOKIE"), "cookie: HttpOnly + Secure + SameSite is not reported");

    r = inspect("GET", "/account/profile.css", "> Cookie: s=1\n< Cache-Control: private, max-age=0\n< Set-Cookie: s=1\n", "{}");
    t.check(field(r, "cache_deception_flag") == 0.0, "wcd: private blocks the flag");

    r = inspect("POST", "/account/profile.css", wcd_headers, "{}");
    t.check(field(r, "cache_deception_flag") == 0.0, "wcd: POST is not cacheable");

    r = inspect("HEAD", "/account/profile.css", wcd_headers, "");
    t.check(field(r, "cache_deception_flag") == 1.0, "wcd: HEAD is cacheable");

    r = inspect("GET", "/account", wcd_headers, "{}");
    t.check(field(r, "cache_deception_flag") == 0.0, "wcd: path without static extension");

    r = inspect("GET", "/.css", wcd_headers, "{}");
    t.check(field(r, "cache_deception_flag") == 0.0, "wcd: bare extension segment is not a static file");
}

void test_secrets(Tally& t) {
    const std::string config_body =
        "{\"jwt_signing_sample\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\","
        "\"aws_access_key_id\":\"AKIAIOSFODNN7EXAMPLE\","
        "\"openai_api_key\":\"sk-Zx81kQp2LmN7vR4tY9wB3cD6eF0gH5jK\","
        "\"database_url\":\"postgres://admin:S3cr3tPw@db:5432/prod\","
        "\"github\":\"ghp_abcdefghijklmnopqrstuvwxyz0123456789\","
        "\"slack\":\"xoxb-1234567890-abcdefghij\","
        "\"stripe\":\"sk-N0tARealKeyJustAFixture123\","
        "\"pem\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA\"}";

    std::string r = inspect("GET", "/api/config", "> Host: localhost:8080\n< :status: 200\n< Content-Type: application/json\n",
                            config_body.c_str());
    t.check(field(r, "secret_leak_flag") == 1.0, "secrets: /api/config sets secret_leak_flag");
    t.check(field(r, "cache_deception_flag") == 0.0, "secrets: /api/config is not WCD");
    t.check(field(r, "anomaly_score") > 0.9, "secrets: /api/config scores above 0.9");
    t.check(count_finding(r, "JWT") == 1, "secrets: JWT detected once");
    t.check(has_finding(r, "AWS_ACCESS_KEY"), "secrets: AWS access key detected");
    t.check(count_finding(r, "API_KEY_SK") == 2, "secrets: two sk- style keys detected");
    t.check(has_finding(r, "DB_CREDENTIAL_URI"), "secrets: database URI with password detected");
    t.check(has_finding(r, "GITHUB_TOKEN"), "secrets: GitHub token detected");
    t.check(has_finding(r, "SLACK_TOKEN"), "secrets: Slack token detected");
    t.check(has_finding(r, "PRIVATE_KEY_PEM"), "secrets: PEM private key header detected");
    t.check(!has_finding(r, "HIGH_ENTROPY_STRING"), "secrets: pattern findings suppress overlapping entropy findings");
    t.check(!contains(r, "admin") && !contains(r, "AKIA") && !contains(r, "eyJ") && !contains(r, "S3cr3t"),
            "secrets: no secret bytes are echoed");

    for (const ParsedFinding& f : parse_findings(r)) {
        if (f.type == "AWS_ACCESS_KEY") {
            t.check(config_body.substr(f.off, f.len) == "AKIAIOSFODNN7EXAMPLE", "secrets: AWS finding offset and length are exact");
        }
        if (f.type == "DB_CREDENTIAL_URI") {
            t.check(config_body.substr(f.off, f.len) == "postgres://admin:S3cr3tPw@db:5432/prod",
                    "secrets: DB URI finding offset and length are exact");
        }
    }

    r = inspect("GET", "/api/x", "", "{\"data\":\"q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA\"}");
    t.check(field(r, "secret_leak_flag") == 1.0 && has_finding(r, "HIGH_ENTROPY_STRING"), "secrets: random base62 token flagged by entropy");

    r = inspect("GET", "/", "< Content-Type: text/html\n",
                "<html><script src=\"/static/js/main-chunk.bundle.min.js\"></script>"
                "<p>The quick brown fox jumps over the lazy dog in 2026.</p>"
                "sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
                "id=123e4567-e89b-12d3-a456-426614174000 task-runner-description-without-digits "
                "redis://cache:6379/0 postgres://readonly@db/prod</html>");
    t.check(field(r, "secret_leak_flag") == 0.0, "secrets control: HTML, hex digest, UUID and password-less URIs are benign");

    r = inspect("GET", "/", "", "desk-reference-guide-chapter-twelve-appendix");
    t.check(field(r, "secret_leak_flag") == 0.0, "secrets control: words ending in sk- are not API keys");

    r = inspect("GET", "/", "", "eyJeyJeyJeyJeyJeyJeyJeyJ.eyJ.eyJ");
    t.check(count_finding(r, "JWT") == 0, "secrets: malformed nested eyJ is not a JWT");

    std::string many;
    for (int i = 0; i < 100; ++i) {
        many += "AKIAIOSFODNN7EXAMPLE ";
    }
    r = inspect("GET", "/", "", many.c_str());
    t.check(parse_findings(r).size() == 64 && field(r, "secret_leak_flag") == 1.0, "findings are capped at 64");
}

void test_session_and_scoring(Tally& t) {
    std::string r = inspect("POST", "/login?session=ATTACKER-FIXED-SESSION-0001",
                            "> Content-Type: application/x-www-form-urlencoded\n"
                            "< :status: 200\n"
                            "< Content-Type: application/json\n"
                            "< Set-Cookie: session=ATTACKER-FIXED-SESSION-0001; Path=/\n",
                            "{\"access_token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0."
                            "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk4\",\"token_type\":\"Bearer\"}");
    t.check(field(r, "secret_leak_flag") == 1.0 && has_finding(r, "JWT"), "login: bearer JWT in body is a leak");
    t.check(has_finding(r, "INSECURE_COOKIE"), "login: fixated cookie without flags is reported");
    t.check(field(r, "cache_deception_flag") == 0.0, "login: POST is never WCD");

    r = inspect("GET", "/api/profile",
                "> Authorization: Bearer q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA\n< Content-Type: application/json\n",
                "{\"name\":\"alice\",\"plan\":\"pro\"}");
    const double s = field(r, "anomaly_score");
    t.check(s > 0.4 && s < 0.65 && field(r, "secret_leak_flag") == 0.0, "scoring: legitimate bearer stays below 0.65");
    t.check(has_finding(r, "HIGH_ENTROPY_CREDENTIAL"), "scoring: strong bearer reported as informational credential");
    t.check(std::fabs(s - expected_score(r)) <= 1.5e-4, "scoring: S = 0.6*N + 0.4*F");

    r = inspect("GET", "/api/health", "> Host: localhost:8080\n< :status: 200\n< Content-Type: application/json\n",
                "{\"status\":\"ok\"}");
    t.check(field(r, "anomaly_score") == 0.0 && parse_findings(r).empty(), "control: /api/health is fully benign");

    r = inspect("GET", "/", "> Cookie: a=1; theme=dark; sid=\"Q9x2Lm7vR4tY8wB3cD6eF1gH5jK0pZ\"\n", "");
    t.check(has_finding(r, "HIGH_ENTROPY_CREDENTIAL") && field(r, "entropy_score") > 4.3, "cookies: quoted multi-pair cookie values are scored");
}

void test_robustness(Tally& t) {
    std::string r = inspect(nullptr, nullptr, nullptr, nullptr);
    t.check(contains(r, "\"error\":null") && field(r, "anomaly_score") == 0.0, "robustness: all-null inputs");
    r = inspect("", "", "", "");
    t.check(contains(r, "\"error\":null") && field(r, "anomaly_score") == 0.0, "robustness: all-empty inputs");
    FreeInspectionResult(nullptr);
    t.check(std::strcmp(NetChimeraEngineVersion(), "1.0.0") == 0 && contains(r, "\"engine_version\":\"1.0.0\""),
            "robustness: version string");

    char* method = static_cast<char*>(std::malloc(16));
    char* path = static_cast<char*>(std::malloc(8192));
    char* headers = static_cast<char*>(std::malloc(65536));
    char* body = static_cast<char*>(std::malloc(65536));
    std::memset(method, 'G', 16);
    std::memset(path, '/', 8192);
    std::memset(headers, '<', 65536);
    std::memset(body, 'A', 65536);
    r = inspect(method, path, headers, body);
    t.check(contains(r, "\"error\":null"), "property 6: unterminated max-size buffers are read within bounds");
    std::free(method);
    std::free(path);
    std::free(headers);
    std::free(body);

    std::string headers_lines;
    while (headers_lines.size() < 70000) {
        headers_lines += "< Set-Cookie: k=v\n";
    }
    r = inspect("GET", "/x.css", headers_lines.c_str(), "");
    t.check(contains(r, "\"error\":null") && parse_findings(r).size() <= 64, "robustness: oversized header block is truncated");

    std::string garbage = "> \n< :\n<  : x\n>:\n< x\n> :status\n";
    r = inspect("GET", "/", garbage.c_str(), "\"unterminated \\");
    t.check(contains(r, "\"error\":null"), "robustness: malformed header lines and JSON");
}

void test_fuzz(Tally& t) {
    std::mt19937_64 rng(42);
    bool deterministic = true;
    bool score_ok = true;
    bool bounds_ok = true;
    bool no_echo = true;
    bool no_error = true;
    for (int it = 0; it < 3000; ++it) {
        std::string body = random_string(rng, rng() % 4096, kFuzzAlphabet, sizeof(kFuzzAlphabet) - 1);
        const std::string secret = random_secret(rng, 40);
        body.insert(body.size() / 2, " " + secret + " ");
        std::string headers;
        const std::size_t lines = rng() % 12;
        for (std::size_t l = 0; l < lines; ++l) {
            headers += (rng() & 1) ? "> " : "< ";
            headers += random_string(rng, rng() % 64, kFuzzAlphabet, sizeof(kFuzzAlphabet) - 1);
            headers += "\n";
        }
        const std::string path = "/" + random_string(rng, rng() % 64, kFuzzAlphabet, sizeof(kFuzzAlphabet) - 1);

        const std::string a = inspect("GET", path.c_str(), headers.c_str(), body.c_str());
        const std::string b = inspect("GET", path.c_str(), headers.c_str(), body.c_str());
        deterministic = deterministic && a == b && !a.empty();
        no_error = no_error && contains(a, "\"error\":null");

        const double s = field(a, "anomaly_score");
        score_ok = score_ok && s >= 0.0 && s <= 1.0 && std::fabs(s - expected_score(a)) <= 1.5e-4;

        for (const ParsedFinding& f : parse_findings(a)) {
            const std::size_t region = f.loc == "body" ? body.size() : headers.size();
            bounds_ok = bounds_ok && f.off + f.len <= region;
        }
        for (std::size_t k = 0; k + 8 <= secret.size(); ++k) {
            no_echo = no_echo && !contains(a, secret.substr(k, 8));
        }
    }
    t.check(deterministic, "property 5: identical inputs give identical output");
    t.check(no_error, "fuzz: no internal errors");
    t.check(score_ok, "property 4: score in [0,1] and matches formula");
    t.check(bounds_ok, "property 7: findings lie within their region");
    t.check(no_echo, "property 8: high-entropy body content is never echoed");
}

void test_memory_and_concurrency(Tally& t) {
    for (int i = 0; i < 20000; ++i) {
        char* r = InspectHTTPPayload("GET", "/a.css", "< Set-Cookie: a=b\n", "AKIAIOSFODNN7EXAMPLE");
        FreeInspectionResult(r);
    }
    t.check(true, "property 9: repeated inspect/free cycles");

    const std::string headers = "> Authorization: Bearer q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA\n< Set-Cookie: s=1\n< Cache-Control: public\n";
    const std::string body = "{\"k\":\"AKIAIOSFODNN7EXAMPLE\",\"t\":\"q8Zt3LmW9xR2vB7nK4pY6sD1fG5hJ0cA\"}";
    const std::string reference = inspect("GET", "/account/x.js", headers.c_str(), body.c_str());
    std::atomic<int> mismatches{0};
    std::vector<std::thread> threads;
    for (int th = 0; th < 8; ++th) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 1000; ++i) {
                if (inspect("GET", "/account/x.js", headers.c_str(), body.c_str()) != reference) {
                    mismatches.fetch_add(1);
                }
            }
        });
    }
    for (std::thread& th : threads) {
        th.join();
    }
    t.check(mismatches.load() == 0, "property 10: 8 threads x 1000 calls give identical output");
}

}

int main() {
    Tally t;
    test_entropy(t);
    test_cache_deception(t);
    test_secrets(t);
    test_session_and_scoring(t);
    test_robustness(t);
    test_fuzz(t);
    test_memory_and_concurrency(t);
    std::printf("engine harness: %d checks, %d failures\n", t.checks, t.failures);
    return t.failures == 0 ? 0 : 1;
}
