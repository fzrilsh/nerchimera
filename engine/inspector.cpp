#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#pragma GCC visibility push(default)
#include "inspector.h"
#pragma GCC visibility pop

namespace {

constexpr std::size_t kMaxMethod = 16;
constexpr std::size_t kMaxPath = 8192;
constexpr std::size_t kMaxHeaders = 65536;
constexpr std::size_t kMaxBody = 65536;
constexpr std::size_t kMaxFindings = 64;
constexpr std::size_t kMinSecretLen = 20;
constexpr std::size_t kMaxSecretLen = 512;
constexpr std::size_t kMaxJsonKeyLen = 64;
constexpr std::size_t kMaxUriLen = 512;
constexpr std::size_t kMaxUserinfoLen = 256;
constexpr std::size_t kPemWindow = 80;
constexpr double kSecretEntropy = 4.3;
constexpr double kEntropyCeiling = 6.0;
constexpr double kEntropyWeight = 0.6;
constexpr double kFlagWeight = 0.4;

constexpr char kVersion[] = "1.0.0";
constexpr char kErrorJson[] =
    "{\"entropy_score\":0.0000,\"normalized_entropy\":0.0000,\"cache_deception_flag\":0,"
    "\"secret_leak_flag\":0,\"anomaly_score\":0.0000,\"findings\":[],"
    "\"engine_version\":\"1.0.0\",\"error\":\"internal_error\"}";

enum class FindingType : std::size_t {
    WebCacheDeception,
    HighEntropyString,
    Jwt,
    AwsAccessKey,
    ApiKeySk,
    GithubToken,
    SlackToken,
    PrivateKeyPem,
    DbCredentialUri,
    InsecureCookie,
    HighEntropyCredential,
    Count
};

constexpr std::array<std::string_view, static_cast<std::size_t>(FindingType::Count)> kFindingNames = {
    "WEB_CACHE_DECEPTION",
    "HIGH_ENTROPY_STRING",
    "JWT",
    "AWS_ACCESS_KEY",
    "API_KEY_SK",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "PRIVATE_KEY_PEM",
    "DB_CREDENTIAL_URI",
    "INSECURE_COOKIE",
    "HIGH_ENTROPY_CREDENTIAL",
};

constexpr std::array<std::string_view, 10> kStaticExtensions = {
    ".css", ".js", ".png", ".ico", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
};

constexpr std::array<std::string_view, 9> kSensitiveKeys = {
    "token", "secret", "key", "password", "passwd", "auth", "session", "jwt", "credential",
};

constexpr std::array<std::string_view, 7> kDbSchemes = {
    "postgresql://", "postgres://", "mysql://", "mongodb+srv://", "mongodb://", "redis://", "amqp://",
};

constexpr std::array<std::string_view, 5> kGithubPrefixes = {"ghp_", "gho_", "ghu_", "ghs_", "ghr_"};

constexpr std::array<std::string_view, 5> kSlackPrefixes = {"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"};

struct Finding {
    FindingType type;
    bool in_body;
    std::size_t off;
    std::size_t len;
    double entropy;
};

struct HeaderView {
    bool request;
    std::string_view name;
    std::string_view value;
    std::size_t value_off;
};

struct Analysis {
    double entropy_score = 0.0;
    int cache_deception = 0;
    int secret_leak = 0;
    std::vector<Finding> findings;
};

std::size_t bounded_len(const char* p, std::size_t max) {
    if (p == nullptr) {
        return 0;
    }
    std::size_t n = 0;
    while (n < max && p[n] != '\0') {
        ++n;
    }
    return n;
}

std::string_view bounded_view(const char* p, std::size_t max) {
    const std::size_t n = bounded_len(p, max);
    if (n == 0) {
        return std::string_view();
    }
    return std::string_view(p, n);
}

constexpr char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr bool is_upper(char c) {
    return c >= 'A' && c <= 'Z';
}

constexpr bool is_lower(char c) {
    return c >= 'a' && c <= 'z';
}

constexpr bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

constexpr bool is_alnum(char c) {
    return is_upper(c) || is_lower(c) || is_digit(c);
}

constexpr bool is_b64url(char c) {
    return is_alnum(c) || c == '-' || c == '_';
}

constexpr bool is_token_char(char c) {
    return is_alnum(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '.' || c == '~';
}

constexpr bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

constexpr bool is_uri_stop(char c) {
    return is_space(c) || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`' || c == ',' || c == '\\';
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) {
            return false;
        }
    }
    return true;
}

bool at(std::string_view s, std::size_t i, std::string_view lit) {
    return i <= s.size() && s.size() - i >= lit.size() && s.substr(i, lit.size()) == lit;
}

bool iat(std::string_view s, std::size_t i, std::string_view lit) {
    return i <= s.size() && s.size() - i >= lit.size() && iequals(s.substr(i, lit.size()), lit);
}

bool icontains(std::string_view hay, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > hay.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        if (iat(hay, i, needle)) {
            return true;
        }
    }
    return false;
}

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

std::size_t leading_space(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && is_space(s[i])) {
        ++i;
    }
    return i;
}

std::string_view trim(std::string_view s) {
    s.remove_prefix(leading_space(s));
    while (!s.empty() && is_space(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

double entropy_bytes(const unsigned char* data, std::size_t n) {
    if (data == nullptr || n == 0) {
        return 0.0;
    }
    std::array<std::size_t, 256> counts{};
    for (std::size_t i = 0; i < n; ++i) {
        ++counts[data[i]];
    }
    const double inv = 1.0 / static_cast<double>(n);
    double h = 0.0;
    for (std::size_t c : counts) {
        if (c != 0) {
            const double p = static_cast<double>(c) * inv;
            h -= p * std::log2(p);
        }
    }
    if (!(h > 0.0)) {
        return 0.0;
    }
    return std::min(h, 8.0);
}

double entropy_sv(std::string_view s) {
    return entropy_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

void add_finding(Analysis& a, FindingType type, bool in_body, std::size_t off, std::size_t len, double entropy) {
    if (a.findings.size() < kMaxFindings) {
        a.findings.push_back(Finding{type, in_body, off, len, entropy});
    }
}

bool overlaps_body_finding(const Analysis& a, std::size_t off, std::size_t len) {
    for (const Finding& f : a.findings) {
        if (f.in_body && off < f.off + f.len && f.off < off + len) {
            return true;
        }
    }
    return false;
}

std::vector<HeaderView> parse_header_block(std::string_view block) {
    std::vector<HeaderView> out;
    std::size_t pos = 0;
    while (pos < block.size()) {
        std::size_t eol = block.find('\n', pos);
        if (eol == std::string_view::npos) {
            eol = block.size();
        }
        const std::string_view line = block.substr(pos, eol - pos);
        const std::size_t line_off = pos;
        pos = eol + 1;
        if (line.size() < 3 || line[1] != ' ') {
            continue;
        }
        bool request = false;
        if (line[0] == '>') {
            request = true;
        } else if (line[0] != '<') {
            continue;
        }
        const std::string_view rest = line.substr(2);
        const std::size_t colon = rest.find(':', rest[0] == ':' ? 1 : 0);
        if (colon == std::string_view::npos || colon == 0) {
            continue;
        }
        const std::string_view name = trim(rest.substr(0, colon));
        std::size_t vstart = colon + 1;
        while (vstart < rest.size() && (rest[vstart] == ' ' || rest[vstart] == '\t')) {
            ++vstart;
        }
        std::string_view value = rest.substr(vstart);
        while (!value.empty() && is_space(value.back())) {
            value.remove_suffix(1);
        }
        out.push_back(HeaderView{request, name, value, line_off + 2 + vstart});
    }
    return out;
}

void consider_credential(Analysis& a, std::string_view token, std::size_t off) {
    if (token.empty()) {
        return;
    }
    const double h = entropy_sv(token);
    a.entropy_score = std::max(a.entropy_score, h);
    if (token.size() >= kMinSecretLen && h > kSecretEntropy) {
        add_finding(a, FindingType::HighEntropyCredential, false, off, token.size(), h);
    }
}

void consider_cookie_pair(Analysis& a, std::string_view pair, std::size_t pair_off) {
    const std::size_t eq = pair.find('=');
    if (eq == std::string_view::npos) {
        return;
    }
    std::string_view value = pair.substr(eq + 1);
    std::size_t off = pair_off + eq + 1;
    const std::size_t lead = leading_space(value);
    value.remove_prefix(lead);
    off += lead;
    value = trim(value);
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
        off += 1;
    }
    consider_credential(a, value, off);
}

void analyze_credentials(Analysis& a, const std::vector<HeaderView>& headers) {
    for (const HeaderView& h : headers) {
        if (h.request && (iequals(h.name, "authorization") || iequals(h.name, "proxy-authorization"))) {
            std::size_t start = 0;
            const std::size_t sp = h.value.find(' ');
            if (sp != std::string_view::npos) {
                start = sp;
                while (start < h.value.size() && h.value[start] == ' ') {
                    ++start;
                }
            }
            consider_credential(a, h.value.substr(start), h.value_off + start);
        } else if (h.request && iequals(h.name, "cookie")) {
            std::size_t p = 0;
            while (p <= h.value.size()) {
                std::size_t semi = h.value.find(';', p);
                if (semi == std::string_view::npos) {
                    semi = h.value.size();
                }
                consider_cookie_pair(a, h.value.substr(p, semi - p), h.value_off + p);
                p = semi + 1;
            }
        } else if (!h.request && iequals(h.name, "set-cookie")) {
            const std::size_t semi = h.value.find(';');
            consider_cookie_pair(a, h.value.substr(0, semi), h.value_off);
        }
    }
}

std::size_t find_string_end(std::string_view s, std::size_t start) {
    for (std::size_t i = start; i < s.size(); ++i) {
        if (s[i] == '\\') {
            ++i;
            continue;
        }
        if (s[i] == '"') {
            return i;
        }
    }
    return std::string_view::npos;
}

bool is_sensitive_key(std::string_view key) {
    for (std::string_view k : kSensitiveKeys) {
        if (icontains(key, k)) {
            return true;
        }
    }
    return false;
}

std::size_t skip_space(std::string_view s, std::size_t i) {
    while (i < s.size() && is_space(s[i])) {
        ++i;
    }
    return i;
}

void analyze_json_fields(Analysis& a, std::string_view body) {
    std::size_t i = 0;
    while (i < body.size()) {
        if (body[i] != '"') {
            ++i;
            continue;
        }
        const std::size_t kend = find_string_end(body, i + 1);
        if (kend == std::string_view::npos) {
            return;
        }
        const std::string_view key = body.substr(i + 1, kend - i - 1);
        std::size_t j = skip_space(body, kend + 1);
        if (j < body.size() && body[j] == ':' && key.size() <= kMaxJsonKeyLen && is_sensitive_key(key)) {
            j = skip_space(body, j + 1);
            if (j < body.size() && body[j] == '"') {
                const std::size_t vend = find_string_end(body, j + 1);
                if (vend == std::string_view::npos) {
                    return;
                }
                const std::string_view value = body.substr(j + 1, vend - j - 1);
                a.entropy_score = std::max(a.entropy_score, entropy_sv(value));
                i = vend + 1;
                continue;
            }
        }
        i = kend + 1;
    }
}

template <typename Pred>
std::size_t run_length(std::string_view s, std::size_t i, std::size_t cap, Pred pred) {
    std::size_t n = 0;
    while (i + n < s.size() && n < cap && pred(s[i + n])) {
        ++n;
    }
    return n;
}

bool has_digit(std::string_view s) {
    return std::any_of(s.begin(), s.end(), is_digit);
}

std::size_t match_jwt(std::string_view s, std::size_t i) {
    if ((i > 0 && is_b64url(s[i - 1])) || !at(s, i, "eyJ")) {
        return 0;
    }
    std::size_t p = i;
    const std::size_t seg1 = run_length(s, p, kMaxBody, is_b64url);
    if (seg1 < 10) {
        return 0;
    }
    p += seg1;
    if (p >= s.size() || s[p] != '.') {
        return 0;
    }
    ++p;
    const std::size_t seg2 = run_length(s, p, kMaxBody, is_b64url);
    if (seg2 < 10) {
        return 0;
    }
    p += seg2;
    if (p >= s.size() || s[p] != '.') {
        return 0;
    }
    ++p;
    const std::size_t seg3 = run_length(s, p, kMaxBody, is_b64url);
    if (seg3 < 16) {
        return 0;
    }
    return p + seg3 - i;
}

std::size_t match_aws(std::string_view s, std::size_t i) {
    if ((i > 0 && is_alnum(s[i - 1])) || !(at(s, i, "AKIA") || at(s, i, "ASIA"))) {
        return 0;
    }
    if (s.size() - i < 20) {
        return 0;
    }
    for (std::size_t k = 4; k < 20; ++k) {
        const char c = s[i + k];
        if (!(is_upper(c) || is_digit(c))) {
            return 0;
        }
    }
    if (i + 20 < s.size() && is_alnum(s[i + 20])) {
        return 0;
    }
    return 20;
}

std::size_t match_sk(std::string_view s, std::size_t i) {
    if (i > 0 && is_b64url(s[i - 1])) {
        return 0;
    }
    std::size_t prefix = 0;
    if (at(s, i, "sk_live_") || at(s, i, "sk_test_")) {
        prefix = 8;
    } else if (at(s, i, "sk-")) {
        prefix = 3;
    } else {
        return 0;
    }
    const std::size_t k = run_length(s, i + prefix, kMaxSecretLen, is_b64url);
    if (k < 20 || !has_digit(s.substr(i + prefix, k))) {
        return 0;
    }
    return prefix + k;
}

std::size_t match_prefixed(std::string_view s, std::size_t i, const std::string_view* prefixes, std::size_t count,
                           std::size_t min_tail, bool (*tail_pred)(char)) {
    if (i > 0 && is_b64url(s[i - 1])) {
        return 0;
    }
    for (std::size_t p = 0; p < count; ++p) {
        if (at(s, i, prefixes[p])) {
            const std::size_t plen = prefixes[p].size();
            const std::size_t k = run_length(s, i + plen, kMaxSecretLen, tail_pred);
            return k >= min_tail ? plen + k : 0;
        }
    }
    return 0;
}

bool is_slack_tail(char c) {
    return is_alnum(c) || c == '-';
}

bool is_alnum_fn(char c) {
    return is_alnum(c);
}

std::size_t match_github(std::string_view s, std::size_t i) {
    return match_prefixed(s, i, kGithubPrefixes.data(), kGithubPrefixes.size(), 36, is_alnum_fn);
}

std::size_t match_slack(std::string_view s, std::size_t i) {
    return match_prefixed(s, i, kSlackPrefixes.data(), kSlackPrefixes.size(), 10, is_slack_tail);
}

std::size_t match_pem(std::string_view s, std::size_t i) {
    if (!at(s, i, "-----BEGIN")) {
        return 0;
    }
    const std::string_view window = s.substr(i, std::min(kPemWindow, s.size() - i));
    const std::size_t marker = window.find("PRIVATE KEY-----");
    if (marker == std::string_view::npos) {
        return 0;
    }
    if (window.substr(0, marker).find('\n') != std::string_view::npos) {
        return 0;
    }
    return marker + std::string_view("PRIVATE KEY-----").size();
}

std::size_t match_db_uri(std::string_view s, std::size_t i) {
    if (i > 0 && (is_alnum(s[i - 1]) || s[i - 1] == '+')) {
        return 0;
    }
    std::size_t scheme_len = 0;
    for (std::string_view scheme : kDbSchemes) {
        if (iat(s, i, scheme)) {
            scheme_len = scheme.size();
            break;
        }
    }
    if (scheme_len == 0) {
        return 0;
    }
    const std::size_t start = i + scheme_len;
    const std::size_t limit = std::min(s.size(), start + kMaxUserinfoLen);
    std::size_t at_pos = std::string_view::npos;
    std::size_t colon = std::string_view::npos;
    for (std::size_t q = start; q < limit; ++q) {
        const char c = s[q];
        if (c == '@') {
            at_pos = q;
            break;
        }
        if (is_uri_stop(c) || c == '/') {
            break;
        }
        if (c == ':' && colon == std::string_view::npos) {
            colon = q;
        }
    }
    if (at_pos == std::string_view::npos || colon == std::string_view::npos || colon + 1 >= at_pos) {
        return 0;
    }
    std::size_t end = at_pos + 1;
    while (end < s.size() && end - i < kMaxUriLen && !is_uri_stop(s[end])) {
        ++end;
    }
    return end - i;
}

void scan_patterns(Analysis& a, std::string_view body) {
    std::size_t i = 0;
    while (i < body.size()) {
        FindingType type = FindingType::Jwt;
        std::size_t len = match_jwt(body, i);
        if (len == 0) {
            type = FindingType::AwsAccessKey;
            len = match_aws(body, i);
        }
        if (len == 0) {
            type = FindingType::ApiKeySk;
            len = match_sk(body, i);
        }
        if (len == 0) {
            type = FindingType::GithubToken;
            len = match_github(body, i);
        }
        if (len == 0) {
            type = FindingType::SlackToken;
            len = match_slack(body, i);
        }
        if (len == 0) {
            type = FindingType::PrivateKeyPem;
            len = match_pem(body, i);
        }
        if (len == 0) {
            type = FindingType::DbCredentialUri;
            len = match_db_uri(body, i);
        }
        if (len == 0) {
            ++i;
            continue;
        }
        const double h = entropy_sv(body.substr(i, len));
        a.entropy_score = std::max(a.entropy_score, h);
        a.secret_leak = 1;
        add_finding(a, type, true, i, len, h);
        i += len;
    }
}

void scan_tokens(Analysis& a, std::string_view body) {
    std::size_t i = 0;
    while (i < body.size()) {
        if (!is_token_char(body[i])) {
            ++i;
            continue;
        }
        std::size_t j = i;
        bool upper = false;
        bool lower = false;
        bool digit = false;
        while (j < body.size() && is_token_char(body[j])) {
            upper = upper || is_upper(body[j]);
            lower = lower || is_lower(body[j]);
            digit = digit || is_digit(body[j]);
            ++j;
        }
        const std::size_t len = j - i;
        if (len >= kMinSecretLen && len <= kMaxSecretLen && upper && lower && digit) {
            const double h = entropy_sv(body.substr(i, len));
            a.entropy_score = std::max(a.entropy_score, h);
            if (h > kSecretEntropy && !overlaps_body_finding(a, i, len)) {
                a.secret_leak = 1;
                add_finding(a, FindingType::HighEntropyString, true, i, len, h);
            }
        }
        i = j;
    }
}

bool cacheable_method(std::string_view method) {
    return method.empty() || iequals(method, "GET") || iequals(method, "HEAD");
}

bool static_extension(std::string_view path) {
    const std::size_t cut = path.find_first_of("?#");
    if (cut != std::string_view::npos) {
        path = path.substr(0, cut);
    }
    const std::size_t slash = path.rfind('/');
    const std::string_view segment = slash == std::string_view::npos ? path : path.substr(slash + 1);
    std::string decoded;
    decoded.reserve(segment.size());
    for (std::size_t k = 0; k < segment.size(); ++k) {
        if (segment[k] == '%' && k + 2 < segment.size() && segment[k + 1] == '2' && ascii_lower(segment[k + 2]) == 'e') {
            decoded.push_back('.');
            k += 2;
        } else {
            decoded.push_back(ascii_lower(segment[k]));
        }
    }
    for (std::string_view ext : kStaticExtensions) {
        if (decoded.size() > ext.size() && ends_with(decoded, ext)) {
            return true;
        }
    }
    return false;
}

bool has_directive(std::string_view value, std::string_view directive) {
    std::size_t p = 0;
    while (p <= value.size()) {
        std::size_t comma = value.find(',', p);
        if (comma == std::string_view::npos) {
            comma = value.size();
        }
        std::string_view item = trim(value.substr(p, comma - p));
        const std::size_t eq = item.find('=');
        if (eq != std::string_view::npos) {
            item = trim(item.substr(0, eq));
        }
        if (iequals(item, directive)) {
            return true;
        }
        p = comma + 1;
    }
    return false;
}

bool dynamic_content_type(std::string_view value) {
    const std::string_view v = trim(value);
    return iat(v, 0, "text/html") || iat(v, 0, "application/json");
}

void detect_cache_deception(Analysis& a, std::string_view method, std::string_view path,
                            const std::vector<HeaderView>& headers) {
    if (!cacheable_method(method) || !static_extension(path)) {
        return;
    }
    bool cacheable = true;
    bool set_cookie = false;
    bool dynamic_type = false;
    bool request_credentials = false;
    for (const HeaderView& h : headers) {
        if (h.request) {
            if (iequals(h.name, "cookie") || iequals(h.name, "authorization")) {
                request_credentials = true;
            }
            continue;
        }
        if (iequals(h.name, "cache-control") && (has_directive(h.value, "no-store") || has_directive(h.value, "private"))) {
            cacheable = false;
        } else if (iequals(h.name, "set-cookie")) {
            set_cookie = true;
        } else if (iequals(h.name, "content-type") && dynamic_content_type(h.value)) {
            dynamic_type = true;
        }
    }
    if (cacheable && (set_cookie || (dynamic_type && request_credentials))) {
        a.cache_deception = 1;
        add_finding(a, FindingType::WebCacheDeception, false, 0, 0, 0.0);
    }
}

void detect_insecure_cookies(Analysis& a, const std::vector<HeaderView>& headers) {
    for (const HeaderView& h : headers) {
        if (h.request || !iequals(h.name, "set-cookie")) {
            continue;
        }
        const std::size_t semi = h.value.find(';');
        const std::string_view pair = h.value.substr(0, semi);
        bool http_only = false;
        bool secure = false;
        bool same_site = false;
        if (semi != std::string_view::npos) {
            std::size_t p = semi + 1;
            while (p <= h.value.size()) {
                std::size_t next = h.value.find(';', p);
                if (next == std::string_view::npos) {
                    next = h.value.size();
                }
                std::string_view attr = trim(h.value.substr(p, next - p));
                const std::size_t eq = attr.find('=');
                if (eq != std::string_view::npos) {
                    attr = trim(attr.substr(0, eq));
                }
                http_only = http_only || iequals(attr, "httponly");
                secure = secure || iequals(attr, "secure");
                same_site = same_site || iequals(attr, "samesite");
                p = next + 1;
            }
        }
        if (!(http_only && secure && same_site)) {
            const std::size_t eq = pair.find('=');
            const double h_value = eq == std::string_view::npos ? 0.0 : entropy_sv(trim(pair.substr(eq + 1)));
            add_finding(a, FindingType::InsecureCookie, false, h.value_off, pair.size(), h_value);
        }
    }
}

long long fixed4(double x) {
    if (!(x > 0.0)) {
        return 0;
    }
    return std::llround(x * 10000.0);
}

void append_uint(std::string& out, unsigned long long v) {
    char buf[24];
    const std::to_chars_result r = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, static_cast<std::size_t>(r.ptr - buf));
}

void append_fixed4(std::string& out, double x) {
    const unsigned long long q = static_cast<unsigned long long>(fixed4(x));
    append_uint(out, q / 10000);
    out.push_back('.');
    const unsigned long long frac = q % 10000;
    out.push_back(static_cast<char>('0' + frac / 1000));
    out.push_back(static_cast<char>('0' + (frac / 100) % 10));
    out.push_back(static_cast<char>('0' + (frac / 10) % 10));
    out.push_back(static_cast<char>('0' + frac % 10));
}

std::string build_json(const Analysis& a) {
    const double normalized = std::min(a.entropy_score / kEntropyCeiling, 1.0);
    const int flag = std::max(a.cache_deception, a.secret_leak);
    const double score = std::min(kEntropyWeight * normalized + kFlagWeight * static_cast<double>(flag), 1.0);

    std::string out;
    out.reserve(256 + a.findings.size() * 96);
    out.append("{\"entropy_score\":");
    append_fixed4(out, a.entropy_score);
    out.append(",\"normalized_entropy\":");
    append_fixed4(out, normalized);
    out.append(",\"cache_deception_flag\":");
    append_uint(out, static_cast<unsigned long long>(a.cache_deception));
    out.append(",\"secret_leak_flag\":");
    append_uint(out, static_cast<unsigned long long>(a.secret_leak));
    out.append(",\"anomaly_score\":");
    append_fixed4(out, score);
    out.append(",\"findings\":[");
    for (std::size_t i = 0; i < a.findings.size(); ++i) {
        const Finding& f = a.findings[i];
        if (i != 0) {
            out.push_back(',');
        }
        out.append("{\"type\":\"");
        out.append(kFindingNames[static_cast<std::size_t>(f.type)]);
        out.append(f.in_body ? "\",\"loc\":\"body\",\"off\":" : "\",\"loc\":\"header\",\"off\":");
        append_uint(out, f.off);
        out.append(",\"len\":");
        append_uint(out, f.len);
        out.append(",\"entropy\":");
        append_fixed4(out, f.entropy);
        out.push_back('}');
    }
    out.append("],\"engine_version\":\"");
    out.append(kVersion);
    out.append("\",\"error\":null}");
    return out;
}

char* copy_out(const char* data, std::size_t n) {
    char* buf = static_cast<char*>(std::malloc(n + 1));
    if (buf == nullptr) {
        return nullptr;
    }
    std::memcpy(buf, data, n);
    buf[n] = '\0';
    return buf;
}

}

extern "C" {

double CalculateShannonEntropy(const char* data, int length) {
    try {
        if (data == nullptr || length <= 0) {
            return 0.0;
        }
        return entropy_bytes(reinterpret_cast<const unsigned char*>(data), static_cast<std::size_t>(length));
    } catch (...) {
        return 0.0;
    }
}

char* InspectHTTPPayload(const char* method, const char* path, const char* headers, const char* body) {
    try {
        const std::string_view m = bounded_view(method, kMaxMethod);
        const std::string_view p = bounded_view(path, kMaxPath);
        const std::string_view h = bounded_view(headers, kMaxHeaders);
        const std::string_view b = bounded_view(body, kMaxBody);

        Analysis a;
        a.findings.reserve(16);
        const std::vector<HeaderView> parsed = parse_header_block(h);
        analyze_credentials(a, parsed);
        detect_cache_deception(a, m, p, parsed);
        detect_insecure_cookies(a, parsed);
        analyze_json_fields(a, b);
        scan_patterns(a, b);
        scan_tokens(a, b);

        const std::string json = build_json(a);
        return copy_out(json.data(), json.size());
    } catch (...) {
        return copy_out(kErrorJson, sizeof(kErrorJson) - 1);
    }
}

void FreeInspectionResult(char* ptr) {
    try {
        std::free(ptr);
    } catch (...) {
    }
}

const char* NetChimeraEngineVersion(void) {
    try {
        return kVersion;
    } catch (...) {
        return kVersion;
    }
}

}
