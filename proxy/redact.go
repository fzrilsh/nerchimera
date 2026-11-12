package main

import (
	"sort"
	"strconv"
	"strings"
)

// redactKeep is how many leading bytes of a secret survive redaction.
const redactKeep = 4

// credentialHeaders are always redacted, whether or not the engine flagged them.
var credentialHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
}

type span struct {
	off, len int
	kind     string
}

// Redact returns copies of the header block and body with every finding span
// and every credential header value masked as "<first 4>…[REDACTED:<KIND>:<len>]".
// The inputs are not modified.
func Redact(headerBlock string, body []byte, findings []Finding) (string, []byte) {
	var hs, bs []span
	for _, f := range findings {
		if f.Len <= 0 || f.Off < 0 {
			continue
		}
		s := span{off: f.Off, len: f.Len, kind: f.Type}
		if f.Loc == "body" {
			bs = append(bs, s)
		} else {
			hs = append(hs, s)
		}
	}
	hs = append(hs, credentialSpans(headerBlock)...)
	return string(applySpans([]byte(headerBlock), hs)), applySpans(body, bs)
}

// credentialSpans locates credential header values in a header block.
// Authorization-style headers keep their scheme ("Bearer ").
func credentialSpans(block string) []span {
	var out []span
	pos := 0
	for pos < len(block) {
		end := strings.IndexByte(block[pos:], '\n')
		if end < 0 {
			end = len(block) - pos
		}
		line := block[pos : pos+end]
		lineOff := pos
		pos += end + 1
		if len(line) < 3 || (line[0] != '>' && line[0] != '<') || line[1] != ' ' {
			continue
		}
		colon := strings.IndexByte(line[2:], ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[2 : 2+colon]))
		if !credentialHeaders[name] {
			continue
		}
		vstart := 2 + colon + 1
		for vstart < len(line) && line[vstart] == ' ' {
			vstart++
		}
		if strings.HasSuffix(name, "authorization") {
			if sp := strings.IndexByte(line[vstart:], ' '); sp > 0 {
				vstart += sp + 1
			}
		}
		if vstart < len(line) {
			out = append(out, span{off: lineOff + vstart, len: len(line) - vstart, kind: "CREDENTIAL"})
		}
	}
	return out
}

// applySpans clamps, merges overlapping spans, and rewrites from the highest
// offset down so that earlier offsets remain valid.
func applySpans(src []byte, spans []span) []byte {
	out := append([]byte(nil), src...)
	if len(spans) == 0 {
		return out
	}
	valid := spans[:0:0]
	for _, s := range spans {
		if s.off >= len(src) {
			continue
		}
		if s.off+s.len > len(src) {
			s.len = len(src) - s.off
		}
		if s.len > 0 {
			valid = append(valid, s)
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].off < valid[j].off })

	var merged []span
	for _, s := range valid {
		if n := len(merged); n > 0 && s.off <= merged[n-1].off+merged[n-1].len {
			last := &merged[n-1]
			if end := s.off + s.len; end > last.off+last.len {
				last.len = end - last.off
			}
			continue
		}
		merged = append(merged, s)
	}

	for i := len(merged) - 1; i >= 0; i-- {
		s := merged[i]
		keep := min(redactKeep, s.len)
		mask := make([]byte, 0, keep+48)
		mask = append(mask, out[s.off:s.off+keep]...)
		mask = append(mask, "…[REDACTED:"...)
		mask = append(mask, s.kind...)
		mask = append(mask, ':')
		mask = strconv.AppendInt(mask, int64(s.len), 10)
		mask = append(mask, ']')
		out = append(out[:s.off], append(mask, out[s.off+s.len:]...)...)
	}
	return out
}
