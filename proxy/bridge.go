package main

/*
#cgo CFLAGS: -I${SRCDIR}/../engine
#cgo LDFLAGS: -L${SRCDIR}/../engine/build -linspector -lm
#cgo darwin LDFLAGS: -lc++
#cgo linux LDFLAGS: -lstdc++
#include <stdlib.h>
#include "inspector.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

// Engine input bounds. They mirror the limits enforced inside inspector.cpp.
const (
	maxMethodLen  = 16
	maxPathLen    = 8192
	maxHeadersLen = 65536
	maxBodyLen    = 65536
)

var errEngineNil = errors.New("engine returned a null result")

type Finding struct {
	Type    string  `json:"type"`
	Loc     string  `json:"loc"`
	Off     int     `json:"off"`
	Len     int     `json:"len"`
	Entropy float64 `json:"entropy"`
}

type InspectionResult struct {
	EntropyScore       float64   `json:"entropy_score"`
	NormalizedEntropy  float64   `json:"normalized_entropy"`
	CacheDeceptionFlag int       `json:"cache_deception_flag"`
	SecretLeakFlag     int       `json:"secret_leak_flag"`
	AnomalyScore       float64   `json:"anomaly_score"`
	Findings           []Finding `json:"findings"`
	EngineVersion      string    `json:"engine_version"`
	Error              *string   `json:"error"`

	// EngineMicros is the wall time of the CGO call, measured by the bridge.
	EngineMicros float64 `json:"-"`
}

type EngineStats struct {
	Calls      uint64
	Errors     uint64
	MeanMicros float64
}

// engineCounters is written by every inspection worker and read by the status ticker.
var engineCounters struct {
	calls      atomic.Uint64
	errors     atomic.Uint64
	totalNanos atomic.Uint64
}

// Inspect runs one transaction through the C++ engine.
//
// Memory contract: every C.CString is released by its own defer; the engine
// result is copied into Go memory with C.GoString and released exactly once by
// the deferred FreeInspectionResult. No C pointer outlives this function and no
// Go pointer is passed to C.
func Inspect(method, path, headerBlock string, body []byte) (InspectionResult, error) {
	cMethod := C.CString(engineInput(method, maxMethodLen))
	defer C.free(unsafe.Pointer(cMethod))
	cPath := C.CString(engineInput(path, maxPathLen))
	defer C.free(unsafe.Pointer(cPath))
	cHeaders := C.CString(engineInput(headerBlock, maxHeadersLen))
	defer C.free(unsafe.Pointer(cHeaders))
	cBody := C.CString(engineInputBytes(body, maxBodyLen))
	defer C.free(unsafe.Pointer(cBody))

	start := time.Now()
	res := C.InspectHTTPPayload(cMethod, cPath, cHeaders, cBody)
	elapsed := time.Since(start)
	engineCounters.calls.Add(1)
	engineCounters.totalNanos.Add(uint64(elapsed.Nanoseconds()))

	if res == nil {
		engineCounters.errors.Add(1)
		return InspectionResult{}, errEngineNil
	}
	defer C.FreeInspectionResult(res)
	raw := C.GoString(res)

	var out InspectionResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		engineCounters.errors.Add(1)
		return InspectionResult{}, fmt.Errorf("decode engine result: %w", err)
	}
	if out.Error != nil {
		engineCounters.errors.Add(1)
		return InspectionResult{}, fmt.Errorf("engine error: %s", *out.Error)
	}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	out.EngineMicros = float64(elapsed.Nanoseconds()) / 1e3
	return out, nil
}

// Entropy computes Shannon entropy in the engine. Inputs are capped at the body bound.
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	if len(b) > maxBodyLen {
		b = b[:maxBodyLen]
	}
	p := C.CBytes(b)
	defer C.free(p)
	return float64(C.CalculateShannonEntropy((*C.char)(p), C.int(len(b))))
}

// EngineVersion returns the engine's static version string. It must not be freed.
func EngineVersion() string {
	return C.GoString(C.NetChimeraEngineVersion())
}

// ProbeEngine verifies the library is linked and computes correctly.
func ProbeEngine() (string, error) {
	version := EngineVersion()
	if version == "" {
		return "", errors.New("engine reported an empty version")
	}
	if h := Entropy([]byte("ab")); math.Abs(h-1) > 1e-9 {
		return version, fmt.Errorf("engine self-test failed: H(\"ab\") = %v, want 1", h)
	}
	return version, nil
}

func ReadEngineStats() EngineStats {
	calls := engineCounters.calls.Load()
	s := EngineStats{Calls: calls, Errors: engineCounters.errors.Load()}
	if calls > 0 {
		s.MeanMicros = float64(engineCounters.totalNanos.Load()) / float64(calls) / 1e3
	}
	return s
}

// engineInput truncates to the engine bound and replaces NUL bytes with spaces.
// Byte offsets are preserved so engine findings still index the original text.
func engineInput(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", " ")
	}
	return s
}

func engineInputBytes(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	return engineInput(string(b), max)
}

// BuildHeaderBlock serializes headers in the engine's format: "> " for request
// headers, "< " for response headers, and a "< :status:" pseudo-header. Names
// are sorted so finding offsets are reproducible for the same transaction.
func BuildHeaderBlock(reqHeaders, respHeaders http.Header, status int) string {
	var b strings.Builder
	writeHeaderLines(&b, "> ", reqHeaders)
	if status > 0 {
		b.WriteString("< :status: ")
		b.WriteString(strconv.Itoa(status))
		b.WriteByte('\n')
	}
	writeHeaderLines(&b, "< ", respHeaders)
	return b.String()
}

var headerLineCleaner = strings.NewReplacer("\r", " ", "\n", " ")

func writeHeaderLines(b *strings.Builder, prefix string, h http.Header) {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range h[name] {
			b.WriteString(prefix)
			b.WriteString(headerLineCleaner.Replace(name))
			b.WriteString(": ")
			b.WriteString(headerLineCleaner.Replace(v))
			b.WriteByte('\n')
		}
	}
}
