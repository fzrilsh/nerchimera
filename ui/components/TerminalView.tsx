"use client";

import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { useStore } from "@/lib/store";
import type { TelemetryLine } from "@/lib/store";
import type { TransactionEvent } from "@/lib/types";
import { decodeBase64, stripControls } from "@/lib/sanitize";
import { hexdump } from "@/lib/hexdump";

const C = {
  reset: "\x1b[0m",
  neon: "\x1b[38;2;0;255;157m",
  amber: "\x1b[38;2;255;184;0m",
  crimson: "\x1b[38;2;255;0;85m",
  dim: "\x1b[38;2;90;100;114m",
  sky: "\x1b[38;2;125;211;252m",
};

// levelColor maps a telemetry level to a UI-generated ANSI colour. Only colours
// the UI creates are ever written; payload text is sanitised first.
function levelColor(level: string) {
  if (level === "error") return C.crimson;
  if (level === "warn") return C.amber;
  return C.neon;
}

export default function TerminalView() {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const lastTelemetryId = useRef<number>(-1);
  const lastSelected = useRef<string | null>(null);

  const selectedId = useStore((s) => s.selectedId);
  const tx = useStore((s) => (s.selectedId ? s.byId.get(s.selectedId) : undefined));
  const telemetry = useStore((s) => s.telemetry);

  useEffect(() => {
    if (!containerRef.current) return;
    const term = new Terminal({
      convertEol: true,
      fontSize: 12,
      fontFamily: "var(--font-mono), JetBrains Mono, monospace",
      theme: {
        background: "#0d0f14",
        foreground: "#c7d0dc",
        cursor: "#00ff9d",
        selectionBackground: "#1a1d24",
      },
      scrollback: 4000,
      disableStdin: true,
      cursorBlink: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    try {
      fit.fit();
    } catch {
      /* container not measured yet */
    }
    termRef.current = term;
    fitRef.current = fit;

    term.writeln(`${C.neon}NetChimera CGO telemetry console${C.reset}`);
    term.writeln(`${C.dim}select a packet to inspect its hex dump · engine logs stream below${C.reset}`);

    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        /* ignore */
      }
    });
    ro.observe(containerRef.current);

    return () => {
      ro.disconnect();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, []);

  // Render the hex dump when the selection changes.
  useEffect(() => {
    const term = termRef.current;
    if (!term || !tx || selectedId === lastSelected.current) return;
    lastSelected.current = selectedId ?? null;
    writeInspection(term, tx);
  }, [selectedId, tx]);

  // Stream new telemetry lines.
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    for (const line of telemetry) {
      if (line.id <= lastTelemetryId.current) continue;
      lastTelemetryId.current = line.id;
      writeTelemetry(term, line);
    }
  }, [telemetry]);

  return <div ref={containerRef} className="h-full w-full" />;
}

function writeInspection(term: Terminal, tx: TransactionEvent) {
  term.writeln("");
  term.writeln(`${C.amber}── packet ${tx.id} ────────────────────────────${C.reset}`);
  term.writeln(`${C.sky}${stripControls(tx.method)} ${stripControls(tx.path)}${C.reset} ${C.dim}→ ${tx.status}${C.reset}`);
  if (tx.classification) {
    term.writeln(`${C.crimson}classification: ${stripControls(tx.classification)}${C.reset}`);
  }
  term.writeln(
    `${C.dim}H=${tx.entropy_score.toFixed(2)} wcd=${tx.cache_deception_flag} leak=${tx.secret_leak_flag} S=${tx.anomaly_score.toFixed(4)} engine=${tx.engine_us}µs${C.reset}`,
  );

  term.writeln(`${C.neon}── headers ──${C.reset}`);
  const headerBytes = new TextEncoder().encode(tx.header_block);
  for (const row of hexdump(headerBytes, 2048)) {
    term.writeln(stripControls(row));
  }

  const body = decodeBase64(tx.body_preview_b64);
  if (body.length > 0) {
    term.writeln(`${C.neon}── body preview (${body.length} bytes${tx.truncated ? ", truncated" : ""}) ──${C.reset}`);
    for (const row of hexdump(body, 2048)) {
      term.writeln(stripControls(row));
    }
  }
  term.writeln("");
}

function writeTelemetry(term: Terminal, line: TelemetryLine) {
  const color = levelColor(line.level);
  const src = stripControls(line.source).padEnd(10).slice(0, 10);
  const msg = stripControls(line.msg);
  term.writeln(`${C.dim}[${src}]${C.reset} ${color}${msg}${C.reset}`);
}
