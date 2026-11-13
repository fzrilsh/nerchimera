"use client";

import dynamic from "next/dynamic";
import { TerminalSquare } from "lucide-react";

// Xterm touches the DOM and window, so it must never run during SSR.
const TerminalView = dynamic(() => import("./TerminalView"), {
  ssr: false,
  loading: () => <div className="p-4 text-[12px] text-dim">booting terminal…</div>,
});

export function Inspector() {
  return (
    <section className="panel flex min-h-0 flex-col">
      <div className="panel-title">
        <TerminalSquare size={13} /> packet inspector · cgo telemetry
      </div>
      <div className="min-h-0 flex-1 overflow-hidden bg-panel">
        <TerminalView />
      </div>
    </section>
  );
}
