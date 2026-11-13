"use client";

import { useEffect, useRef, useState } from "react";
import { Activity, BrainCircuit, Cpu, Layers, Radio, Wifi, WifiOff } from "lucide-react";
import { useStore } from "@/lib/store";
import { sendThreshold } from "@/lib/ws";
import { SimulateButton } from "./SimulateButton";

type Tone = "ok" | "warn" | "crit" | "idle";

const toneClass: Record<Tone, string> = {
  ok: "text-neon border-neon/40",
  warn: "text-amber border-amber/40",
  crit: "text-crimson border-crimson/50 animate-pulseCrit",
  idle: "text-dim border-grid",
};

function Badge({
  icon,
  label,
  value,
  tone,
  title,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: Tone;
  title?: string;
}) {
  return (
    <div
      title={title}
      className={`flex items-center gap-2 rounded-sm border bg-void/60 px-2.5 py-1 ${toneClass[tone]}`}
    >
      <span className="opacity-90">{icon}</span>
      <div className="flex flex-col leading-tight">
        <span className="text-[9px] uppercase tracking-[0.2em] text-dim">{label}</span>
        <span className="text-[12px] tabular-nums">{value}</span>
      </div>
    </div>
  );
}

export function TopBar() {
  const status = useStore((s) => s.status);
  const connection = useStore((s) => s.connection);
  const threshold = useStore((s) => s.threshold);

  const [local, setLocal] = useState(threshold);
  const dragging = useRef(false);
  useEffect(() => {
    if (!dragging.current) setLocal(threshold);
  }, [threshold]);

  const engine = status?.engine;
  const pool = status?.pool;
  const ai = status?.ai;

  const engineTone: Tone = !engine
    ? "idle"
    : engine.status === "online"
      ? "ok"
      : engine.status === "degraded"
        ? "warn"
        : "crit";
  const poolTone: Tone = !pool ? "idle" : pool.dropped > 0 ? "warn" : pool.load > 0.8 ? "warn" : "ok";
  const aiTone: Tone = !ai
    ? "idle"
    : ai.status === "error"
      ? "crit"
      : ai.status === "busy"
        ? "warn"
        : "ok";

  function commit(v: number) {
    dragging.current = false;
    sendThreshold(v);
  }

  return (
    <header className="flex flex-wrap items-center gap-3 border-b border-grid bg-panel px-4 py-2">
      <div className="flex items-center gap-2 pr-2">
        <Activity size={18} className="text-neon neon-text" />
        <div className="leading-none">
          <div className="text-[15px] font-semibold tracking-wider text-neon neon-text">
            NET<span className="text-crimson">CHIMERA</span>
          </div>
          <div className="text-[9px] uppercase tracking-[0.25em] text-dim">
            tactical http analysis
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Badge
          icon={<Cpu size={15} />}
          label="C++ engine"
          value={engine ? `${engine.status} · v${engine.version}` : "—"}
          tone={engineTone}
          title={engine ? `${engine.calls} calls, ${engine.errors} errors, mean ${engine.mean_us}µs` : undefined}
        />
        <Badge
          icon={<Layers size={15} />}
          label="go pool"
          value={pool ? `${pool.queue_len}/${pool.queue_cap} · ${pool.dropped} drop` : "—"}
          tone={poolTone}
          title={pool ? `${pool.workers} workers, load ${(pool.load * 100).toFixed(0)}%` : undefined}
        />
        <Badge
          icon={<BrainCircuit size={15} />}
          label="ai agent"
          value={ai ? `${ai.mode} · ${ai.status}` : "—"}
          tone={aiTone}
          title={ai ? `model ${ai.model || "mock"}, ${ai.processed} processed, ${ai.dropped} dropped` : undefined}
        />
        <Badge
          icon={connection === "open" ? <Wifi size={15} /> : <WifiOff size={15} />}
          label="ws link"
          value={connection}
          tone={connection === "open" ? "ok" : connection === "connecting" ? "warn" : "crit"}
        />
      </div>

      <div className="ml-auto flex items-center gap-4">
        <label className="flex items-center gap-2 text-[11px] text-dim">
          <Radio size={14} className="text-amber" />
          <span className="uppercase tracking-wider">threshold</span>
          <input
            type="range"
            min={0}
            max={1}
            step={0.01}
            value={local}
            onChange={(e) => {
              dragging.current = true;
              setLocal(parseFloat(e.target.value));
            }}
            onPointerUp={(e) => commit(parseFloat((e.target as HTMLInputElement).value))}
            onKeyUp={(e) => commit(parseFloat((e.target as HTMLInputElement).value))}
            className="h-1 w-32 cursor-pointer appearance-none rounded-full bg-grid accent-amber"
          />
          <span className="tabular-nums text-amber w-9 text-right">{local.toFixed(2)}</span>
        </label>
        <SimulateButton />
      </div>
    </header>
  );
}
