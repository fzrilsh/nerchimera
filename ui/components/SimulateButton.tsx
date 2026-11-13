"use client";

import { useEffect, useState } from "react";
import { Zap } from "lucide-react";
import { triggerSimulate } from "@/lib/ws";

export function SimulateButton() {
  const [cooldown, setCooldown] = useState(0);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  async function run() {
    if (busy || cooldown > 0) return;
    setBusy(true);
    setNote(null);
    const res = await triggerSimulate();
    setBusy(false);
    if (res.status === 202) {
      setCooldown(5);
      setNote(`launched ${res.scenarios ?? ""} scenarios`);
    } else if (res.status === 429) {
      setCooldown(res.retryAfter ?? 5);
      setNote("rate limited");
    } else {
      setNote("proxy unreachable");
    }
    setTimeout(() => setNote(null), 2500);
  }

  const disabled = busy || cooldown > 0;
  return (
    <div className="flex items-center gap-2">
      <button
        onClick={run}
        disabled={disabled}
        className={`inline-flex items-center gap-1.5 rounded-sm border px-2.5 py-1 text-[12px] uppercase tracking-wider transition ${
          disabled
            ? "border-grid text-dim cursor-not-allowed"
            : "border-crimson/60 text-crimson bg-crimson/10 hover:bg-crimson/20 shadow-crimson"
        }`}
        title="Replay the fixed attack scenarios through the proxy"
      >
        <Zap size={13} className={busy ? "animate-pulseCrit" : ""} />
        {cooldown > 0 ? `simulate (${cooldown}s)` : "simulate attack"}
      </button>
      {note && <span className="text-[11px] text-dim">{note}</span>}
    </div>
  );
}
