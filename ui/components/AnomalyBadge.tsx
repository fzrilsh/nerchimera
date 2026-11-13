"use client";

import type { TransactionEvent } from "@/lib/types";

// AnomalyBadge colors the score: green below 0.40, amber from 0.40 up to the
// threshold, crimson above the threshold or when any flag is set.
export function AnomalyBadge({ tx, threshold }: { tx: TransactionEvent; threshold: number }) {
  const flagged = tx.cache_deception_flag === 1 || tx.secret_leak_flag === 1;
  const s = tx.anomaly_score;
  let cls = "text-neon border-neon/40 bg-neon/5";
  let crit = false;
  if (flagged || s > threshold) {
    cls = "text-crimson border-crimson/50 bg-crimson/10";
    crit = true;
  } else if (s >= 0.4) {
    cls = "text-amber border-amber/40 bg-amber/5";
  }
  return (
    <span
      className={`inline-flex items-center justify-center rounded-sm border px-1.5 py-0.5 text-[11px] tabular-nums ${cls} ${
        crit ? "animate-pulseCrit" : ""
      }`}
    >
      {s.toFixed(2)}
    </span>
  );
}
