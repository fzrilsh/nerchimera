"use client";

// EntropyBar renders Shannon entropy on a 0..8 bits/char scale with a marker
// at the 4.3 bit secret threshold.
export function EntropyBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value / 8)) * 100;
  const markerPct = (4.3 / 8) * 100;
  const hot = value > 4.3;
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-2 w-24 rounded-sm bg-grid overflow-hidden">
        <div
          className={hot ? "h-full bg-crimson" : "h-full bg-neon"}
          style={{ width: `${pct}%` }}
        />
        <div
          className="absolute top-0 h-full w-px bg-amber/80"
          style={{ left: `${markerPct}%` }}
          title="4.3 bits/char secret threshold"
        />
      </div>
      <span className="tabular-nums text-[11px] text-dim w-9 text-right">
        {value.toFixed(2)}
      </span>
    </div>
  );
}
