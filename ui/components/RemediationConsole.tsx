"use client";

import { useState } from "react";
import { BrainCircuit, Check, Copy, ShieldAlert } from "lucide-react";
import { useStore } from "@/lib/store";
import type { Advisory, Severity } from "@/lib/types";
import { stripControls } from "@/lib/sanitize";
import { DiffView } from "./DiffView";

const severityClass: Record<Severity, string> = {
  low: "text-neon border-neon/40",
  medium: "text-amber border-amber/40",
  high: "text-amber border-amber/50",
  critical: "text-crimson border-crimson/50",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard denied */
    }
  }
  return (
    <button
      onClick={copy}
      className="inline-flex items-center gap-1 rounded-sm border border-grid px-2 py-0.5 text-[11px] text-dim hover:border-neon/40 hover:text-neon"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {copied ? "copied" : "copy patch"}
    </button>
  );
}

function Rule({ label, body }: { label: string; body: string }) {
  if (!body) return null;
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase tracking-[0.2em] text-dim">{label}</div>
      <pre className="overflow-x-auto whitespace-pre-wrap rounded-sm bg-void/60 p-2 text-[11px] text-[#9aa7b6]">
        {stripControls(body)}
      </pre>
    </div>
  );
}

function AdvisoryCard({ adv }: { adv: Advisory }) {
  return (
    <article className="border-b border-grid p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={`rounded-sm border px-1.5 py-0.5 text-[10px] uppercase tracking-wider ${severityClass[adv.severity] ?? severityClass.low}`}
          >
            {adv.severity}
          </span>
          <span className="text-[12px] font-semibold text-crimson">
            {stripControls(adv.classification).replace(/_/g, " ")}
          </span>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-dim">
          <span
            className={`rounded-sm border px-1 py-0.5 uppercase ${
              adv.source === "llm"
                ? "border-neon/40 text-neon"
                : adv.source === "fallback"
                  ? "border-amber/40 text-amber"
                  : "border-grid text-dim"
            }`}
          >
            {adv.source}
          </span>
          <span className="tabular-nums">{adv.duration_ms}ms</span>
        </div>
      </div>

      <div className="mb-1 text-[12px] text-[#c7d0dc]">{stripControls(adv.title)}</div>
      <div className="mb-3 text-[11px] text-dim">
        {stripControls(adv.method)} {stripControls(adv.path)} · {stripControls(adv.model)}
      </div>

      <div className="mb-3">
        <div className="mb-1 text-[10px] uppercase tracking-[0.2em] text-dim">root cause</div>
        <p className="text-[12px] leading-relaxed text-[#9aa7b6]">{stripControls(adv.root_cause)}</p>
      </div>

      <div className="mb-3">
        <div className="mb-1 flex items-center justify-between">
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.2em] text-dim">
            unified diff
            {!adv.diff_valid && (
              <span className="rounded-sm border border-amber/40 px-1 text-amber">unverified</span>
            )}
          </div>
          <CopyButton text={adv.diff} />
        </div>
        <div className="rounded-sm bg-void/60 p-2">
          <DiffView diff={adv.diff} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2">
        <Rule label="nginx rule" body={adv.nginx_rule} />
        <Rule label="cloudflare rule" body={adv.cloudflare_rule} />
      </div>
    </article>
  );
}

export function RemediationConsole() {
  const advisories = useStore((s) => s.advisories);
  const streaming = useStore((s) => s.streaming);
  const streamIds = Array.from(streaming.keys());

  return (
    <section className="panel flex min-h-0 flex-col">
      <div className="panel-title justify-between">
        <span className="flex items-center gap-2">
          <BrainCircuit size={13} /> autonomous ai remediation
        </span>
        <span className="text-dim">{advisories.length}</span>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {streamIds.map((id) => (
          <div key={id} className="border-b border-grid p-3">
            <div className="mb-1 flex items-center gap-2 text-[11px] text-amber">
              <ShieldAlert size={12} className="animate-pulseCrit" /> synthesizing advisory…
            </div>
            <pre className="max-h-40 overflow-y-auto whitespace-pre-wrap text-[11px] text-[#9aa7b6]">
              {stripControls(streaming.get(id) ?? "")}
            </pre>
          </div>
        ))}
        {advisories.length === 0 && streamIds.length === 0 ? (
          <div className="p-4 text-[12px] text-dim">
            no advisories yet. flagged anomalies are analyzed here with a ready-to-apply patch.
          </div>
        ) : (
          advisories.map((adv) => <AdvisoryCard key={adv.advisory_id} adv={adv} />)
        )}
      </div>
    </section>
  );
}
