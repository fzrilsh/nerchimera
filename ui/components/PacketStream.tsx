"use client";

import { ListFilter } from "lucide-react";
import { useStore, store } from "@/lib/store";
import type { TransactionEvent } from "@/lib/types";
import { EntropyBar } from "./EntropyBar";
import { AnomalyBadge } from "./AnomalyBadge";

function statusColor(code: number) {
  if (code >= 500) return "text-crimson";
  if (code >= 400) return "text-amber";
  if (code >= 300) return "text-sky-300";
  return "text-neon";
}

function Row({
  tx,
  threshold,
  selected,
}: {
  tx: TransactionEvent;
  threshold: number;
  selected: boolean;
}) {
  const flagged = tx.cache_deception_flag === 1 || tx.secret_leak_flag === 1;
  return (
    <button
      onClick={() => store.select(tx.id)}
      className={`grid w-full grid-cols-[auto_1fr_auto_auto_auto] items-center gap-2 border-b border-grid/60 px-3 py-1.5 text-left text-[12px] transition hover:bg-grid/40 ${
        selected ? "bg-grid/60" : flagged ? "bg-crimson/5" : ""
      }`}
    >
      <span className="w-10 font-semibold text-dim">{tx.method}</span>
      <span className="truncate font-medium text-[#c7d0dc]" title={tx.path}>
        {tx.path}
        {tx.classification && (
          <span className="ml-2 rounded-sm border border-crimson/40 px-1 text-[9px] uppercase tracking-wider text-crimson">
            {tx.classification.replace(/_/g, " ")}
          </span>
        )}
      </span>
      <span className={`w-8 text-right tabular-nums ${statusColor(tx.status)}`}>{tx.status}</span>
      <EntropyBar value={tx.entropy_score} />
      <AnomalyBadge tx={tx} threshold={threshold} />
    </button>
  );
}

export function PacketStream() {
  const transactions = useStore((s) => s.transactions);
  const threshold = useStore((s) => s.threshold);
  const selectedId = useStore((s) => s.selectedId);

  return (
    <section className="panel flex min-h-0 flex-col">
      <div className="panel-title justify-between">
        <span className="flex items-center gap-2">
          <ListFilter size={13} /> live packet stream
        </span>
        <span className="text-dim">{transactions.length} tx</span>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {transactions.length === 0 ? (
          <div className="p-4 text-[12px] text-dim">
            waiting for traffic… run the proxy and click “simulate attack”.
          </div>
        ) : (
          transactions.map((tx) => (
            <Row key={tx.id} tx={tx} threshold={threshold} selected={tx.id === selectedId} />
          ))
        )}
      </div>
    </section>
  );
}
