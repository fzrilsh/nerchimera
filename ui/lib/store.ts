"use client";

import { useSyncExternalStore } from "react";
import type {
  Advisory,
  AIPatchStream,
  EngineTelemetry,
  Envelope,
  SystemStatus,
  TransactionEvent,
} from "./types";

export type ConnectionState = "connecting" | "open" | "closed";

const MAX_TX = 500;
const MAX_ADVISORIES = 100;
const MAX_TELEMETRY = 500;

export interface TelemetryLine extends EngineTelemetry {
  id: number;
  ts: number;
}

export interface State {
  transactions: TransactionEvent[];
  byId: Map<string, TransactionEvent>;
  selectedId: string | null;
  advisories: Advisory[];
  streaming: Map<string, string>;
  telemetry: TelemetryLine[];
  status: SystemStatus | null;
  threshold: number;
  connection: ConnectionState;
}

let state: State = {
  transactions: [],
  byId: new Map(),
  selectedId: null,
  advisories: [],
  streaming: new Map(),
  telemetry: [],
  status: null,
  threshold: 0.65,
  connection: "connecting",
};

const listeners = new Set<() => void>();
let telemetrySeq = 0;

function emit() {
  for (const l of listeners) l();
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function getSnapshot() {
  return state;
}

// Incoming envelopes are buffered and flushed once per animation frame so a
// burst of traffic triggers at most one render per frame.
let pending: Envelope[] = [];
let frameQueued = false;

function scheduleFlush() {
  if (frameQueued) return;
  frameQueued = true;
  const raf =
    typeof requestAnimationFrame !== "undefined"
      ? requestAnimationFrame
      : (cb: FrameRequestCallback) => setTimeout(() => cb(0), 16);
  raf(() => {
    frameQueued = false;
    flush();
  });
}

function flush() {
  if (pending.length === 0) return;
  const batch = pending;
  pending = [];

  let transactions = state.transactions;
  let byId = state.byId;
  let advisories = state.advisories;
  let streaming = state.streaming;
  let telemetry = state.telemetry;
  let status = state.status;
  let threshold = state.threshold;
  let selectedId = state.selectedId;

  let txDirty = false;
  let advDirty = false;
  let streamDirty = false;

  for (const env of batch) {
    switch (env.type) {
      case "TRANSACTION_EVENT": {
        const tx = env.data as TransactionEvent;
        if (!txDirty) {
          transactions = transactions.slice();
          byId = new Map(byId);
          txDirty = true;
        }
        transactions.unshift(tx);
        byId.set(tx.id, tx);
        if (transactions.length > MAX_TX) {
          const removed = transactions.splice(MAX_TX);
          for (const r of removed) byId.delete(r.id);
        }
        break;
      }
      case "AI_PATCH_STREAM": {
        const s = env.data as AIPatchStream;
        if (!streamDirty) {
          streaming = new Map(streaming);
          streamDirty = true;
        }
        streaming.set(s.advisory_id, (streaming.get(s.advisory_id) ?? "") + s.delta);
        break;
      }
      case "AI_PATCH_EVENT": {
        const adv = env.data as Advisory;
        if (!advDirty) {
          advisories = advisories.slice();
          advDirty = true;
        }
        advisories.unshift(adv);
        if (advisories.length > MAX_ADVISORIES) advisories.length = MAX_ADVISORIES;
        if (!streamDirty) {
          streaming = new Map(streaming);
          streamDirty = true;
        }
        streaming.delete(adv.advisory_id);
        break;
      }
      case "ENGINE_TELEMETRY": {
        const t = env.data as EngineTelemetry;
        telemetry = telemetry.slice();
        telemetry.push({ ...t, id: telemetrySeq++, ts: env.ts });
        if (telemetry.length > MAX_TELEMETRY) telemetry.splice(0, telemetry.length - MAX_TELEMETRY);
        break;
      }
      case "SYSTEM_STATUS": {
        status = env.data as SystemStatus;
        threshold = status.threshold;
        break;
      }
      case "CONFIG_UPDATED": {
        threshold = (env.data as { threshold: number }).threshold;
        break;
      }
    }
  }

  state = {
    ...state,
    transactions,
    byId,
    advisories,
    streaming,
    telemetry,
    status,
    threshold,
    selectedId,
  };
  emit();
}

export const store = {
  subscribe,
  getSnapshot,
  ingest(env: Envelope) {
    pending.push(env);
    scheduleFlush();
  },
  setConnection(c: ConnectionState) {
    if (state.connection !== c) {
      state = { ...state, connection: c };
      emit();
    }
  },
  select(id: string | null) {
    if (state.selectedId !== id) {
      state = { ...state, selectedId: id };
      emit();
    }
  },
  // Optimistic local threshold while dragging; the server confirms via CONFIG_UPDATED.
  setLocalThreshold(v: number) {
    state = { ...state, threshold: v };
    emit();
  },
};

export function useStore<T>(selector: (s: State) => T): T {
  return useSyncExternalStore(
    subscribe,
    () => selector(state),
    () => selector(state),
  );
}
