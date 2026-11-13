"use client";

import { store } from "./store";
import type { Envelope, MsgType, SetThreshold } from "./types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8081/ws";
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8081";

const KNOWN: ReadonlySet<MsgType> = new Set<MsgType>([
  "TRANSACTION_EVENT",
  "ENGINE_TELEMETRY",
  "SYSTEM_STATUS",
  "AI_PATCH_STREAM",
  "AI_PATCH_EVENT",
  "CONFIG_UPDATED",
]);

let socket: WebSocket | null = null;
let backoff = 500;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let stopped = false;

function scheduleReconnect() {
  if (stopped || reconnectTimer) return;
  const jitter = backoff * (0.8 + Math.random() * 0.4);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, jitter);
  backoff = Math.min(backoff * 2, 10000);
}

function connect() {
  if (stopped) return;
  store.setConnection(socket ? "connecting" : "connecting");
  let ws: WebSocket;
  try {
    ws = new WebSocket(WS_URL);
  } catch {
    scheduleReconnect();
    return;
  }
  socket = ws;

  ws.onopen = () => {
    backoff = 500;
    store.setConnection("open");
  };
  ws.onmessage = (ev) => {
    let env: Envelope;
    try {
      env = JSON.parse(ev.data as string);
    } catch {
      return;
    }
    if (env && typeof env.type === "string" && KNOWN.has(env.type as MsgType)) {
      store.ingest(env);
    }
  };
  ws.onclose = () => {
    if (socket === ws) socket = null;
    store.setConnection("closed");
    scheduleReconnect();
  };
  ws.onerror = () => {
    ws.close();
  };
}

export function startWS() {
  stopped = false;
  if (!socket) connect();
}

export function stopWS() {
  stopped = true;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (socket) {
    socket.close();
    socket = null;
  }
}

export function sendThreshold(value: number) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    const msg: SetThreshold = { type: "SET_THRESHOLD", value };
    socket.send(JSON.stringify(msg));
  }
}

export interface SimulateResult {
  ok: boolean;
  status: number;
  retryAfter?: number;
  scenarios?: number;
}

export async function triggerSimulate(): Promise<SimulateResult> {
  try {
    const res = await fetch(`${API_URL}/api/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    let body: { scenarios?: number; retry_after?: number } = {};
    try {
      body = await res.json();
    } catch {
      /* ignore */
    }
    return {
      ok: res.ok,
      status: res.status,
      retryAfter: body.retry_after,
      scenarios: body.scenarios,
    };
  } catch {
    return { ok: false, status: 0 };
  }
}
