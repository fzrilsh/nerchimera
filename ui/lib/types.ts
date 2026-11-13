export type MsgType =
  | "TRANSACTION_EVENT"
  | "ENGINE_TELEMETRY"
  | "SYSTEM_STATUS"
  | "AI_PATCH_STREAM"
  | "AI_PATCH_EVENT"
  | "CONFIG_UPDATED";

export interface Envelope<T = unknown> {
  type: MsgType;
  ts: number;
  data: T;
}

export interface Finding {
  type: string;
  loc: "header" | "body";
  off: number;
  len: number;
  entropy: number;
}

export type AIStatusKind = "none" | "queued" | "deduplicated" | "dropped";

export interface TransactionEvent {
  id: string;
  ts: number;
  method: string;
  host: string;
  path: string;
  status: number;
  latency_ms: number;
  size: number;
  truncated: boolean;
  body_inspected: boolean;
  entropy_score: number;
  normalized_entropy: number;
  cache_deception_flag: 0 | 1;
  secret_leak_flag: 0 | 1;
  anomaly_score: number;
  findings: Finding[];
  classification: string | null;
  ai_status: AIStatusKind;
  header_block: string;
  body_preview_b64: string;
  engine_us: number;
  engine_error?: string;
}

export type TelemetryLevel = "info" | "warn" | "error";

export interface EngineTelemetry {
  level: TelemetryLevel;
  source: string;
  msg: string;
}

export interface SystemStatus {
  engine: {
    status: "online" | "degraded" | "offline";
    version: string;
    calls: number;
    errors: number;
    mean_us: number;
  };
  pool: {
    workers: number;
    queue_len: number;
    queue_cap: number;
    dropped: number;
    load: number;
  };
  ai: {
    mode: "live" | "mock";
    status: "idle" | "busy" | "error";
    model: string;
    queue_len: number;
    queue_cap: number;
    processed: number;
    dropped: number;
  };
  hub: { clients: number; dropped: number };
  threshold: number;
}

export interface AIPatchStream {
  advisory_id: string;
  tx_id: string;
  delta: string;
}

export type Severity = "low" | "medium" | "high" | "critical";
export type AdvisorySource = "llm" | "mock" | "fallback";

export interface Advisory {
  advisory_id: string;
  tx_id: string;
  classification: string;
  severity: Severity;
  title: string;
  root_cause: string;
  diff: string;
  diff_valid: boolean;
  nginx_rule: string;
  cloudflare_rule: string;
  source: AdvisorySource;
  model: string;
  raw?: string;
  duration_ms: number;
  method: string;
  path: string;
}

export interface ConfigUpdated {
  threshold: number;
}

export interface SetThreshold {
  type: "SET_THRESHOLD";
  value: number;
}
