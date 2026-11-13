// stripControls removes terminal control characters (ESC, other C0/C1) from
// network-derived text before it is written to xterm or rendered, keeping only
// tab and newline. Captured traffic must never inject escape sequences.
export function stripControls(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x09 || c === 0x0a) {
      out += s[i];
      continue;
    }
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) {
      out += ".";
      continue;
    }
    out += s[i];
  }
  return out;
}

// decodeBase64 turns a base64 string into bytes without throwing on bad input.
export function decodeBase64(b64: string): Uint8Array {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array(0);
  }
}
