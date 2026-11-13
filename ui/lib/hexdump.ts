// hexdump renders bytes as classic offset / hex / ASCII rows:
//   00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
export function hexdump(bytes: Uint8Array, maxBytes = 4096): string[] {
  const rows: string[] = [];
  const n = Math.min(bytes.length, maxBytes);
  for (let off = 0; off < n; off += 16) {
    const slice = bytes.subarray(off, Math.min(off + 16, n));
    const hexCols: string[] = [];
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i < slice.length) {
        hexCols.push(slice[i].toString(16).padStart(2, "0"));
        const c = slice[i];
        ascii += c >= 0x20 && c <= 0x7e ? String.fromCharCode(c) : ".";
      } else {
        hexCols.push("  ");
        ascii += " ";
      }
    }
    const left = hexCols.slice(0, 8).join(" ");
    const right = hexCols.slice(8).join(" ");
    rows.push(`${off.toString(16).padStart(8, "0")}  ${left}  ${right}  |${ascii}|`);
  }
  if (bytes.length > maxBytes) {
    rows.push(`… ${bytes.length - maxBytes} more bytes truncated`);
  }
  return rows;
}
