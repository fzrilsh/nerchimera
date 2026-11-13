"use client";

import { stripControls } from "@/lib/sanitize";

// DiffView renders a unified diff as plain text nodes, colouring lines by
// prefix. No HTML is ever derived from the diff content.
export function DiffView({ diff }: { diff: string }) {
  const lines = stripControls(diff).split("\n");
  return (
    <pre className="text-[12px] leading-[1.5] overflow-x-auto whitespace-pre">
      {lines.map((line, i) => {
        let cls = "text-dim";
        if (line.startsWith("+++") || line.startsWith("---")) cls = "text-sky-300";
        else if (line.startsWith("@@")) cls = "text-amber";
        else if (line.startsWith("+")) cls = "text-neon";
        else if (line.startsWith("-")) cls = "text-crimson";
        else cls = "text-[#9aa7b6]";
        return (
          <div key={i} className={cls}>
            {line === "" ? "\u00a0" : line}
          </div>
        );
      })}
    </pre>
  );
}
