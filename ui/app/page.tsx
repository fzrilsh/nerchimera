"use client";

import { useEffect } from "react";
import { TopBar } from "@/components/TopBar";
import { PacketStream } from "@/components/PacketStream";
import { Inspector } from "@/components/Inspector";
import { RemediationConsole } from "@/components/RemediationConsole";
import { startWS, stopWS } from "@/lib/ws";

export default function Page() {
  useEffect(() => {
    startWS();
    return () => stopWS();
  }, []);

  return (
    <main className="flex h-screen flex-col bg-void">
      <TopBar />
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-2 p-2 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,1.3fr)]">
        <PacketStream />
        <Inspector />
        <RemediationConsole />
      </div>
    </main>
  );
}
