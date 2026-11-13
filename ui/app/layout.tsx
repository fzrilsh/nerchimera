import type { Metadata } from "next";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "NetChimera · Tactical HTTP Security Proxy",
  description:
    "Real-time HTTP security analysis proxy stitching a C++ engine, a Go pipeline, an LLM agent, and a terminal UI.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={mono.variable}>
      <body className="font-mono scanlines">{children}</body>
    </html>
  );
}
