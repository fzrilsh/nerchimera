import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#08090c",
        panel: "#0d0f14",
        grid: "#1a1d24",
        neon: "#00ff9d",
        amber: "#ffb800",
        crimson: "#ff0055",
        dim: "#5a6472",
      },
      fontFamily: {
        mono: [
          "var(--font-mono)",
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      boxShadow: {
        neon: "0 0 8px rgba(0,255,157,0.35)",
        crimson: "0 0 10px rgba(255,0,85,0.45)",
      },
      keyframes: {
        pulseCrit: {
          "0%,100%": { opacity: "1" },
          "50%": { opacity: "0.45" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        flicker: {
          "0%,100%": { opacity: "1" },
          "92%": { opacity: "1" },
          "94%": { opacity: "0.6" },
          "96%": { opacity: "1" },
        },
      },
      animation: {
        pulseCrit: "pulseCrit 1.1s ease-in-out infinite",
        scan: "scan 6s linear infinite",
        flicker: "flicker 4s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
