import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Expose auth mode to middleware runtime (NOT secrets — never put secrets here,
  // the env block is inlined into client-side JavaScript bundles)
  // Force-inline env vars into edge middleware at build time.
  env: {
    TERMINALX_AUTH_MODE: process.env.TERMINALX_AUTH_MODE ?? "none",
    TERMINALX_JWT_SECRET: process.env.TERMINALX_JWT_SECRET ?? "",
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-XSS-Protection", value: "1; mode=block" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
          { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'" },
        ],
      },
    ];
  },
};

export default nextConfig;
