import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Do not use NextConfig.env for authentication or security configuration.
  // Those values are compiled into bundles at image-build time. Proxy and
  // route handlers must read the container's runtime environment instead.
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
          {
            key: "Content-Security-Policy",
            value:
              "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
