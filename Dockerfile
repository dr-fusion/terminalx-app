# TerminalX — Self-hosted terminal IDE for the browser
# Single-stage build: node-pty native addon requires build-essential at both
# compile and runtime (glibc must match). Single stage avoids version mismatches.
#
# Pinned to minor version. Dependabot updates patch releases and digest.
FROM node:20.18-bookworm-slim

# Install system dependencies: tmux (terminal multiplexer), build tools (node-pty),
# tini (PID 1 signal handling), curl (HEALTHCHECK).
RUN apt-get update && apt-get install -y --no-install-recommends \
    tmux \
    build-essential \
    python3 \
    ca-certificates \
    tini \
    curl \
  && rm -rf /var/lib/apt/lists/*

# Create non-root user owning /app and /home/terminus (the file-browser root).
RUN useradd --create-home --shell /bin/bash --uid 1001 terminus

WORKDIR /app

# Install dependencies (cached layer). Chown so the app user owns node_modules.
COPY --chown=terminus:terminus package.json package-lock.json .npmrc ./
RUN npm ci --include=dev

# Copy source, owned by the app user.
COPY --chown=terminus:terminus . .

# Build Next.js
RUN npm run build

# Create data directory for recordings / secrets / user store.
RUN mkdir -p /app/data && chown terminus:terminus /app/data && chmod 700 /app/data

# Runtime configuration
ENV NODE_ENV=production
ENV PORT=3000
ENV TERMINUS_HOST=0.0.0.0
ENV TERMINUS_ROOT=/home/terminus
ENV TERMINALX_AUTH_MODE=none

# Drop privileges.
USER terminus

EXPOSE 3000

# Liveness probe — hits the unauthenticated server-level /health handler.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

# tini reaps zombies and forwards signals to node (important for tmux children).
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["npx", "tsx", "server/index.ts"]
