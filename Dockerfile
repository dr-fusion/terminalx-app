# TerminalX production image.
# Keep both stages on the same immutable Debian/Node image so node-pty is
# compiled against the exact glibc shipped at runtime.
ARG NODE_IMAGE=node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

FROM ${NODE_IMAGE} AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json .npmrc ./
COPY vendor/ ./vendor/
RUN npm ci --include=dev

COPY . .
RUN npm run build \
  && npm prune --omit=dev \
  && npm cache clean --force

FROM ${NODE_IMAGE} AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    openssh-client \
    openssl \
    tini \
    tmux \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --shell /bin/bash --uid 1001 terminus \
  && mkdir -p /app/data /workspace \
  && chown -R terminus:terminus /app /workspace \
  && chmod 700 /app/data /workspace

WORKDIR /app
COPY --from=build --chown=terminus:terminus /app /app

RUN chmod 755 /app/docker-entrypoint.sh

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    TERMINUS_HOST=0.0.0.0 \
    TERMINUS_ROOT=/workspace

USER terminus

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["./node_modules/.bin/tsx", "server/index.ts"]
