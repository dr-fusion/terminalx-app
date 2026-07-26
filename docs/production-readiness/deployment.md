# TerminalX deployment profiles

Three supported production profiles. All share one hard rule: a restart must
**drain gracefully** and must **never kill live tmux/pty sessions**.

## Graceful drain (all profiles)

On SIGTERM/SIGINT the server (`server/index.ts` + `server/graceful-shutdown.ts`):

1. marks multiplayer transport unavailable and stops the maintenance loop;
2. stops accepting new HTTP connections (begins the drain);
3. lets in-flight requests finish, then closes multiplayer ingress/workers and
   finally SQLite, stops Telegram, closes the file watcher and legacy WebSockets;
4. destroys process resources (PTYs, log streams, identity service).

All within a bounded deadline (Runtime shutdown budget + 30 s auxiliary; ~335 s
for the local-tmux profile). Configure the supervisor's stop timeout at or above
that budget (345 s below) so the drain is never cut short.

## 1. systemd (`deploy/terminalx.service`)

- **`KillMode=process`** — on stop/restart systemd signals only the main web
  server, not the cgroup. tmux sessions and node-pty children survive.
- `TimeoutStopSec=345` accommodates the graceful drain.
- `Restart=on-failure` restarts crashes, not clean operator stops.

Install and verify:

```bash
sudo cp deploy/terminalx.service /etc/systemd/system/terminalx.service
sudo install -m600 deploy/terminalx.env.example /etc/terminalx/terminalx.env   # then edit
sudo systemctl daemon-reload && sudo systemctl enable --now terminalx.service
systemctl show terminalx.service -p KillMode -p ExecStop -p TimeoutStopSec       # KillMode=process
sudo systemctl restart terminalx.service && tmux list-sessions                   # sessions survive
```

## 2. PM2 (`deploy/ecosystem.config.js`)

- `exec_mode: fork`, `instances: 1` — WebSocket/PTY/SQLite state is per-process
  and single-instance by design; never use cluster mode.
- `kill_timeout: 345000` lets the graceful drain finish; fork mode leaves the
  tmux/pty grandchildren alive across a `pm2 reload`.

```bash
pm2 start deploy/ecosystem.config.js
pm2 save && pm2 startup
pm2 reload terminalx        # graceful; existing tmux sessions survive
```

## 3. Container (`Dockerfile` + `docker-compose.yml`)

- Non-root (`terminus`, uid 1001), read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`, tmpfs for `/tmp` and the Next cache, `pids_limit`.
- **Resource ceilings**: `mem_limit`, `memswap_limit`, `cpus`.
- **Healthcheck uses the readiness probe** (`/api/health/ready`), so an
  orchestrator holds traffic until SQLite is migrated and the broker (if any) is
  ready. `stop_grace_period: 345s` matches the drain budget; tini reaps children.
- The Secret Broker runs as an optional supervised **sibling** service (commented
  template in `docker-compose.yml`); TerminalX fails closed until its key exists.

```bash
docker compose up -d --build
docker compose ps        # health: healthy once ready
docker compose restart terminalx
```

## Probes and ops endpoints

| Endpoint            | Purpose   | Access                                                                |
| ------------------- | --------- | --------------------------------------------------------------------- |
| `/health`           | liveness  | public, minimal, no dependency/timing data                            |
| `/api/health/ready` | readiness | public, bare non-leaking status; drives LB routing                    |
| `/api/metrics`      | metrics   | `TERMINALX_METRICS_TOKEN` bearer **or** authenticated admin; 404 else |

### Metrics exposure model

Prefer scraping `/api/metrics` with `TERMINALX_METRICS_TOKEN` over a private
network. The endpoint is access-controlled and returns `404` to unauthorized
callers (it does not disclose its existence). If you cannot use a token, bind the
server to a private interface (`TERMINUS_HOST`) and scrape from there, or place
the endpoint behind your reverse proxy's auth. Never expose it unauthenticated on
a public interface.

## Reverse proxy

Set `TERMINALX_PUBLIC_URL` and, when behind a trusted proxy,
`TERMINALX_TRUST_PROXY=1`, so external URLs and the CSRF same-origin fence are
computed correctly. WebSocket upgrade (`/ws/*`, `/ws/team-sessions/*`) must be
proxied.
