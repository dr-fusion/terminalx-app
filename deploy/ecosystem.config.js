// TerminalX PM2 ecosystem profile.
//
// Usage:
//   pm2 start deploy/ecosystem.config.js
//   pm2 save && pm2 startup      # persist across reboots
//
// SAFE RESTART: `pm2 reload terminalx` (or restart) sends SIGINT/SIGTERM, which
// the server drains gracefully (finish in-flight, refuse new, flush workers) via
// server/graceful-shutdown.ts. kill_timeout below allows that drain to complete.
// PM2's fork mode does not kill the tmux/pty grandchildren, so live agent work
// survives a restart — the same guarantee the systemd unit's KillMode=process
// provides. Do NOT use cluster mode: the WebSocket/PTY/SQLite state is per-process
// and single-instance by design.

module.exports = {
  apps: [
    {
      name: "terminalx",
      script: "./node_modules/.bin/tsx",
      args: "server/index.ts",
      cwd: "/opt/terminalx",
      exec_mode: "fork",
      instances: 1,
      autorestart: true,
      max_restarts: 10,
      // Allow the graceful drain (local-tmux shutdown budget + auxiliary) to finish.
      kill_timeout: 345000,
      // Give the process time to bind and pass readiness before PM2 considers it up.
      listen_timeout: 20000,
      wait_ready: false,
      env: {
        NODE_ENV: "production",
        PORT: "3000",
        TERMINUS_HOST: "127.0.0.1",
      },
      // Structured JSON telemetry already timestamps its own records.
      time: true,
    },
  ],
};
