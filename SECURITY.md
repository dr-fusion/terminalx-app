# Security Policy

## Supported versions

TerminalX is pre-1.0. Only the `main` branch receives security fixes.
Tagged releases are provided for reference and reproducibility — production
users should track `main` until a stable 1.0 is cut.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use GitHub's private vulnerability reporting:

1. Go to https://github.com/dudhatparesh/terminalx-app-mono/security/advisories/new
2. Describe the issue, impact, and (if possible) a reproduction.
3. You'll get an acknowledgement within 72 hours.

If GitHub's advisory system is unavailable to you, open a minimal issue
that says "security report — please contact me privately" and leave a
way to reach you. A maintainer will respond off-thread.

## What we treat as in-scope

- Authentication and authorization bypass
- Path traversal, command injection, SSRF
- Secret exposure (env, recordings, logs)
- CSRF on state-changing endpoints
- WebSocket origin / auth bypass
- Denial of service via unbounded resources

## Out of scope

- Attacks that require prior filesystem or root access on the host
- Issues in explicitly allowed `TERMINALX_AUTH_MODE=none` deployments — this
  mode is unauthenticated and intended only for loopback, single-user,
  Tailscale/VPN, or other trusted-network deployments. Non-loopback no-auth
  startup requires `TERMINALX_ALLOW_NO_AUTH=1`.
- Dependency CVEs already tracked upstream and not yet patched

## Disclosure

We aim to ship a fix or mitigation within 14 days of report confirmation.
After a fix lands, we'll publish a GHSA with credit to the reporter (unless
the reporter asks to remain anonymous).
