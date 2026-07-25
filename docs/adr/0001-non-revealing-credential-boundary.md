---
status: accepted
---

# Keep raw credentials outside agent-visible execution

TerminalX follows the Centaur-style non-reveal boundary: application state stores only opaque
Credential Handles, and approved brokers or destination-scoped proxies perform typed operations
without returning raw tokens, private keys, or secret values. This deliberately rejects direct
secret injection and generic decrypt/export APIs—even when a User explicitly asks—because prompt
convenience cannot be allowed to turn the agent, shell, logs, artifacts, or model output into a
credential extraction path; support for a broader approval model may be reconsidered only as a new
security-boundary decision.
