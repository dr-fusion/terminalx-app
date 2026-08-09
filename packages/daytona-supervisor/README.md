# TerminalX Daytona supervisor

This package is a separately runnable, private-stdio NDJSON supervisor for one exact TerminalX hosted Runtime assignment. It authenticates every lifecycle or containment command, writes a signed atomic dispatch intent before invoking effects, reconciles ambiguous intents after restart, and emits a durable monotonic stream of binding-scoped signed receipt observations.

## Required production boundary

The supervisor must run as uid 0 from `/usr/local/bin/terminalx-sandbox-init`. The Daytona daemon and agent run as the nonroot `terminalx` uid and cannot read or signal the supervisor, its inherited credential channel, its observation key, or its state. A unique observation key is provisioned per assignment through the plan's opaque `observation.keyProvisioningRef`; private bytes never enter the plan, provider API, agent environment, protocol response, checkpoint, or image.

The daemon has no network listener and inherits only stdin/stdout from the root-side transport. It requires all of the following before it becomes useful:

- signed effective-isolation evidence from an independently pinned root/platform enforcer;
- a reviewed hardened Daytona descendant of the base commit in the canonical
  [`daytona-production-source.json`](../../config/daytona-production-source.json) (the base itself is
  rejected because it runs ordinary sandboxes privileged and has no PID limit);
- a root-owned, hash-pinned external effect executor that supports exact `apply` and `reconcile` operations and returns enforced receipts plus signed enforcer attestations;
- signed enforcer-manifest trust pins, command-authority public-key pins, and root-only state/observation key provisioning.

The v1 isolation verifier also pins the deployment-attested snapshot reference and independently inspected immutable image ID, Docker/containerd versions, seccomp digest, XFS-backed overlay and quota, exact internal IPv4 runner bridge, capability sets, pre-start firewall rules, and telemetry/token-injection disablement. It requires both `Authorization` and `X-Daytona-Authorization` to be consumed before toolbox proxying, never forwarded into the Sandbox. The effect executor must live below a protected root-owned directory and match its configured SHA-256 before and after every invocation.

There is deliberately no permissive local executor. Missing evidence, keys, pins, executable, durable state integrity, or uid/isolation controls makes the daemon fail closed.

## Remaining integration work

The package does not manufacture isolation evidence, implement provider effects, or install itself into Daytona. Production deployment still needs the hardened image/init installer, the root-only inherited transport/credential channel, the concrete effect executor, and the independent root/platform isolation attestor. Those components must satisfy the attested v1 contract before ingress is admitted.
