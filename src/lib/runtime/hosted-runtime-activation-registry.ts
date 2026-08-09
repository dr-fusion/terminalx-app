import type {
  HostedRuntimeActivation,
  HostedRuntimeActivationQuery,
  HostedRuntimeActivationSink,
  HostedRuntimeActivationSource,
} from "./hosted-runtime-control-plane";
import { snapshotHostedRuntimeActivation } from "./hosted-runtime-activation";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

export interface HostedRuntimeActivationRegistry
  extends HostedRuntimeActivationSource, HostedRuntimeActivationSink {
  close(): void;
}

/**
 * Process-private bridge from provider activation to the kernel settlement.
 * It performs no I/O and cannot replace a previously admitted binding.
 */
export function createHostedRuntimeActivationRegistry(): HostedRuntimeActivationRegistry {
  const activations = new Map<string, HostedRuntimeActivation>();
  let closed = false;
  return Object.freeze({
    register(value: HostedRuntimeActivation): void {
      if (closed) throw new TypeError();
      const activation = snapshotHostedRuntimeActivation(value);
      const key = activationKey(activation);
      const existing = activations.get(key);
      if (existing) {
        if (canonicalRuntimeJson(existing) !== canonicalRuntimeJson(activation))
          throw new TypeError();
        return;
      }
      activations.set(key, activation);
    },
    resolve(value: HostedRuntimeActivationQuery): HostedRuntimeActivation | null {
      if (closed) return null;
      const query = snapshotQuery(value);
      return activations.get(activationKey(query)) ?? null;
    },
    close(): void {
      closed = true;
      activations.clear();
    },
  });
}

function snapshotQuery(value: unknown): HostedRuntimeActivationQuery {
  const snapshot = snapshotRuntimeSupervisorPortableData(value) as HostedRuntimeActivationQuery;
  if (
    !snapshot ||
    typeof snapshot !== "object" ||
    !Number.isSafeInteger(snapshot.runtimeAuthorizationGeneration) ||
    snapshot.runtimeAuthorizationGeneration < 1 ||
    !/^[0-9a-f]{64}$/.test(snapshot.assignmentPlanDigest) ||
    !/^[0-9a-f]{64}$/.test(snapshot.effectEnforcerPolicyDigest)
  ) {
    throw new TypeError();
  }
  canonicalRuntimeJson(snapshot.binding);
  return Object.freeze(snapshot);
}

function activationKey(value: HostedRuntimeActivationQuery): string {
  return canonicalRuntimeJson({
    binding: value.binding,
    runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
    assignmentPlanDigest: value.assignmentPlanDigest,
    effectEnforcerPolicyDigest: value.effectEnforcerPolicyDigest,
  });
}
