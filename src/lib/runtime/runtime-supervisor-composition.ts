import type { Runtime } from "./contracts";
import type { RuntimeAuthorityVerifier } from "./runtime-command-execution";
import type { RuntimeCompensationAuthorityVerifier } from "./runtime-compensation-execution";
import type { RuntimeCompensationEnforcementProofVerifier } from "./runtime-compensation-enforcement-proof";
import {
  RuntimeCompensationSupervisor,
  type RuntimeCompensationHandleResolver,
  type RuntimeCompensationJournal,
} from "./runtime-compensation-supervisor";
import type { RuntimeCompensationMaterializerWorker } from "./runtime-supervisor-root";
import type { RuntimeEnforcementProofVerifier } from "./runtime-enforcement-proof";
import {
  RuntimeLifecycleSupervisor,
  type RuntimeLifecycleHandleResolver,
  type RuntimeLifecycleJournal,
} from "./runtime-lifecycle-supervisor";
import {
  RuntimeReceiptFollowSupervisor,
  type RuntimeReceiptFollowHandleResolver,
  type RuntimeReceiptFollowJournal,
  type RuntimeReceiptFollowTransport,
} from "./runtime-receipt-follow-supervisor";
import {
  RuntimeSupervisorRoot,
  type RuntimeDurableWriteStateSource,
} from "./runtime-supervisor-root";
import { createRuntimeWriteStateRegistry, type RuntimeWriteStateRegistry } from "./write-state";

const MAX_CAPABILITY_PROTOTYPE_DEPTH = 32;
const INCOMPLETE_COMPENSATION_RECOVERY = Symbol("incomplete-compensation-recovery");

type AnyFunction = (...args: unknown[]) => unknown;

interface CapturedMethod {
  readonly receiver: object;
  readonly method: AnyFunction;
}

interface CapturedRuntimeSupervisorCompositionOptions {
  readonly writeStateSource: RuntimeDurableWriteStateSource;
  readonly lifecycleJournal: RuntimeLifecycleJournal;
  readonly receiptFollowJournal: RuntimeReceiptFollowJournal;
  readonly compensationJournal: RuntimeCompensationJournal;
  readonly compensationMaterializer: RuntimeCompensationMaterializerWorker;
  readonly runtime: Runtime;
  readonly receiptTransport: RuntimeReceiptFollowTransport;
  readonly lifecycleHandles: RuntimeLifecycleHandleResolver;
  readonly receiptFollowHandles: RuntimeReceiptFollowHandleResolver;
  readonly compensationHandles: RuntimeCompensationHandleResolver;
  readonly verifyLifecycleAuthority: RuntimeAuthorityVerifier;
  readonly verifyLifecycleEnforcementProof: RuntimeEnforcementProofVerifier;
  readonly verifyCompensationAuthority: RuntimeCompensationAuthorityVerifier;
  readonly verifyCompensationEnforcementProof: RuntimeCompensationEnforcementProofVerifier;
  readonly workerIdPrefix: string;
  readonly clock?: () => number;
  readonly onOperationalError?: (component: RuntimeSupervisorComponent) => void;
}

export type RuntimeSupervisorComponent = "lifecycle" | "receipt-follow" | "compensation" | "root";

/** Private durable seams supplied by the Team Session kernel. */
export interface RuntimeSupervisorKernel {
  readonly runtimeWriteStateSnapshotSource: RuntimeDurableWriteStateSource;
  readonly runtimeLifecycleJournal: RuntimeLifecycleJournal;
  readonly runtimeReceiptFollowJournal: RuntimeReceiptFollowJournal;
  readonly runtimeCompensationJournal?: RuntimeCompensationJournal;
  readonly runtimeCompensationMaterializer?: RuntimeCompensationMaterializerWorker;
}

export interface CreateRuntimeSupervisorCompositionOptions {
  readonly kernel: RuntimeSupervisorKernel;
  readonly runtime: Runtime;
  readonly receiptTransport: RuntimeReceiptFollowTransport;
  readonly lifecycleHandles: RuntimeLifecycleHandleResolver;
  readonly receiptFollowHandles: RuntimeReceiptFollowHandleResolver;
  readonly compensationHandles: RuntimeCompensationHandleResolver;
  readonly verifyLifecycleAuthority: RuntimeAuthorityVerifier;
  readonly verifyLifecycleEnforcementProof: RuntimeEnforcementProofVerifier;
  readonly verifyCompensationAuthority: RuntimeCompensationAuthorityVerifier;
  readonly verifyCompensationEnforcementProof: RuntimeCompensationEnforcementProofVerifier;
  /** Stable per-process prefix; component suffixes make lease ownership unambiguous. */
  readonly workerIdPrefix: string;
  readonly clock?: () => number;
  readonly onOperationalError?: (component: RuntimeSupervisorComponent) => void;
}

/**
 * Complete portable Runtime-truth worker graph. Construction requires the
 * compensation trust group, and the returned write-state registry remains
 * fail-closed until `root.start()` loads its SQLite snapshot.
 */
export interface RuntimeSupervisorComposition {
  readonly root: RuntimeSupervisorRoot;
  readonly writeStateRegistry: RuntimeWriteStateRegistry;
  readonly lifecycle: RuntimeLifecycleSupervisor;
  readonly receiptFollow: RuntimeReceiptFollowSupervisor;
  readonly compensation: RuntimeCompensationSupervisor;
}

export function createRuntimeSupervisorComposition(
  options: CreateRuntimeSupervisorCompositionOptions
): RuntimeSupervisorComposition {
  let captured: CapturedRuntimeSupervisorCompositionOptions;
  try {
    captured = captureCompositionOptions(options);
  } catch (error) {
    if (error === INCOMPLETE_COMPENSATION_RECOVERY) {
      throw new TypeError("Runtime supervisor composition requires compensation recovery");
    }
    throw new TypeError("Invalid Runtime supervisor composition");
  }

  const report = (component: RuntimeSupervisorComponent) => () => {
    try {
      captured.onOperationalError?.(component);
    } catch {
      // Operational telemetry cannot terminate a safety worker.
    }
  };
  const sharedClock = captured.clock === undefined ? {} : { clock: captured.clock };
  const writeStateRegistry = createRuntimeWriteStateRegistry({ requireBootstrap: true });
  const lifecycle = new RuntimeLifecycleSupervisor({
    journal: captured.lifecycleJournal,
    runtime: captured.runtime,
    handles: captured.lifecycleHandles,
    verifyAuthority: captured.verifyLifecycleAuthority,
    verifyEnforcementProof: captured.verifyLifecycleEnforcementProof,
    workerId: `${captured.workerIdPrefix}:lifecycle`,
    ...sharedClock,
    onOperationalError: report("lifecycle"),
  });
  const receiptFollow = new RuntimeReceiptFollowSupervisor({
    journal: captured.receiptFollowJournal,
    transport: captured.receiptTransport,
    handles: captured.receiptFollowHandles,
    workerId: `${captured.workerIdPrefix}:receipt-follow`,
    ...sharedClock,
    onOperationalError: report("receipt-follow"),
  });
  const compensation = new RuntimeCompensationSupervisor({
    journal: captured.compensationJournal,
    runtime: captured.runtime,
    handles: captured.compensationHandles,
    verifyAuthority: captured.verifyCompensationAuthority,
    verifyEnforcementProof: captured.verifyCompensationEnforcementProof,
    workerId: `${captured.workerIdPrefix}:compensation`,
    ...sharedClock,
    onOperationalError: report("compensation"),
  });
  const root = new RuntimeSupervisorRoot({
    lifecycle,
    receiptFollow,
    compensation,
    materializer: captured.compensationMaterializer,
    writeStateRegistry,
    writeStateSource: captured.writeStateSource,
    ...sharedClock,
    onOperationalError: report("root"),
  });

  return Object.freeze({
    root,
    writeStateRegistry,
    lifecycle,
    receiptFollow,
    compensation,
  });
}

function captureCompositionOptions(
  options: CreateRuntimeSupervisorCompositionOptions
): CapturedRuntimeSupervisorCompositionOptions {
  const record = dataRecord(options);
  const kernel = dataRecord(dataField(record, "kernel"));
  const workerIdPrefix = dataField(record, "workerIdPrefix");
  const clock = optionalDataField(record, "clock");
  const onOperationalError = optionalDataField(record, "onOperationalError");
  if (
    typeof workerIdPrefix !== "string" ||
    workerIdPrefix.length < 1 ||
    workerIdPrefix.length > 96 ||
    !/^[A-Za-z0-9][A-Za-z0-9._~:/-]*$/.test(workerIdPrefix) ||
    (clock !== undefined && typeof clock !== "function") ||
    (onOperationalError !== undefined && typeof onOperationalError !== "function")
  ) {
    throw new TypeError();
  }

  const compensationJournal = optionalDataField(kernel, "runtimeCompensationJournal");
  const compensationMaterializer = optionalDataField(kernel, "runtimeCompensationMaterializer");
  if (compensationJournal === undefined || compensationMaterializer === undefined) {
    throw INCOMPLETE_COMPENSATION_RECOVERY;
  }

  const verifyLifecycleAuthority = dataField(record, "verifyLifecycleAuthority");
  const verifyLifecycleEnforcementProof = dataField(record, "verifyLifecycleEnforcementProof");
  const verifyCompensationAuthority = dataField(record, "verifyCompensationAuthority");
  const verifyCompensationEnforcementProof = dataField(
    record,
    "verifyCompensationEnforcementProof"
  );
  if (
    typeof verifyLifecycleAuthority !== "function" ||
    typeof verifyLifecycleEnforcementProof !== "function" ||
    typeof verifyCompensationAuthority !== "function" ||
    typeof verifyCompensationEnforcementProof !== "function"
  ) {
    throw new TypeError();
  }

  return Object.freeze({
    writeStateSource: captureWriteStateSource(dataField(kernel, "runtimeWriteStateSnapshotSource")),
    lifecycleJournal: captureLifecycleJournal(dataField(kernel, "runtimeLifecycleJournal")),
    receiptFollowJournal: captureReceiptFollowJournal(
      dataField(kernel, "runtimeReceiptFollowJournal")
    ),
    compensationJournal: captureCompensationJournal(compensationJournal),
    compensationMaterializer: captureMaterializer(compensationMaterializer),
    runtime: captureRuntime(dataField(record, "runtime")),
    receiptTransport: captureReceiptTransport(dataField(record, "receiptTransport")),
    lifecycleHandles: captureLifecycleHandles(dataField(record, "lifecycleHandles")),
    receiptFollowHandles: captureReceiptFollowHandles(dataField(record, "receiptFollowHandles")),
    compensationHandles: captureCompensationHandles(dataField(record, "compensationHandles")),
    verifyLifecycleAuthority: verifyLifecycleAuthority as RuntimeAuthorityVerifier,
    verifyLifecycleEnforcementProof:
      verifyLifecycleEnforcementProof as RuntimeEnforcementProofVerifier,
    verifyCompensationAuthority:
      verifyCompensationAuthority as RuntimeCompensationAuthorityVerifier,
    verifyCompensationEnforcementProof:
      verifyCompensationEnforcementProof as RuntimeCompensationEnforcementProofVerifier,
    workerIdPrefix,
    ...(clock === undefined ? {} : { clock: clock as () => number }),
    ...(onOperationalError === undefined
      ? {}
      : {
          onOperationalError: onOperationalError as (component: RuntimeSupervisorComponent) => void,
        }),
  });
}

function captureRuntime(value: unknown): Runtime {
  const command = captureMethod(value, "command");
  return Object.freeze({
    command: (...args: Parameters<Runtime["command"]>) =>
      invoke(command, args) as ReturnType<Runtime["command"]>,
  }) as unknown as Runtime;
}

function captureReceiptTransport(value: unknown): RuntimeReceiptFollowTransport {
  const follow = captureMethod(value, "follow");
  return Object.freeze({
    follow: (...args: Parameters<RuntimeReceiptFollowTransport["follow"]>) =>
      invoke(follow, args) as ReturnType<RuntimeReceiptFollowTransport["follow"]>,
  });
}

function captureLifecycleJournal(value: unknown): RuntimeLifecycleJournal {
  const reconcile = captureMethod(value, "reconcile");
  const claim = captureMethod(value, "claim");
  const renew = captureMethod(value, "renew");
  const complete = captureMethod(value, "complete");
  return Object.freeze({
    reconcile: (...args: Parameters<RuntimeLifecycleJournal["reconcile"]>) =>
      invoke(reconcile, args) as ReturnType<RuntimeLifecycleJournal["reconcile"]>,
    claim: (...args: Parameters<RuntimeLifecycleJournal["claim"]>) =>
      invoke(claim, args) as ReturnType<RuntimeLifecycleJournal["claim"]>,
    renew: (...args: Parameters<RuntimeLifecycleJournal["renew"]>) =>
      invoke(renew, args) as ReturnType<RuntimeLifecycleJournal["renew"]>,
    complete: (...args: Parameters<RuntimeLifecycleJournal["complete"]>) =>
      invoke(complete, args) as ReturnType<RuntimeLifecycleJournal["complete"]>,
  });
}

function captureReceiptFollowJournal(value: unknown): RuntimeReceiptFollowJournal {
  const reconcile = captureMethod(value, "reconcile");
  const claim = captureMethod(value, "claim");
  const renew = captureMethod(value, "renew");
  const release = captureMethod(value, "release");
  const settle = captureMethod(value, "settle");
  return Object.freeze({
    reconcile: (...args: Parameters<RuntimeReceiptFollowJournal["reconcile"]>) =>
      invoke(reconcile, args) as ReturnType<RuntimeReceiptFollowJournal["reconcile"]>,
    claim: (...args: Parameters<RuntimeReceiptFollowJournal["claim"]>) =>
      invoke(claim, args) as ReturnType<RuntimeReceiptFollowJournal["claim"]>,
    renew: (...args: Parameters<RuntimeReceiptFollowJournal["renew"]>) =>
      invoke(renew, args) as ReturnType<RuntimeReceiptFollowJournal["renew"]>,
    release: (...args: Parameters<RuntimeReceiptFollowJournal["release"]>) =>
      invoke(release, args) as ReturnType<RuntimeReceiptFollowJournal["release"]>,
    settle: (...args: Parameters<RuntimeReceiptFollowJournal["settle"]>) =>
      invoke(settle, args) as ReturnType<RuntimeReceiptFollowJournal["settle"]>,
  });
}

function captureCompensationJournal(value: unknown): RuntimeCompensationJournal {
  const reconcile = captureMethod(value, "reconcile");
  const claim = captureMethod(value, "claim");
  const renew = captureMethod(value, "renew");
  const complete = captureMethod(value, "complete");
  return Object.freeze({
    reconcile: (...args: Parameters<RuntimeCompensationJournal["reconcile"]>) =>
      invoke(reconcile, args) as ReturnType<RuntimeCompensationJournal["reconcile"]>,
    claim: (...args: Parameters<RuntimeCompensationJournal["claim"]>) =>
      invoke(claim, args) as ReturnType<RuntimeCompensationJournal["claim"]>,
    renew: (...args: Parameters<RuntimeCompensationJournal["renew"]>) =>
      invoke(renew, args) as ReturnType<RuntimeCompensationJournal["renew"]>,
    complete: (...args: Parameters<RuntimeCompensationJournal["complete"]>) =>
      invoke(complete, args) as ReturnType<RuntimeCompensationJournal["complete"]>,
  });
}

function captureWriteStateSource(value: unknown): RuntimeDurableWriteStateSource {
  const read = captureMethod(value, "read");
  return Object.freeze({
    read: (...args: Parameters<RuntimeDurableWriteStateSource["read"]>) =>
      invoke(read, args) as ReturnType<RuntimeDurableWriteStateSource["read"]>,
  });
}

function captureMaterializer(value: unknown): RuntimeCompensationMaterializerWorker {
  const runOnce = captureMethod(value, "runOnce");
  return Object.freeze({
    runOnce: (...args: Parameters<RuntimeCompensationMaterializerWorker["runOnce"]>) =>
      invoke(runOnce, args) as ReturnType<RuntimeCompensationMaterializerWorker["runOnce"]>,
  });
}

function captureLifecycleHandles(value: unknown): RuntimeLifecycleHandleResolver {
  const resolve = captureMethod(value, "resolve");
  return Object.freeze({
    resolve: (...args: Parameters<RuntimeLifecycleHandleResolver["resolve"]>) =>
      invoke(resolve, args) as ReturnType<RuntimeLifecycleHandleResolver["resolve"]>,
  });
}

function captureReceiptFollowHandles(value: unknown): RuntimeReceiptFollowHandleResolver {
  const resolve = captureMethod(value, "resolve");
  return Object.freeze({
    resolve: (...args: Parameters<RuntimeReceiptFollowHandleResolver["resolve"]>) =>
      invoke(resolve, args) as ReturnType<RuntimeReceiptFollowHandleResolver["resolve"]>,
  });
}

function captureCompensationHandles(value: unknown): RuntimeCompensationHandleResolver {
  const resolve = captureMethod(value, "resolve");
  return Object.freeze({
    resolve: (...args: Parameters<RuntimeCompensationHandleResolver["resolve"]>) =>
      invoke(resolve, args) as ReturnType<RuntimeCompensationHandleResolver["resolve"]>,
  });
}

function dataRecord(value: unknown): object {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError();
  return value;
}

function dataField(value: object, key: PropertyKey): unknown {
  const result = optionalDataField(value, key);
  if (result === undefined) throw new TypeError();
  return result;
}

function optionalDataField(value: object, key: PropertyKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function captureMethod(value: unknown, key: PropertyKey): CapturedMethod {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    throw new TypeError();
  }
  const receiver = value as object;
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < MAX_CAPABILITY_PROTOTYPE_DEPTH; depth += 1) {
    if (visited.has(current)) throw new TypeError();
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError();
      }
      return Object.freeze({ receiver, method: descriptor.value as AnyFunction });
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new TypeError();
}

function invoke(capability: CapturedMethod, args: readonly unknown[]): unknown {
  return Reflect.apply(capability.method, capability.receiver, args);
}
