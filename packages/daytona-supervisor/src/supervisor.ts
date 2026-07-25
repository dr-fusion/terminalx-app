import { createHash, timingSafeEqual } from "node:crypto";
import { types as nodeTypes } from "node:util";
import type {
  DaytonaSupervisorCommandOutcome,
  DaytonaSupervisorCommandRequest,
  DaytonaSupervisorFollowRequest,
  DaytonaSupervisorIsolationRequest,
  PinnedDaytonaSupervisorTransport,
} from "../../../src/lib/runtime/daytona-hosted-control-plane";
import type {
  RuntimeCommand,
  RuntimeCompensationCommand,
  RuntimeCompensationReceipt,
  RuntimeLifecycleCommand,
  RuntimeReceipt,
} from "../../../src/lib/runtime/contracts";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import type { RuntimeCommandAuthorityVerifier } from "../../../src/lib/runtime/runtime-command-authority";
import {
  snapshotRuntimeCompensationReceiptForCommand,
  verifyRuntimeCompensationReceiptEnforcementProofSynchronously,
} from "../../../src/lib/runtime/runtime-compensation-execution";
import type { SynchronousRuntimeCompensationEnforcementProofVerifier } from "../../../src/lib/runtime/runtime-compensation-enforcement-proof";
import type { RuntimeCompensationReceiptObservationIssuer } from "../../../src/lib/runtime/runtime-compensation-receipt-observation";
import {
  snapshotRuntimeReceiptForCommand,
  verifyRuntimeReceiptEnforcementProofSynchronously,
} from "../../../src/lib/runtime/runtime-command-execution";
import type { SynchronousRuntimeEnforcementProofVerifier } from "../../../src/lib/runtime/runtime-enforcement-proof";
import type { RuntimeReceiptObservationIssuer } from "../../../src/lib/runtime/runtime-receipt-observation";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import type { RuntimeBinding } from "../../../src/lib/team-sessions/contracts";
import { HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN } from "../../../src/lib/runtime/hosted-runtime-control-plane";

export const DAYTONA_SUPERVISOR_PROTOCOL_VERSION = 1 as const;
export const DAYTONA_SUPERVISOR_ARTIFACT_KIND = "terminalx.daytona-supervisor" as const;
export const DAYTONA_SUPERVISOR_STATE_SIGNATURE_DOMAIN =
  "terminalx/daytona-supervisor-state/v1\0" as const;
export const DAYTONA_SUPERVISOR_ISOLATION_CLAIMS_DIGEST_DOMAIN =
  "terminalx/daytona-effective-isolation-claims/v1\0" as const;
export const DAYTONA_SUPERVISOR_ISOLATION_SIGNATURE_DOMAIN =
  "terminalx/daytona-effective-isolation-authority/v1\0" as const;

const HOSTED_COMMAND_DIGEST_DOMAIN = "terminalx/hosted-command/v1\0";
const PROVIDER_IDENTITY_DIGEST_DOMAIN = "terminalx/daytona-provider-identity/v1\0";
const SUPERVISOR_CONFIGURATION_DIGEST_DOMAIN = "terminalx/daytona-supervisor-configuration/v1\0";
const LIFECYCLE_KINDS = new Set(["run.start", "run.pause", "run.resume", "run.stop"]);
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const CURSOR = /^[0-9]{20}$/;
const MAX_OPERATIONS = 100_000;

type AnyFunction = (...args: never[]) => unknown;

export type DaytonaSupervisorProtocolErrorCode =
  | "invalid-request"
  | "permission-denied"
  | "conflict"
  | "not-ready"
  | "unavailable"
  | "internal";

const SAFE_ERROR_MESSAGES: Readonly<Record<DaytonaSupervisorProtocolErrorCode, string>> =
  Object.freeze({
    "invalid-request": "Daytona supervisor request is invalid",
    "permission-denied": "Daytona supervisor denied the request",
    conflict: "Daytona supervisor request conflicts with durable state",
    "not-ready": "Daytona supervisor enforcement is not ready",
    unavailable: "Daytona supervisor is unavailable",
    internal: "Daytona supervisor operation failed",
  });

/** Safe wire surface: no command, provider identifier, path, or verifier error is retained. */
export class DaytonaSupervisorProtocolError extends Error {
  constructor(readonly code: DaytonaSupervisorProtocolErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "DaytonaSupervisorProtocolError";
  }
}

export interface DaytonaSupervisorConfiguration {
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly providerIdentityCommitment: string;
  readonly artifactDigest: string;
  readonly sandboxUser: string;
  readonly supervisorArtifactDigest: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
  /** Concrete provider-bound signed manifest claims digest. */
  readonly effectEnforcerSetDigest: string;
  readonly expectedRevision: number;
  readonly maxOperations: number;
}

export interface DaytonaSupervisorEffectExecutionRequest {
  readonly mode: "apply" | "reconcile";
  readonly operationId: string;
  readonly commandId: string;
  readonly commandDigest: string;
  readonly command: RuntimeLifecycleCommand | RuntimeCompensationCommand;
  readonly requiredEffectEnforcerSetDigest: string;
}

export interface DaytonaSupervisorEffectExecutionResult {
  readonly receipt: unknown;
  /** Signed effect-enforcer attestations referenced by the receipt proof. */
  readonly attestations: readonly unknown[];
}

export interface DaytonaSupervisorEffectExecutor {
  execute(
    request: DaytonaSupervisorEffectExecutionRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorEffectExecutionResult>;
}

export interface DaytonaSupervisorProofVerifierFactory {
  lifecycle(
    attestations: readonly unknown[],
    requiredEffectEnforcerSetDigest: string
  ): SynchronousRuntimeEnforcementProofVerifier;
  compensation(
    attestations: readonly unknown[],
    requiredEffectEnforcerSetDigest: string
  ): SynchronousRuntimeCompensationEnforcementProofVerifier;
}

export interface DaytonaSupervisorIsolationEvidenceSource {
  read(): unknown;
  verify(input: {
    readonly evidence: unknown;
    readonly request: DaytonaSupervisorIsolationRequest;
    readonly providerIdentityCommitment: string;
  }): boolean;
}

export interface DaytonaSupervisorCompletedOperation {
  readonly status: "complete";
  readonly operationId: string;
  readonly commandId: string;
  readonly commandDigest: string;
  readonly cursor: string;
  readonly observationDigest: string;
  readonly receipt: RuntimeReceipt | RuntimeCompensationReceipt;
  readonly observation: unknown;
  readonly attestations: readonly unknown[];
}

export interface DaytonaSupervisorDispatchingOperation {
  readonly status: "dispatching";
  readonly operationId: string;
  readonly commandId: string;
  readonly commandDigest: string;
}

export type DaytonaSupervisorOperation =
  | DaytonaSupervisorDispatchingOperation
  | DaytonaSupervisorCompletedOperation;

export interface DaytonaSupervisorState {
  readonly version: 1;
  readonly configurationDigest: string;
  readonly nextCursor: number;
  readonly operations: readonly DaytonaSupervisorOperation[];
}

export interface DaytonaSupervisorStateStore {
  load(configurationDigest: string): DaytonaSupervisorState;
  commit(state: DaytonaSupervisorState): Promise<void>;
}

export interface CreatePinnedDaytonaSupervisorOptions {
  readonly configuration: DaytonaSupervisorConfiguration;
  readonly authorityVerifier: RuntimeCommandAuthorityVerifier;
  readonly lifecycleObservationIssuer: RuntimeReceiptObservationIssuer;
  readonly compensationObservationIssuer: RuntimeCompensationReceiptObservationIssuer;
  readonly isolationEvidence: DaytonaSupervisorIsolationEvidenceSource;
  readonly effectExecutor: DaytonaSupervisorEffectExecutor;
  readonly proofVerifiers: DaytonaSupervisorProofVerifierFactory;
  readonly stateStore: DaytonaSupervisorStateStore;
  readonly clock: () => number;
  readonly observationId: (cursor: string) => string;
}

type DaytonaSupervisorReceiptBackedCommandRequest = Omit<
  DaytonaSupervisorCommandRequest,
  "command"
> & {
  readonly command: RuntimeLifecycleCommand | RuntimeCompensationCommand;
};

interface CapturedMethod {
  readonly receiver: object;
  readonly method: AnyFunction;
}

interface CapturedOptions {
  readonly configuration: DaytonaSupervisorConfiguration;
  readonly configurationDigest: string;
  readonly authorityVerifier: RuntimeCommandAuthorityVerifier;
  readonly lifecycleObservationIssuer: CapturedMethod;
  readonly compensationObservationIssuer: CapturedMethod;
  readonly isolationRead: CapturedMethod;
  readonly isolationVerify: CapturedMethod;
  readonly effectExecute: CapturedMethod;
  readonly lifecycleProofFactory: CapturedMethod;
  readonly compensationProofFactory: CapturedMethod;
  readonly stateLoad: CapturedMethod;
  readonly stateCommit: CapturedMethod;
  readonly clock: () => number;
  readonly observationId: (cursor: string) => string;
}

/**
 * Durable supervisor protocol core. It never executes effects itself: a pinned
 * enforcer must return an exact enforced receipt and signed attestations.
 */
export class PinnedDaytonaSupervisor implements PinnedDaytonaSupervisorTransport {
  private readonly options: CapturedOptions;
  private state: DaytonaSupervisorState;
  private tail: Promise<void> = Promise.resolve();
  private closed = false;

  constructor(unsafeOptions: CreatePinnedDaytonaSupervisorOptions) {
    try {
      this.options = captureOptions(unsafeOptions);
      this.state = snapshotState(
        Reflect.apply(this.options.stateLoad.method, this.options.stateLoad.receiver, [
          this.options.configurationDigest,
        ]),
        this.options.configurationDigest,
        this.options.configuration.maxOperations
      );
    } catch (error) {
      if (error instanceof DaytonaSupervisorProtocolError) throw error;
      throw new DaytonaSupervisorProtocolError("invalid-request");
    }
  }

  async attestIsolation(
    unsafeRequest: DaytonaSupervisorIsolationRequest,
    signal: AbortSignal
  ): Promise<unknown> {
    this.assertAvailable(signal);
    const request = snapshotProtocolRequest(() => snapshotIsolationRequest(unsafeRequest));
    this.validateIsolationRequest(request);
    let evidence: unknown;
    let verified: unknown;
    try {
      evidence = snapshotRuntimeSupervisorPortableData(
        Reflect.apply(this.options.isolationRead.method, this.options.isolationRead.receiver, [])
      );
      verified = Reflect.apply(
        this.options.isolationVerify.method,
        this.options.isolationVerify.receiver,
        [
          Object.freeze({
            evidence,
            request,
            providerIdentityCommitment: this.options.configuration.providerIdentityCommitment,
          }),
        ]
      );
    } catch {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    if (verified !== true || signal.aborted) {
      suppressPromise(verified);
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    assertProviderIdentifierAbsent(evidence, request.providerSandboxId);
    return evidence;
  }

  executeAuthenticated(
    unsafeRequest: DaytonaSupervisorCommandRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome> {
    this.assertAvailable(signal);
    const request = snapshotProtocolRequest(() => snapshotCommandRequest(unsafeRequest));
    return this.serial(async () => this.executeSerialized(request, signal));
  }

  followSigned(
    unsafeRequest: DaytonaSupervisorFollowRequest,
    signal: AbortSignal
  ): AsyncIterable<unknown> {
    this.assertAvailable(signal);
    const request = snapshotProtocolRequest(() => snapshotFollowRequest(unsafeRequest));
    this.validateFollowRequest(request);
    const snapshot = this.state;
    const checkpoint = snapshotCheckpoint(request.checkpoint);
    const completed = snapshot.operations
      .filter(
        (operation): operation is DaytonaSupervisorCompletedOperation =>
          operation.status === "complete"
      )
      .sort((left, right) => left.cursor.localeCompare(right.cursor));
    let start = 0;
    if (checkpoint !== null) {
      const index = completed.findIndex((operation) => operation.cursor === checkpoint.cursor);
      if (
        index < 0 ||
        !sameDigest(completed[index]?.observationDigest, checkpoint.observationDigest)
      ) {
        throw new DaytonaSupervisorProtocolError("conflict");
      }
      start = index + 1;
    }
    return Object.freeze({
      async *[Symbol.asyncIterator](): AsyncGenerator<unknown> {
        for (const operation of completed.slice(start)) {
          if (signal.aborted) return;
          yield Object.freeze({
            observation: operation.observation,
            attestations: operation.attestations,
          });
        }
      },
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.tail.catch(() => undefined);
  }

  private async executeSerialized(
    request: DaytonaSupervisorReceiptBackedCommandRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome> {
    this.assertAvailable(signal);
    this.validateCommandRequest(request, "persisted");
    const existing = findOperation(this.state, request.operationId, request.commandId);
    if (existing !== null) {
      assertReplayMatches(existing, request);
      if (existing.status === "complete") return outcomeFrom(existing);
      return this.dispatchAndComplete(request, existing, "reconcile", signal);
    }
    this.validateCommandRequest(request, "fresh");
    if (this.state.operations.length >= this.options.configuration.maxOperations) {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    const intent: DaytonaSupervisorDispatchingOperation = Object.freeze({
      status: "dispatching",
      operationId: request.operationId,
      commandId: request.commandId,
      commandDigest: request.commandDigest,
    });
    const nextState = Object.freeze({
      ...this.state,
      operations: Object.freeze([...this.state.operations, intent]),
    });
    await this.commit(nextState);
    return this.dispatchAndComplete(request, intent, "apply", signal);
  }

  private async dispatchAndComplete(
    request: DaytonaSupervisorReceiptBackedCommandRequest,
    intent: DaytonaSupervisorDispatchingOperation,
    mode: "apply" | "reconcile",
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome> {
    this.assertAvailable(signal);
    let unsafeResult: unknown;
    try {
      unsafeResult = Reflect.apply(
        this.options.effectExecute.method,
        this.options.effectExecute.receiver,
        [
          Object.freeze({
            mode,
            operationId: request.operationId,
            commandId: request.commandId,
            commandDigest: request.commandDigest,
            command: request.command,
            requiredEffectEnforcerSetDigest: request.trust.requiredEffectEnforcerSetDigest,
          } satisfies DaytonaSupervisorEffectExecutionRequest),
          signal,
        ]
      );
    } catch {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    if (!nodeTypes.isPromise(unsafeResult)) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    let resolvedResult: unknown;
    try {
      resolvedResult = await unsafeResult;
    } catch {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    let result: DaytonaSupervisorEffectExecutionResult;
    try {
      result = snapshotEffectResult(resolvedResult);
    } catch {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    if (signal.aborted) throw new DaytonaSupervisorProtocolError("unavailable");

    const { receipt, observation } = this.verifyAndObserve(request, result);
    assertProviderIdentifierAbsent(receipt, request.providerSandboxId);
    assertProviderIdentifierAbsent(observation, request.providerSandboxId);
    const cursor = observationCursor(observation);
    const observationDigest = observationClaimsDigest(observation);
    const completed: DaytonaSupervisorCompletedOperation = Object.freeze({
      status: "complete",
      operationId: intent.operationId,
      commandId: intent.commandId,
      commandDigest: intent.commandDigest,
      cursor,
      observationDigest,
      receipt,
      observation,
      attestations: result.attestations,
    });
    const operations = this.state.operations.map((operation) =>
      operation.operationId === intent.operationId ? completed : operation
    );
    const nextState: DaytonaSupervisorState = Object.freeze({
      ...this.state,
      nextCursor: this.state.nextCursor + 1,
      operations: Object.freeze(operations),
    });
    await this.commit(nextState);
    return outcomeFrom(completed);
  }

  private verifyAndObserve(
    request: DaytonaSupervisorReceiptBackedCommandRequest,
    result: DaytonaSupervisorEffectExecutionResult
  ): {
    readonly receipt: RuntimeReceipt | RuntimeCompensationReceipt;
    readonly observation: unknown;
  } {
    const cursor = formatCursor(this.state.nextCursor);
    const previous = lastCheckpoint(this.state);
    const observationId = safeReference(this.options.observationId(cursor));
    if (isCompensationCommand(request.command)) {
      const receipt = snapshotRuntimeCompensationReceiptForCommand(result.receipt, request.command);
      requireEnforced(receipt);
      const verifier = this.proofVerifier(
        "compensation",
        result.attestations,
        request.trust.requiredEffectEnforcerSetDigest
      ) as SynchronousRuntimeCompensationEnforcementProofVerifier;
      verifyRuntimeCompensationReceiptEnforcementProofSynchronously(
        request.command,
        receipt,
        verifier
      );
      const observation = Reflect.apply(
        this.options.compensationObservationIssuer.method,
        this.options.compensationObservationIssuer.receiver,
        [Object.freeze({ observationId, cursor, previous, command: request.command, receipt })]
      );
      return Object.freeze({ receipt, observation: snapshotObservation(observation) });
    }

    const command = request.command as RuntimeLifecycleCommand;
    const receipt = snapshotRuntimeReceiptForCommand(result.receipt as RuntimeReceipt, command);
    requireEnforced(receipt);
    const verifier = this.proofVerifier(
      "lifecycle",
      result.attestations,
      request.trust.requiredEffectEnforcerSetDigest
    ) as SynchronousRuntimeEnforcementProofVerifier;
    verifyRuntimeReceiptEnforcementProofSynchronously(command, receipt, verifier);
    const observation = Reflect.apply(
      this.options.lifecycleObservationIssuer.method,
      this.options.lifecycleObservationIssuer.receiver,
      [Object.freeze({ observationId, cursor, previous, command, receipt })]
    );
    return Object.freeze({ receipt, observation: snapshotObservation(observation) });
  }

  private proofVerifier(
    kind: "lifecycle" | "compensation",
    attestations: readonly unknown[],
    digest: string
  ): unknown {
    const capability =
      kind === "lifecycle"
        ? this.options.lifecycleProofFactory
        : this.options.compensationProofFactory;
    let verifier: unknown;
    try {
      verifier = Reflect.apply(capability.method, capability.receiver, [attestations, digest]);
    } catch {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    if (typeof verifier !== "function" || nodeTypes.isProxy(verifier)) {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    return verifier;
  }

  private validateIsolationRequest(request: DaytonaSupervisorIsolationRequest): void {
    this.validatePlanRequest(
      request.providerSandboxId,
      request.plan,
      this.options.configuration.expectedRevision,
      request.trust
    );
    if (
      !sameDigest(request.artifactDigest, this.options.configuration.artifactDigest) ||
      request.sandboxUser !== this.options.configuration.sandboxUser
    ) {
      throw new DaytonaSupervisorProtocolError("conflict");
    }
  }

  private validatePlanRequest(
    providerSandboxId: string,
    plan: DaytonaSupervisorIsolationRequest["plan"],
    expectedRevision: number,
    trust: DaytonaSupervisorIsolationRequest["trust"]
  ): void {
    const configuration = this.options.configuration;
    if (
      !sameDigest(
        providerIdentityCommitment(providerSandboxId),
        configuration.providerIdentityCommitment
      ) ||
      !sameDigest(planDigest(plan), configuration.planDigest) ||
      !sameBinding(plan.binding, configuration.binding) ||
      expectedRevision !== configuration.expectedRevision ||
      trust.supervisorArtifactDigest !== configuration.supervisorArtifactDigest ||
      trust.observationIssuerKeyId !== configuration.observationIssuerKeyId ||
      !sameDigest(trust.observationPublicKeyDigest, configuration.observationPublicKeyDigest)
    ) {
      throw new DaytonaSupervisorProtocolError("conflict");
    }
  }

  private validateCommandRequest(
    request: DaytonaSupervisorReceiptBackedCommandRequest,
    freshness: "fresh" | "persisted"
  ): void {
    const configuration = this.options.configuration;
    if (
      !sameDigest(
        providerIdentityCommitment(request.providerSandboxId),
        configuration.providerIdentityCommitment
      ) ||
      request.expectedRevision !== configuration.expectedRevision ||
      request.commandId !== request.command.commandId ||
      !sameDigest(hostedCommandDigest(request.command), request.commandDigest) ||
      !sameBinding(request.command.binding, configuration.binding) ||
      request.trust.supervisorArtifactDigest !== configuration.supervisorArtifactDigest ||
      request.trust.observationIssuerKeyId !== configuration.observationIssuerKeyId ||
      !sameDigest(
        request.trust.observationPublicKeyDigest,
        configuration.observationPublicKeyDigest
      )
    ) {
      throw new DaytonaSupervisorProtocolError("conflict");
    }
    const requiredDigest = configuration.effectEnforcerSetDigest;
    const commandDigest = isCompensationCommand(request.command)
      ? request.command.requiredContainmentEnforcerSetDigest
      : request.command.requiredEffectEnforcerSetDigest;
    if (
      !sameDigest(requiredDigest, request.trust.requiredEffectEnforcerSetDigest) ||
      !sameDigest(commandDigest, requiredDigest)
    ) {
      throw new DaytonaSupervisorProtocolError("conflict");
    }
    if (freshness === "persisted") return;
    if (!this.verifyAuthority(request.command, request.command.authority.issuedAtMs)) {
      throw new DaytonaSupervisorProtocolError("permission-denied");
    }
    const now = sampleClock(this.options.clock);
    if (
      now < request.command.issuedAtMs ||
      now >= request.command.deadlineAtMs ||
      now < request.command.authority.issuedAtMs ||
      now >= request.command.authority.expiresAtMs ||
      !this.verifyAuthority(request.command, now)
    ) {
      throw new DaytonaSupervisorProtocolError("permission-denied");
    }
    const confirmedAt = sampleClock(this.options.clock);
    if (
      confirmedAt < now ||
      confirmedAt >= request.command.deadlineAtMs ||
      confirmedAt >= request.command.authority.expiresAtMs ||
      !this.verifyAuthority(request.command, confirmedAt)
    ) {
      throw new DaytonaSupervisorProtocolError("permission-denied");
    }
  }

  private validateFollowRequest(request: DaytonaSupervisorFollowRequest): void {
    const configuration = this.options.configuration;
    if (
      !sameDigest(
        providerIdentityCommitment(request.providerSandboxId),
        configuration.providerIdentityCommitment
      ) ||
      request.expectedRevision !== configuration.expectedRevision ||
      request.trust.supervisorArtifactDigest !== configuration.supervisorArtifactDigest ||
      request.trust.observationIssuerKeyId !== configuration.observationIssuerKeyId ||
      !sameDigest(
        request.trust.observationPublicKeyDigest,
        configuration.observationPublicKeyDigest
      )
    ) {
      throw new DaytonaSupervisorProtocolError("conflict");
    }
  }

  private verifyAuthority(command: RuntimeCommand, nowMs: number): boolean {
    try {
      const result = this.options.authorityVerifier(Object.freeze({ command, nowMs }));
      if (result !== true) suppressPromise(result);
      return result === true;
    } catch {
      return false;
    }
  }

  private async commit(state: DaytonaSupervisorState): Promise<void> {
    let result: unknown;
    try {
      result = Reflect.apply(this.options.stateCommit.method, this.options.stateCommit.receiver, [
        state,
      ]);
    } catch {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    if (!nodeTypes.isPromise(result)) throw new DaytonaSupervisorProtocolError("unavailable");
    try {
      const value = await result;
      if (value !== undefined) throw new TypeError();
    } catch {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    this.state = state;
  }

  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation, operation);
    this.tail = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private assertAvailable(signal: AbortSignal): void {
    if (this.closed) throw new DaytonaSupervisorProtocolError("unavailable");
    try {
      AbortSignal.prototype.throwIfAborted.call(signal);
    } catch {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
  }
}

export function createPinnedDaytonaSupervisor(
  options: CreatePinnedDaytonaSupervisorOptions
): PinnedDaytonaSupervisorTransport {
  return new PinnedDaytonaSupervisor(options);
}

function captureOptions(options: CreatePinnedDaytonaSupervisorOptions): CapturedOptions {
  const record = exactRecord(options, [
    "configuration",
    "authorityVerifier",
    "lifecycleObservationIssuer",
    "compensationObservationIssuer",
    "isolationEvidence",
    "effectExecutor",
    "proofVerifiers",
    "stateStore",
    "clock",
    "observationId",
  ]);
  const configuration = snapshotConfiguration(field(record, "configuration"));
  return Object.freeze({
    configuration,
    configurationDigest: sha256(
      `${SUPERVISOR_CONFIGURATION_DIGEST_DOMAIN}${canonicalRuntimeJson(configuration)}`
    ),
    authorityVerifier: captureFunction(
      field(record, "authorityVerifier")
    ) as RuntimeCommandAuthorityVerifier,
    lifecycleObservationIssuer: captureMethod(field(record, "lifecycleObservationIssuer"), "issue"),
    compensationObservationIssuer: captureMethod(
      field(record, "compensationObservationIssuer"),
      "issue"
    ),
    isolationRead: captureMethod(field(record, "isolationEvidence"), "read"),
    isolationVerify: captureMethod(field(record, "isolationEvidence"), "verify"),
    effectExecute: captureMethod(field(record, "effectExecutor"), "execute"),
    lifecycleProofFactory: captureMethod(field(record, "proofVerifiers"), "lifecycle"),
    compensationProofFactory: captureMethod(field(record, "proofVerifiers"), "compensation"),
    stateLoad: captureMethod(field(record, "stateStore"), "load"),
    stateCommit: captureMethod(field(record, "stateStore"), "commit"),
    clock: captureFunction(field(record, "clock")) as () => number,
    observationId: captureFunction(field(record, "observationId")) as (cursor: string) => string,
  });
}

function snapshotConfiguration(value: unknown): DaytonaSupervisorConfiguration {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "binding",
    "planDigest",
    "providerIdentityCommitment",
    "artifactDigest",
    "sandboxUser",
    "supervisorArtifactDigest",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
    "effectEnforcerSetDigest",
    "expectedRevision",
    "maxOperations",
  ]);
  const maxOperations = positiveInteger(field(record, "maxOperations"));
  if (maxOperations > MAX_OPERATIONS) throw new TypeError();
  return Object.freeze({
    binding: snapshotBinding(field(record, "binding")),
    planDigest: digest(field(record, "planDigest")),
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    artifactDigest: digest(field(record, "artifactDigest")),
    sandboxUser: safeReference(field(record, "sandboxUser")),
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    observationIssuerKeyId: safeReference(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
    expectedRevision: positiveInteger(field(record, "expectedRevision")),
    maxOperations,
  });
}

function snapshotState(
  value: unknown,
  configurationDigest: string,
  maxOperations: number
): DaytonaSupervisorState {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "version",
    "configurationDigest",
    "nextCursor",
    "operations",
  ]);
  if (
    field(record, "version") !== 1 ||
    !sameDigest(field(record, "configurationDigest"), configurationDigest)
  ) {
    throw new DaytonaSupervisorProtocolError("conflict");
  }
  const nextCursor = positiveInteger(field(record, "nextCursor"));
  const unsafeOperations = field(record, "operations");
  if (!Array.isArray(unsafeOperations) || unsafeOperations.length > maxOperations)
    throw new TypeError();
  const operations = unsafeOperations.map(snapshotOperation);
  const operationIds = new Set<string>();
  const commandIds = new Set<string>();
  let lastCursor = 0;
  for (const operation of operations) {
    if (operationIds.has(operation.operationId) || commandIds.has(operation.commandId))
      throw new TypeError();
    operationIds.add(operation.operationId);
    commandIds.add(operation.commandId);
    if (operation.status === "complete") {
      const numericCursor = Number(operation.cursor);
      if (!Number.isSafeInteger(numericCursor) || numericCursor <= lastCursor)
        throw new TypeError();
      lastCursor = numericCursor;
    }
  }
  if (nextCursor <= lastCursor) throw new TypeError();
  return Object.freeze({
    version: 1,
    configurationDigest,
    nextCursor,
    operations: Object.freeze(operations),
  });
}

function snapshotOperation(value: unknown): DaytonaSupervisorOperation {
  if (typeof value !== "object" || value === null) throw new TypeError();
  const record = exactRecord(value, Reflect.ownKeys(value) as string[]);
  const status = field(record, "status");
  const common = {
    operationId: safeReference(field(record, "operationId")),
    commandId: safeReference(field(record, "commandId")),
    commandDigest: digest(field(record, "commandDigest")),
  };
  if (status === "dispatching") {
    exactFields(record, ["status", "operationId", "commandId", "commandDigest"]);
    return Object.freeze({ status, ...common });
  }
  if (status !== "complete") throw new TypeError();
  exactFields(record, [
    "status",
    "operationId",
    "commandId",
    "commandDigest",
    "cursor",
    "observationDigest",
    "receipt",
    "observation",
    "attestations",
  ]);
  const observation = snapshotObservation(field(record, "observation"));
  const attestations = snapshotAttestations(field(record, "attestations"));
  const cursor = cursorValue(field(record, "cursor"));
  if (
    observationCursor(observation) !== cursor ||
    !sameDigest(observationClaimsDigest(observation), field(record, "observationDigest"))
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    status,
    ...common,
    cursor,
    observationDigest: digest(field(record, "observationDigest")),
    receipt: snapshotRuntimeSupervisorPortableData(field(record, "receipt")) as
      | RuntimeReceipt
      | RuntimeCompensationReceipt,
    observation,
    attestations,
  });
}

function snapshotIsolationRequest(value: unknown): DaytonaSupervisorIsolationRequest {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "providerSandboxId",
    "plan",
    "artifactDigest",
    "sandboxUser",
    "trust",
  ]);
  return Object.freeze({
    providerSandboxId: safeReference(field(record, "providerSandboxId")),
    plan: snapshotRuntimeSupervisorPortableData(
      field(record, "plan")
    ) as DaytonaSupervisorIsolationRequest["plan"],
    artifactDigest: digest(field(record, "artifactDigest")),
    sandboxUser: safeReference(field(record, "sandboxUser")),
    trust: snapshotIsolationTrust(field(record, "trust")),
  });
}

function snapshotProtocolRequest<T>(snapshot: () => T): T {
  try {
    return snapshot();
  } catch (error) {
    if (error instanceof DaytonaSupervisorProtocolError && error.code === "invalid-request") {
      throw error;
    }
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
}

function snapshotCommandRequest(value: unknown): DaytonaSupervisorReceiptBackedCommandRequest {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "providerSandboxId",
    "operationId",
    "commandId",
    "commandDigest",
    "command",
    "expectedRevision",
    "trust",
  ]);
  const command = field(record, "command");
  if (!isReceiptBackedCommand(command)) throw new DaytonaSupervisorProtocolError("invalid-request");
  return Object.freeze({
    providerSandboxId: safeReference(field(record, "providerSandboxId")),
    operationId: safeReference(field(record, "operationId")),
    commandId: safeReference(field(record, "commandId")),
    commandDigest: digest(field(record, "commandDigest")),
    command,
    expectedRevision: positiveInteger(field(record, "expectedRevision")),
    trust: snapshotCommandTrust(field(record, "trust")),
  });
}

function snapshotFollowRequest(value: unknown): DaytonaSupervisorFollowRequest {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "providerSandboxId",
    "expectedRevision",
    "checkpoint",
    "trust",
  ]);
  return Object.freeze({
    providerSandboxId: safeReference(field(record, "providerSandboxId")),
    expectedRevision: positiveInteger(field(record, "expectedRevision")),
    checkpoint: snapshotCheckpoint(field(record, "checkpoint")),
    trust: snapshotIsolationTrust(field(record, "trust")),
  });
}

function snapshotEffectResult(value: unknown): DaytonaSupervisorEffectExecutionResult {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, ["receipt", "attestations"]);
  return Object.freeze({
    receipt: field(record, "receipt"),
    attestations: snapshotAttestations(field(record, "attestations")),
  });
}

function snapshotAttestations(value: unknown): readonly unknown[] {
  if (!Array.isArray(value) || value.length > 64) throw new TypeError();
  return Object.freeze(
    value.map((attestation) => snapshotRuntimeSupervisorPortableData(attestation))
  );
}

function snapshotCommandTrust(value: unknown): DaytonaSupervisorCommandRequest["trust"] {
  const record = exactRecord(value, [
    "supervisorArtifactDigest",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
    "requiredEffectEnforcerSetDigest",
  ]);
  return Object.freeze({
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    observationIssuerKeyId: safeReference(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
    requiredEffectEnforcerSetDigest: digest(field(record, "requiredEffectEnforcerSetDigest")),
  });
}

function snapshotIsolationTrust(value: unknown): DaytonaSupervisorIsolationRequest["trust"] {
  const record = exactRecord(value, [
    "supervisorArtifactDigest",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
  ]);
  return Object.freeze({
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    observationIssuerKeyId: safeReference(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
  });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRecord(value, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function findOperation(
  state: DaytonaSupervisorState,
  operationId: string,
  commandId: string
): DaytonaSupervisorOperation | null {
  const byOperation = state.operations.find((operation) => operation.operationId === operationId);
  const byCommand = state.operations.find((operation) => operation.commandId === commandId);
  if (byOperation && byCommand && byOperation !== byCommand) {
    throw new DaytonaSupervisorProtocolError("conflict");
  }
  return byOperation ?? byCommand ?? null;
}

function assertReplayMatches(
  operation: DaytonaSupervisorOperation,
  request: DaytonaSupervisorReceiptBackedCommandRequest
): void {
  if (
    operation.operationId !== request.operationId ||
    operation.commandId !== request.commandId ||
    !sameDigest(operation.commandDigest, request.commandDigest)
  ) {
    throw new DaytonaSupervisorProtocolError("conflict");
  }
}

function outcomeFrom(
  operation: DaytonaSupervisorCompletedOperation
): DaytonaSupervisorCommandOutcome {
  return Object.freeze({
    commandId: operation.commandId,
    commandDigest: operation.commandDigest,
    receipt: operation.receipt,
    observation: operation.observation,
    attestations: operation.attestations,
  });
}

function lastCheckpoint(
  state: DaytonaSupervisorState
): { readonly cursor: string; readonly observationDigest: string } | null {
  const completed = state.operations.filter(
    (operation): operation is DaytonaSupervisorCompletedOperation => operation.status === "complete"
  );
  const last = completed.at(-1);
  return last === undefined
    ? null
    : Object.freeze({ cursor: last.cursor, observationDigest: last.observationDigest });
}

function snapshotCheckpoint(
  value: unknown
): { readonly cursor: string; readonly observationDigest: string } | null {
  if (value === null) return null;
  const record = exactRecord(value, ["cursor", "observationDigest"]);
  return Object.freeze({
    cursor: cursorValue(field(record, "cursor")),
    observationDigest: digest(field(record, "observationDigest")),
  });
}

function snapshotObservation(value: unknown): unknown {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "version",
    "kind",
    "observationId",
    "cursor",
    "previous",
    "observedAtMs",
    "command",
    "receipt",
    "receiptDigest",
    "authority",
  ]);
  if (
    field(record, "version") !== 1 ||
    (field(record, "kind") !== "runtime.lifecycle-receipt-observed" &&
      field(record, "kind") !== "runtime.compensation-receipt-observed")
  ) {
    throw new TypeError();
  }
  cursorValue(field(record, "cursor"));
  observationClaimsDigest(snapshot);
  return snapshot;
}

function observationCursor(value: unknown): string {
  return cursorValue(
    field(exactRecord(value, Reflect.ownKeys(value as object) as string[]), "cursor")
  );
}

function observationClaimsDigest(value: unknown): string {
  const record = exactRecord(value, Reflect.ownKeys(value as object) as string[]);
  const authority = exactRecord(field(record, "authority"), [
    "issuer",
    "issuerKeyId",
    "audience",
    "capability",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  return digest(field(authority, "claimsDigest"));
}

function requireEnforced(receipt: RuntimeReceipt | RuntimeCompensationReceipt): void {
  const effective = receipt.outcome === "duplicate" ? receipt.originalReceipt : receipt;
  if (effective.outcome !== "enforced" || effective.aggregateEnforcementProof === undefined) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function isReceiptBackedCommand(
  value: unknown
): value is RuntimeLifecycleCommand | RuntimeCompensationCommand {
  if (typeof value !== "object" || value === null) return false;
  const descriptor = Object.getOwnPropertyDescriptor(value, "kind");
  return (
    descriptor !== undefined &&
    "value" in descriptor &&
    typeof descriptor.value === "string" &&
    (LIFECYCLE_KINDS.has(descriptor.value) || descriptor.value === "safety.quarantine")
  );
}

function isCompensationCommand(command: RuntimeCommand): command is RuntimeCompensationCommand {
  return command.kind === "safety.quarantine";
}

function hostedCommandDigest(command: RuntimeCommand): string {
  return sha256(`${HOSTED_COMMAND_DIGEST_DOMAIN}${canonicalRuntimeJson(command)}`);
}

function planDigest(plan: DaytonaSupervisorIsolationRequest["plan"]): string {
  return sha256(`${HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN}${canonicalRuntimeJson(plan)}`);
}

function providerIdentityCommitment(providerSandboxId: string): string {
  return sha256(`${PROVIDER_IDENTITY_DIGEST_DOMAIN}${safeReference(providerSandboxId)}`);
}

function formatCursor(value: number): string {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError();
  const cursor = String(value).padStart(20, "0");
  return cursorValue(cursor);
}

function cursorValue(value: unknown): string {
  if (typeof value !== "string" || !CURSOR.test(value)) throw new TypeError();
  return value;
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return canonicalRuntimeJson(left) === canonicalRuntimeJson(right);
}

function sameDigest(left: unknown, right: unknown): boolean {
  if (
    typeof left !== "string" ||
    typeof right !== "string" ||
    !SHA256.test(left) ||
    !SHA256.test(right)
  ) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function assertProviderIdentifierAbsent(value: unknown, providerSandboxId: string): void {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (typeof current === "string" && current.includes(providerSandboxId)) {
      throw new DaytonaSupervisorProtocolError("internal");
    }
    if (Array.isArray(current)) {
      stack.push(...current);
    } else if (typeof current === "object" && current !== null) {
      for (const key of Reflect.ownKeys(current)) {
        if (typeof key !== "string") throw new DaytonaSupervisorProtocolError("internal");
        if (key.includes(providerSandboxId)) {
          throw new DaytonaSupervisorProtocolError("internal");
        }
        const descriptor = Object.getOwnPropertyDescriptor(current, key);
        if (!descriptor || !("value" in descriptor)) {
          throw new DaytonaSupervisorProtocolError("internal");
        }
        stack.push(descriptor.value);
      }
    }
  }
}

function captureFunction(value: unknown): AnyFunction {
  if (typeof value !== "function" || nodeTypes.isProxy(value)) throw new TypeError();
  return value as AnyFunction;
}

function captureMethod(value: unknown, name: string): CapturedMethod {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    throw new TypeError();
  const receiver = value;
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) break;
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) break;
      return Object.freeze({ receiver, method: captureFunction(descriptor.value) });
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new TypeError();
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of fields) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function exactFields(record: Record<string, unknown>, fields: readonly string[]): void {
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    throw new TypeError();
  }
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new TypeError();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

function sampleClock(clock: () => number): number {
  let value: unknown;
  try {
    value = clock();
  } catch {
    throw new DaytonaSupervisorProtocolError("internal");
  }
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new DaytonaSupervisorProtocolError("internal");
  }
  return value as number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function suppressPromise(value: unknown): void {
  if (nodeTypes.isPromise(value)) void (value as Promise<unknown>).catch(() => undefined);
}
