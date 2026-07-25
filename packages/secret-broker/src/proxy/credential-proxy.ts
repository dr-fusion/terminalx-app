import {
  canonicalJson,
  domainSeparatedDigest,
  sameDigest,
  SecretBrokerProtocolError,
} from "../protocol";
import type { SecretBrokerStateStore } from "../state-store";
import {
  openProxyAccountingStore,
  type ProxyAccountingInput,
  type ProxyAccountingStore,
} from "./accounting-store";
import {
  CREDENTIAL_PROXY_OPERATIONS,
  OperationInputError,
  type CredentialPlacement,
  type ProxyRequestPlan,
  type TypedProviderOperation,
} from "./operations";
import {
  ProxyNetworkError,
  type ProxyNetworkClient,
  type ProxyOutboundRequest,
} from "./network-client";
import {
  type ProxyAuthoritySnapshot,
  type ProxyErrorCode,
  type ProxyExecuteRequest,
  type ProxyResultClass,
  snapshotProxyExecuteRequest,
} from "./proxy-protocol";
import type { AssignmentEligibilityStore } from "./assignment-eligibility-store";

const AUTHORITY_DIGEST_DOMAIN = "terminalx/credential-proxy-authority-snapshot/v1\0";
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Reveal usable credential bytes for an `active` handle from its stored,
 * adapter-opaque material. Runs only inside the broker process. Returns `null`
 * when the broker kind holds no broker-local usable material (e.g. an external
 * reference), so the proxy fails closed with `unsupported-credential-kind`.
 */
export type CredentialResolver = (brokerKind: string, storedMaterial: Buffer) => Buffer | null;

export interface CredentialProxyAuditEvent {
  readonly action: "proxy.execute";
  readonly operation: string;
  readonly resultClass: ProxyResultClass;
  readonly errorCode: ProxyErrorCode | null;
  readonly ambiguous: boolean;
  /** Digest of the authority snapshot; never the raw identifiers. */
  readonly authoritySnapshotDigest: string;
}

export interface CreateCredentialProxyOptions {
  readonly store: SecretBrokerStateStore;
  readonly accounting: ProxyAccountingStore;
  readonly network: ProxyNetworkClient;
  readonly resolveCredential: CredentialResolver;
  readonly operations?: ReadonlyMap<string, TypedProviderOperation>;
  /** Resolve a destination host to a request origin (defaults to https://host). */
  readonly resolveOrigin?: (host: string) => string;
  readonly clock?: () => number;
  readonly requestTimeoutMs?: number;
  readonly audit?: (event: CredentialProxyAuditEvent) => void;
  /**
   * Slice 8F Runtime-Assignment-scoped eligibility. When present, a
   * `hosted-assignment` caller must pass the assignment generation-fence before
   * the credential is attached. Absent, hosted-assignment callers fail closed.
   */
  readonly assignmentEligibility?: AssignmentEligibilityStore;
}

export interface CredentialProxyResult {
  readonly operation: string;
  readonly provider: string;
  readonly destinationHost: string;
  readonly resultClass: ProxyResultClass;
  readonly ambiguous: boolean;
  readonly errorCode: ProxyErrorCode | null;
  readonly requestBytes: number;
  readonly responseBytes: number;
  readonly handleGeneration: number;
  readonly installationRevision: number;
  readonly bindingRevision: number | null;
  readonly startedAtMs: number;
  readonly completedAtMs: number;
  readonly accountingRowId: number;
  readonly projection: Record<string, unknown> | null;
}

export interface CredentialProxy {
  execute(params: unknown): Promise<CredentialProxyResult>;
  /** Connection-runner entry point: dispatches the single `proxy.execute` method. */
  handle(request: { readonly method: string; readonly params: unknown }): Promise<unknown>;
}

/**
 * The Credential Proxy: the destination-scoped effect boundary. For each typed
 * operation it revalidates the authority fences against broker-durable state,
 * resolves the credential inside this process, performs one bounded outbound
 * request, projects the response to the operation's allowlisted fields, and
 * durably accounts the call. Authorization headers and signing keys never leave
 * this boundary and never appear in any result, log, or error.
 */
export function createCredentialProxy(options: CreateCredentialProxyOptions): CredentialProxy {
  const operations = options.operations ?? CREDENTIAL_PROXY_OPERATIONS;
  const resolveOrigin = options.resolveOrigin ?? ((host: string) => `https://${host}`);
  const clock = options.clock ?? Date.now;
  const timeoutMs = options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new TypeError();
  }
  const audit = options.audit ?? ((): void => undefined);
  const { store, accounting, network, resolveCredential } = options;
  const assignmentEligibility = options.assignmentEligibility ?? null;

  const now = (): number => {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 0) throw new SecretBrokerProtocolError("internal");
    return value;
  };

  async function execute(params: unknown): Promise<CredentialProxyResult> {
    const request = snapshotProxyExecuteRequest(params);
    const startedAtMs = now();
    const digest = authoritySnapshotDigest(request);

    // A duplicate frame (same nonce) converges on the recorded outcome without
    // re-sending; a fresh retry always uses a fresh nonce and is a new row.
    const existing = accounting.getByOperationId(request.operationId);
    if (existing) {
      return finalize(existing.rowId, {
        operation: existing.operation,
        provider: existing.provider,
        destinationHost: existing.destinationHost,
        resultClass: existing.resultClass,
        ambiguous: existing.ambiguous,
        errorCode: existing.errorCode,
        requestBytes: existing.requestBytes,
        responseBytes: existing.responseBytes,
        request,
        startedAtMs: existing.startedAtMs,
        completedAtMs: existing.completedAtMs,
        projection: null,
        digest,
      });
    }

    const operation = operations.get(request.operation);
    if (!operation) {
      return deny(
        request,
        digest,
        startedAtMs,
        "unsupported-operation",
        "unknown",
        request.authority.provider
      );
    }
    if (operation.provider !== request.authority.provider) {
      return deny(
        request,
        digest,
        startedAtMs,
        "provider-mismatch",
        operation.destinationHost,
        operation.provider
      );
    }

    const row = store.getByHandleId(request.authority.handleId);
    if (!row || row.status !== "active") {
      return deny(
        request,
        digest,
        startedAtMs,
        "handle-inactive",
        operation.destinationHost,
        operation.provider
      );
    }
    if (row.provider !== operation.provider) {
      return deny(
        request,
        digest,
        startedAtMs,
        "provider-mismatch",
        operation.destinationHost,
        operation.provider
      );
    }
    if (!sameDigest(row.expectationDigest, request.authority.expectationDigest)) {
      return deny(
        request,
        digest,
        startedAtMs,
        "authority-mismatch",
        operation.destinationHost,
        operation.provider
      );
    }

    // Slice 8F: a hosted Run may exercise the handle only under the exact
    // Runtime Assignment identity, generation-fenced by the eligibility store.
    // Human-session callers (the 8E HTTP flows) are unfenced here.
    if (request.caller?.class === "hosted-assignment") {
      if (!assignmentEligibility) {
        return deny(
          request,
          digest,
          startedAtMs,
          "authority-mismatch",
          operation.destinationHost,
          operation.provider
        );
      }
      let outcome;
      try {
        outcome = assignmentEligibility.evaluate(
          {
            handleId: request.authority.handleId,
            runtimeAssignmentId: request.caller.runtimeAssignmentId,
            runtimeAssignmentGeneration: request.caller.runtimeAssignmentGeneration,
            sandboxIdentityDigest: request.caller.sandboxIdentityDigest,
          },
          startedAtMs
        );
      } catch {
        outcome = "denied-mismatch" as const;
      }
      if (outcome !== "eligible") {
        return deny(
          request,
          digest,
          startedAtMs,
          "authority-mismatch",
          operation.destinationHost,
          operation.provider
        );
      }
    }

    let plan: ProxyRequestPlan;
    try {
      plan = operation.plan(request.params);
    } catch (error) {
      const code: ProxyErrorCode =
        error instanceof OperationInputError ? error.code : "invalid-params";
      return deny(
        request,
        digest,
        startedAtMs,
        code,
        operation.destinationHost,
        operation.provider
      );
    }

    const storedMaterial = store.getActiveSecretMaterial(request.authority.handleId);
    if (!storedMaterial) {
      return deny(
        request,
        digest,
        startedAtMs,
        "handle-inactive",
        operation.destinationHost,
        operation.provider
      );
    }
    let credential: Buffer | null;
    try {
      credential = resolveCredential(row.brokerKind, storedMaterial);
    } catch {
      credential = null;
      return deny(
        request,
        digest,
        startedAtMs,
        "credential-unavailable",
        operation.destinationHost,
        operation.provider
      );
    } finally {
      storedMaterial.fill(0);
    }
    if (!credential) {
      return deny(
        request,
        digest,
        startedAtMs,
        "unsupported-credential-kind",
        operation.destinationHost,
        operation.provider
      );
    }

    const built = buildOutbound(operation, plan, credential, resolveOrigin, timeoutMs);
    const requestBytes = built.requestBytes;
    let response: { status: number; body: Buffer } | null = null;
    let networkError: ProxyNetworkError | null = null;
    try {
      response = await network.send(built.request);
    } catch (error) {
      if (error instanceof ProxyNetworkError) networkError = error;
      else networkError = new ProxyNetworkError("transport");
    } finally {
      credential.fill(0);
    }

    if (networkError) {
      const mapped = mapNetworkError(networkError.kind);
      return record(request, digest, operation.provider, operation.destinationHost, {
        resultClass: mapped.resultClass,
        errorCode: mapped.errorCode,
        ambiguous: mapped.ambiguous,
        requestBytes,
        responseBytes: 0,
        startedAtMs,
        projection: null,
      });
    }

    const okResponse = response as { status: number; body: Buffer };
    const outcome = operation.project({ status: okResponse.status, body: okResponse.body });
    const projection = assertProjectionClosed(operation, outcome.projection);
    return record(request, digest, operation.provider, operation.destinationHost, {
      resultClass: outcome.resultClass,
      errorCode: outcome.errorCode,
      ambiguous: false,
      requestBytes,
      responseBytes: okResponse.body.byteLength,
      startedAtMs,
      projection,
    });
  }

  function deny(
    request: ProxyExecuteRequest,
    digest: string,
    startedAtMs: number,
    errorCode: ProxyErrorCode,
    destinationHost: string,
    provider: string
  ): CredentialProxyResult {
    return record(request, digest, provider, destinationHost, {
      resultClass: "denied",
      errorCode,
      ambiguous: false,
      requestBytes: 0,
      responseBytes: 0,
      startedAtMs,
      projection: null,
    });
  }

  function record(
    request: ProxyExecuteRequest,
    digest: string,
    provider: string,
    destinationHost: string,
    outcome: {
      resultClass: ProxyResultClass;
      errorCode: ProxyErrorCode | null;
      ambiguous: boolean;
      requestBytes: number;
      responseBytes: number;
      startedAtMs: number;
      projection: Record<string, unknown> | null;
    }
  ): CredentialProxyResult {
    const completedAtMs = now();
    const input: ProxyAccountingInput = {
      operationId: request.operationId,
      provider,
      operation: request.operation,
      destinationHost,
      resultClass: outcome.resultClass,
      ambiguous: outcome.ambiguous,
      errorCode: outcome.errorCode,
      requestBytes: outcome.requestBytes,
      responseBytes: outcome.responseBytes,
      handleId: request.authority.handleId,
      handleGeneration: request.authority.handleGeneration,
      installationRevision: request.authority.installationRevision,
      bindingRevision: request.authority.bindingRevision,
      authoritySnapshotDigest: digest,
      startedAtMs: outcome.startedAtMs,
      completedAtMs,
    };
    const row = accounting.record(input);
    audit({
      action: "proxy.execute",
      operation: request.operation,
      resultClass: outcome.resultClass,
      errorCode: outcome.errorCode,
      ambiguous: outcome.ambiguous,
      authoritySnapshotDigest: digest,
    });
    return finalize(row.rowId, {
      operation: request.operation,
      provider,
      destinationHost,
      resultClass: outcome.resultClass,
      ambiguous: outcome.ambiguous,
      errorCode: outcome.errorCode,
      requestBytes: outcome.requestBytes,
      responseBytes: outcome.responseBytes,
      request,
      startedAtMs: outcome.startedAtMs,
      completedAtMs,
      projection: outcome.projection,
      digest,
    });
  }

  function finalize(
    accountingRowId: number,
    input: {
      operation: string;
      provider: string;
      destinationHost: string;
      resultClass: ProxyResultClass;
      ambiguous: boolean;
      errorCode: ProxyErrorCode | null;
      requestBytes: number;
      responseBytes: number;
      request: ProxyExecuteRequest;
      startedAtMs: number;
      completedAtMs: number;
      projection: Record<string, unknown> | null;
      digest: string;
    }
  ): CredentialProxyResult {
    return Object.freeze({
      operation: input.operation,
      provider: input.provider,
      destinationHost: input.destinationHost,
      resultClass: input.resultClass,
      ambiguous: input.ambiguous,
      errorCode: input.errorCode,
      requestBytes: input.requestBytes,
      responseBytes: input.responseBytes,
      handleGeneration: input.request.authority.handleGeneration,
      installationRevision: input.request.authority.installationRevision,
      bindingRevision: input.request.authority.bindingRevision,
      startedAtMs: input.startedAtMs,
      completedAtMs: input.completedAtMs,
      accountingRowId,
      projection: input.projection,
    });
  }

  return Object.freeze({
    execute,
    async handle(request: { method: string; params: unknown }): Promise<unknown> {
      if (request.method !== "proxy.execute") {
        throw new SecretBrokerProtocolError("invalid-request");
      }
      return execute(request.params);
    },
  });
}

interface BuiltOutbound {
  readonly request: ProxyOutboundRequest;
  readonly requestBytes: number;
}

/**
 * Attach the credential per the operation's placement and compute the accounted
 * request byte count, which excludes all credential bytes (the Telegram bot
 * token lives in the URL path; the Slack bearer lives in an excluded header).
 */
function buildOutbound(
  operation: TypedProviderOperation,
  plan: ProxyRequestPlan,
  credential: Buffer,
  resolveOrigin: (host: string) => string,
  timeoutMs: number
): BuiltOutbound {
  const token = credential.toString("utf8");
  const body = plan.jsonBody === null ? null : canonicalJson(plan.jsonBody);
  const bodyBytes = body === null ? 0 : Buffer.byteLength(body, "utf8");
  const accountingHeaders: Record<string, string> = {};
  const sendHeaders: Record<string, string> = {};
  if (body) {
    accountingHeaders["content-type"] = "application/json";
    sendHeaders["content-type"] = "application/json";
  }

  let path: string;
  const placement: CredentialPlacement = operation.credentialPlacement;
  if (placement === "telegram-bot-path") {
    path = `/bot${token}/${plan.pathSegments.join("/")}`;
  } else if (placement === "telegram-file-path") {
    path = `/file/bot${token}/${plan.pathSegments.join("/")}`;
  } else {
    // slack-bearer: the credential is an excluded Authorization header.
    path = `/${plan.pathSegments.join("/")}`;
    sendHeaders["authorization"] = `Bearer ${token}`;
  }

  const requestBytes =
    bodyBytes +
    Object.entries(accountingHeaders).reduce(
      (sum, [key, value]) => sum + Buffer.byteLength(key) + Buffer.byteLength(value),
      0
    );

  return {
    request: Object.freeze({
      method: plan.method,
      origin: resolveOrigin(operation.destinationHost),
      path,
      query: plan.query,
      headers: sendHeaders,
      body,
      maxResponseBytes: plan.maxResponseBytes,
      timeoutMs,
    }),
    requestBytes,
  };
}

function mapNetworkError(kind: ProxyNetworkError["kind"]): {
  resultClass: ProxyResultClass;
  errorCode: ProxyErrorCode;
  ambiguous: boolean;
} {
  switch (kind) {
    case "timeout-after-send":
      return { resultClass: "retryable", errorCode: "timeout-ambiguous", ambiguous: true };
    case "timeout-before-response":
      return { resultClass: "retryable", errorCode: "timeout", ambiguous: false };
    case "response-too-large":
      return { resultClass: "denied", errorCode: "response-too-large", ambiguous: false };
    case "redirect":
      return { resultClass: "provider-error", errorCode: "provider-error", ambiguous: false };
    case "tls-required":
      return { resultClass: "denied", errorCode: "destination-denied", ambiguous: false };
    default:
      return { resultClass: "retryable", errorCode: "transport", ambiguous: false };
  }
}

function assertProjectionClosed(
  operation: TypedProviderOperation,
  projection: Record<string, unknown> | null
): Record<string, unknown> | null {
  if (projection === null) return null;
  for (const key of Object.keys(projection)) {
    if (!operation.projectionFields.includes(key)) {
      throw new SecretBrokerProtocolError("internal");
    }
  }
  return projection;
}

function authoritySnapshotDigest(request: ProxyExecuteRequest): string {
  const authority: ProxyAuthoritySnapshot = request.authority;
  return domainSeparatedDigest(
    AUTHORITY_DIGEST_DOMAIN,
    canonicalJson({
      operation: request.operation,
      provider: authority.provider,
      handleId: authority.handleId,
      handleGeneration: authority.handleGeneration,
      expectationDigest: authority.expectationDigest,
      installationId: authority.installationId,
      installationRevision: authority.installationRevision,
      bindingId: authority.bindingId,
      bindingRevision: authority.bindingRevision,
    })
  );
}

/** Convenience constructor for the daemon: opens the accounting store at `path`. */
export function openCredentialProxyAccounting(databasePath: string): ProxyAccountingStore {
  return openProxyAccountingStore({ databasePath });
}
