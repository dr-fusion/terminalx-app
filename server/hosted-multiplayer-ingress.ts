import { IncomingMessage } from "node:http";
import { Duplex } from "node:stream";
import { types as nodeTypes } from "node:util";
import type { RequestActor, RequestHeaders } from "../src/lib/request-actor";
import type {
  HostedMultiplayerIngress,
  HostedMultiplayerIngressContext,
} from "../src/lib/runtime/hosted-multiplayer-service";
import { createTeamSessionTerminalGateway } from "../src/lib/team-session-terminal-gateway";
import {
  createTeamSessionWebSockets,
  type CanonicalTerminalPtyAdapter,
  type TeamSessionWebSockets,
} from "./team-session-websockets";

const DEFAULT_SHELL_SENTINEL = "/bin/false";

type AnyFunction = (...args: unknown[]) => unknown;

export interface CreateHostedMultiplayerIngressOptions {
  readonly resolveActor?: (headers: RequestHeaders) => Promise<RequestActor | null>;
  readonly credentialCheckIntervalMs?: number;
  readonly eventPollIntervalMs?: number;
  readonly monitorPollIntervalMs?: number;
  readonly reportInternalError?: (errorName: string) => void;
}

/** Stable ingress failure; no request, provider, or dependency details are attached. */
export class HostedMultiplayerIngressError extends Error {
  constructor() {
    super("Hosted multiplayer ingress unavailable");
    this.name = "HostedMultiplayerIngressError";
  }
}

class HostedMultiplayerIngressImpl implements HostedMultiplayerIngress {
  private readonly options: CreateHostedMultiplayerIngressOptions;
  private webSockets: TeamSessionWebSockets | null = null;
  private lifetimeSignal: AbortSignal | null = null;
  private started = false;
  private closing = false;
  private closePromise: Promise<void> | null = null;

  constructor(options: CreateHostedMultiplayerIngressOptions) {
    this.options = snapshotOptions(options);
  }

  async start(
    contextValue: HostedMultiplayerIngressContext,
    signalValue: AbortSignal
  ): Promise<void> {
    if (this.started || this.closing) unavailable();
    const context = exactDataRecord(contextValue, [
      "teamSessions",
      "hostedAssignmentPlans",
      "hostedTerminal",
      "isRuntimeWriteAllowed",
    ]);
    const signal = nativeAbortSignal(signalValue);
    if (signal.aborted) unavailable();
    const isRuntimeWriteAllowed = captureFunction(dataField(context, "isRuntimeWriteAllowed"));
    const terminalGateway = createTeamSessionTerminalGateway({
      teamSessions: dataField(
        context,
        "teamSessions"
      ) as HostedMultiplayerIngressContext["teamSessions"],
      hostedAssignmentPlans: dataField(
        context,
        "hostedAssignmentPlans"
      ) as HostedMultiplayerIngressContext["hostedAssignmentPlans"],
      monitorPollIntervalMs: this.options.monitorPollIntervalMs,
      isRuntimeWriteAllowed: (input) =>
        Reflect.apply(isRuntimeWriteAllowed, undefined, [input]) === true,
    });
    let webSockets: TeamSessionWebSockets;
    try {
      webSockets = createTeamSessionWebSockets({
        teamSessions: dataField(
          context,
          "teamSessions"
        ) as HostedMultiplayerIngressContext["teamSessions"],
        terminalGateway,
        pty: rejectingLocalPtyAdapter(),
        hostedTerminal: dataField(
          context,
          "hostedTerminal"
        ) as HostedMultiplayerIngressContext["hostedTerminal"],
        resolveTmuxSocketName: () => unavailable(),
        resolveTmuxSessionRef: () => unavailable(),
        shell: DEFAULT_SHELL_SENTINEL,
        ...(this.options.resolveActor ? { resolveActor: this.options.resolveActor } : {}),
        ...(this.options.credentialCheckIntervalMs === undefined
          ? {}
          : { credentialCheckIntervalMs: this.options.credentialCheckIntervalMs }),
        ...(this.options.eventPollIntervalMs === undefined
          ? {}
          : { eventPollIntervalMs: this.options.eventPollIntervalMs }),
        ...(this.options.reportInternalError
          ? { reportInternalError: this.options.reportInternalError }
          : {}),
      });
    } catch {
      unavailable();
    }
    this.webSockets = webSockets;
    this.lifetimeSignal = signal;
    this.started = true;
    signal.addEventListener(
      "abort",
      () => {
        void this.close().catch(() => undefined);
      },
      { once: true }
    );
    if (signal.aborted) {
      await this.close().catch(() => undefined);
      unavailable();
    }
  }

  readiness(): boolean {
    return (
      this.started &&
      !this.closing &&
      this.webSockets !== null &&
      this.lifetimeSignal?.aborted === false
    );
  }

  async handle(inputValue: unknown, signalValue: AbortSignal): Promise<boolean> {
    if (!this.readiness()) return false;
    let input: Record<string, unknown>;
    let signal: AbortSignal;
    try {
      input = exactDataRecord(inputValue, ["request", "socket", "head"]);
      signal = nativeAbortSignal(signalValue);
    } catch {
      return false;
    }
    if (signal !== this.lifetimeSignal || signal.aborted || !this.readiness()) {
      return false;
    }
    const request = dataField(input, "request");
    const socket = dataField(input, "socket");
    const unsafeHead = dataField(input, "head");
    if (
      !(request instanceof IncomingMessage) ||
      nodeTypes.isProxy(request) ||
      !(socket instanceof Duplex) ||
      nodeTypes.isProxy(socket) ||
      !(unsafeHead instanceof Uint8Array) ||
      nodeTypes.isProxy(unsafeHead) ||
      unsafeHead.byteLength > 64 * 1024
    ) {
      return false;
    }
    const webSockets = this.webSockets;
    if (!webSockets) return false;
    try {
      const handled = await webSockets.handleUpgrade(
        request,
        socket,
        Buffer.from(new Uint8Array(unsafeHead))
      );
      return handled && signal === this.lifetimeSignal && this.readiness();
    } catch {
      return false;
    }
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closing = true;
    const webSockets = this.webSockets;
    this.webSockets = null;
    const close = (async () => {
      if (webSockets !== null) {
        try {
          await webSockets.close();
        } catch {
          unavailable();
        }
      }
    })();
    this.closePromise = close;
    return close;
  }
}

/** Concrete hosted-only composition for canonical terminal and event WebSockets. */
export function createHostedMultiplayerIngress(
  options: CreateHostedMultiplayerIngressOptions = {}
): HostedMultiplayerIngress {
  const ingress = new HostedMultiplayerIngressImpl(options);
  return Object.freeze({
    start: (context: HostedMultiplayerIngressContext, signal: AbortSignal) =>
      ingress.start(context, signal),
    readiness: () => ingress.readiness(),
    handle: (input: unknown, signal: AbortSignal) => ingress.handle(input, signal),
    close: () => ingress.close(),
  });
}

function rejectingLocalPtyAdapter(): CanonicalTerminalPtyAdapter {
  return Object.freeze({
    create: () => unavailable(),
    write: () => unavailable(),
    resize: () => unavailable(),
    interrupt: () => unavailable(),
    destroy: () => undefined,
  });
}

function snapshotOptions(
  value: CreateHostedMultiplayerIngressOptions
): CreateHostedMultiplayerIngressOptions {
  const allowed = [
    "resolveActor",
    "credentialCheckIntervalMs",
    "eventPollIntervalMs",
    "monitorPollIntervalMs",
    "reportInternalError",
  ] as const;
  const record = safePlainRecord(value);
  const keys = Reflect.ownKeys(record);
  if (keys.some((key) => typeof key !== "string" || !allowed.includes(key as never))) unavailable();
  const resolveActor = optionalFunction(record, "resolveActor");
  const reportInternalError = optionalFunction(record, "reportInternalError");
  return Object.freeze({
    ...(resolveActor
      ? {
          resolveActor: resolveActor as NonNullable<
            CreateHostedMultiplayerIngressOptions["resolveActor"]
          >,
        }
      : {}),
    ...(reportInternalError
      ? {
          reportInternalError: reportInternalError as NonNullable<
            CreateHostedMultiplayerIngressOptions["reportInternalError"]
          >,
        }
      : {}),
    ...optionalInterval(record, "credentialCheckIntervalMs", 10, 2_000),
    ...optionalInterval(record, "eventPollIntervalMs", 10, 5_000),
    ...optionalInterval(record, "monitorPollIntervalMs", 10, 5_000),
  });
}

function optionalInterval(
  record: Record<string, unknown>,
  field: "credentialCheckIntervalMs" | "eventPollIntervalMs" | "monitorPollIntervalMs",
  minimum: number,
  maximum: number
): Partial<Record<typeof field, number>> {
  if (!Object.hasOwn(record, field)) return {};
  const value = dataField(record, field);
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    unavailable();
  }
  return { [field]: value as number };
}

function optionalFunction(record: Record<string, unknown>, field: string): AnyFunction | undefined {
  if (!Object.hasOwn(record, field)) return undefined;
  return captureFunction(dataField(record, field));
}

function exactDataRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const record = safePlainRecord(value);
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    unavailable();
  }
  for (const field of fields) dataField(record, field);
  return record;
}

function safePlainRecord(value: unknown): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    unavailable();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) unavailable();
  return value as Record<string, unknown>;
}

function dataField(record: Record<string, unknown>, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) unavailable();
  return descriptor.value;
}

function captureFunction(value: unknown): AnyFunction {
  if (typeof value !== "function" || nodeTypes.isProxy(value)) unavailable();
  return value as AnyFunction;
}

function nativeAbortSignal(value: unknown): AbortSignal {
  if (!(value instanceof AbortSignal) || nodeTypes.isProxy(value)) unavailable();
  return value;
}

function unavailable(): never {
  throw new HostedMultiplayerIngressError();
}
