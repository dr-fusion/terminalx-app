/** Portable action classes. Runtime may only reclassify an action to a stricter class. */
export type ActionClass = "local" | "scoped-external" | "protected" | "forbidden";

/** Millisecond duration encoded as an object so it cannot be confused with an instant. */
export interface Duration {
  readonly milliseconds: number;
}

/** Currency amount in minor units. Callers must not use binary floating-point major units. */
export interface Money {
  readonly currency: string;
  readonly minorUnits: number;
}

/**
 * Conservative resource accounting shared by manifests, grants, and usage ledgers.
 * Every field is explicit so implementations do not need provider-native payloads.
 */
export interface ResourceEffect {
  readonly wallClock: Duration;
  readonly modelTokens: number;
  readonly modelSpend: Money;
  readonly outboundBytes: number;
  readonly actionCounts: Readonly<Record<ActionClass, number>>;
}

/** Provider-independent identity and generation fences for one Runtime assignment. */
export interface RuntimeBinding {
  readonly teamId: string;
  readonly projectId: string;
  readonly sessionId: string;
  readonly runtimeAssignmentId: string;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxId: string;
  readonly sandboxGeneration: number;
  readonly runtimePrincipalId: string;
}
