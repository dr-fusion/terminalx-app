/**
 * Attach a rejection observer only when `value` is a genuine Promise branded by
 * this realm. Calling the intrinsic directly never reads or invokes an
 * untrusted object's custom `then` property.
 */
export function suppressNativePromiseRejection(value: unknown): void {
  try {
    Reflect.apply(Promise.prototype.then, value, [undefined, () => undefined]);
  } catch {
    // Non-Promises (including custom thenables and Promise proxies) are rejected
    // by the intrinsic brand check without executing provider-controlled code.
  }
}
