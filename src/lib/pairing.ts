import { withMobileAuthAuthority } from "./identity-service";
import {
  PairingIssuanceLimitError,
  type ConsumedPairingCode,
  type CreatedPairingCode,
  type CreatePairingCodeInput,
  type PairingSourceAuthentication,
} from "./mobile-auth/authority";

export { PairingIssuanceLimitError };
export type {
  ConsumedPairingCode,
  CreatedPairingCode,
  CreatePairingCodeInput,
  PairingSourceAuthentication,
};

/**
 * Compatibility facade for callers. The deep mobile-auth module owns durable
 * limits, digest-only persistence, cleanup, and transactional publication.
 */
export async function createPairingCode(
  input: CreatePairingCodeInput
): Promise<CreatedPairingCode> {
  return withMobileAuthAuthority((authority) => authority.createPairingCode(input));
}

/** Unknown, expired, or previously consumed codes deliberately share null. */
export async function consumePairingCode(code: string): Promise<ConsumedPairingCode | null> {
  return withMobileAuthAuthority((authority) => authority.consumePairingCode(code));
}
