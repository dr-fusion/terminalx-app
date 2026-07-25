import { getDevice } from "./devices";
import {
  createStoredAuthenticationSessionValidator,
  type AuthenticationCredentialProvenance,
  type StoredAuthenticationSessionSnapshot,
} from "./auth-session-validator";

export type { AuthenticationCredentialProvenance, StoredAuthenticationSessionSnapshot };

const validateStoredAuthenticationSession = createStoredAuthenticationSessionValidator({
  getDevice,
});

/**
 * Revalidate a stored authentication-session snapshot immediately before a
 * high-trust operation completes. It deliberately accepts no raw JWT or JTI.
 * All malformed, stale, disabled, unreadable, or ambiguous state returns
 * false rather than throwing.
 */
export function isStoredAuthenticationSessionActive(
  snapshot: StoredAuthenticationSessionSnapshot
): boolean {
  return validateStoredAuthenticationSession(snapshot);
}
