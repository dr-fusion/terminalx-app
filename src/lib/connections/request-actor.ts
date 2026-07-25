import type { RequestActor } from "../request-actor";
import type { ConnectionActorSnapshot } from "./contracts";

/**
 * Narrow a freshly verified HTTP actor into the snapshot accepted by the
 * connection authority. Auth-disabled and legacy credentials deliberately do
 * not have this shape, so they cannot register handles, install providers, or
 * issue Link Challenges.
 */
export function connectionActorSnapshot(actor: RequestActor): ConnectionActorSnapshot | null {
  const authentication = actor.authentication;
  if (!authentication) return null;
  return Object.freeze({
    userId: actor.userId,
    userGeneration: authentication.userGeneration,
    authProvider: authentication.provider,
    authSubject: authentication.subject,
    authIdentityGeneration: authentication.identityGeneration,
    ...(authentication.authenticatedAtMs !== undefined
      ? { authenticatedAtMs: authentication.authenticatedAtMs }
      : {}),
    credentialIssuedAtMs: authentication.credentialIssuedAtMs,
    credentialExpiresAtMs: authentication.credentialExpiresAtMs,
    credentialJtiDigest: authentication.credentialJtiDigest,
    device:
      authentication.device.provenance === "paired-device"
        ? {
            provenance: "paired-device" as const,
            id: authentication.device.id,
          }
        : { provenance: "browser" as const },
  });
}
