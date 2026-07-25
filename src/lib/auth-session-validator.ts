import { isJwtIdentifierDigestActive } from "./auth";
import { getAuthMode, isEmailAllowed } from "./auth-config";
import type { Device } from "./mobile-auth/authority";

export type AuthenticationCredentialProvenance =
  | { provenance: "browser" }
  | { provenance: "paired-device"; id: string };

export interface StoredAuthenticationSessionSnapshot {
  canonicalUserId: string;
  canonicalUsername: string;
  provider: "local" | "google" | "password";
  credentialJtiDigest: string;
  credentialExpiresAtMs: number;
  device: AuthenticationCredentialProvenance;
}

interface StoredAuthenticationSessionValidatorDependencies {
  getDevice(deviceId: string): Device | null;
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

/** Build one fail-closed validator around the owning mobile-device authority. */
export function createStoredAuthenticationSessionValidator(
  dependencies: StoredAuthenticationSessionValidatorDependencies
): (snapshot: StoredAuthenticationSessionSnapshot) => boolean {
  return (snapshot): boolean => {
    try {
      if (!snapshot || typeof snapshot !== "object") return false;
      if (
        typeof snapshot.canonicalUserId !== "string" ||
        snapshot.canonicalUserId.length < 1 ||
        snapshot.canonicalUserId.length > 300 ||
        typeof snapshot.canonicalUsername !== "string" ||
        snapshot.canonicalUsername.length < 1 ||
        snapshot.canonicalUsername.length > 1024 ||
        (snapshot.provider !== "local" &&
          snapshot.provider !== "google" &&
          snapshot.provider !== "password") ||
        snapshot.provider !== getAuthMode() ||
        (snapshot.provider === "google" && !isEmailAllowed(snapshot.canonicalUsername)) ||
        !Number.isSafeInteger(snapshot.credentialExpiresAtMs) ||
        snapshot.credentialExpiresAtMs <= Date.now() ||
        !isJwtIdentifierDigestActive(snapshot.credentialJtiDigest)
      ) {
        return false;
      }

      const device = snapshot.device;
      if (!device || typeof device !== "object") return false;
      if (device.provenance === "browser") return exactKeys(device, ["provenance"]);
      if (
        device.provenance !== "paired-device" ||
        !exactKeys(device, ["id", "provenance"]) ||
        typeof device.id !== "string" ||
        device.id.length < 1 ||
        device.id.length > 300
      ) {
        return false;
      }
      const registered = dependencies.getDevice(device.id);
      return (
        registered !== null &&
        registered.userId === snapshot.canonicalUserId &&
        registered.revokedAt === null
      );
    } catch {
      return false;
    }
  };
}
