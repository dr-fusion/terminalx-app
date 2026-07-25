import { canonicalJson, domainSeparatedDigest } from "../../../packages/secret-broker/src/protocol";
import {
  boundedIdentifier,
  connectionProvider,
  credentialBrokerKind,
  credentialHandleUsage,
  positiveVersion,
  sha256Digest,
} from "./contracts";
import type { CredentialHandleRegistrationExpectation } from "./authority";

const EXPECTATION_DIGEST_DOMAIN = "terminalx/secret-broker-expectation/v1\0";

/**
 * Deterministic digest over the exact CredentialHandleRegistrationExpectation.
 * Both the prepare client and the receipt verifier compute it identically, so a
 * receipt issued for one authority target can never be replayed against another
 * provider, broker kind, usage, authority binding, or rotation linkage.
 */
export function secretBrokerExpectationDigest(
  expectation: Readonly<CredentialHandleRegistrationExpectation>
): string {
  return domainSeparatedDigest(EXPECTATION_DIGEST_DOMAIN, canonicalJson(normalize(expectation)));
}

function normalize(
  expectation: Readonly<CredentialHandleRegistrationExpectation>
): Record<string, unknown> {
  const provider = connectionProvider(expectation.provider);
  const brokerKind = credentialBrokerKind(expectation.brokerKind);
  const usage = credentialHandleUsage(expectation.usage);
  const binding = expectation.authorityBinding;
  let normalizedBinding: Record<string, unknown>;
  if (binding?.kind === "installation") {
    if (usage !== "installation") throw new TypeError("mismatched usage/binding");
    normalizedBinding = {
      kind: "installation",
      teamId: boundedIdentifier(binding.teamId, "Credential Handle Team ID", 300),
      externalTenantId: boundedIdentifier(binding.externalTenantId, "external tenant ID"),
      externalAppId: boundedIdentifier(binding.externalAppId, "external application ID"),
    };
  } else if (binding?.kind === "identity-connection") {
    if (usage !== "identity-connection") throw new TypeError("mismatched usage/binding");
    normalizedBinding = {
      kind: "identity-connection",
      userId: boundedIdentifier(binding.userId, "Credential Handle User ID", 300),
      installationId: boundedIdentifier(
        binding.installationId,
        "Credential Handle Installation ID",
        300
      ),
      installationRevision: positiveVersion(
        binding.installationRevision,
        "Credential Handle Installation revision"
      ),
      externalTenantId: boundedIdentifier(binding.externalTenantId, "external tenant ID"),
      externalSubject: boundedIdentifier(binding.externalSubject, "external provider subject"),
      providerProofReplayDigest: sha256Digest(
        binding.providerProofReplayDigest,
        "provider proof replay digest"
      ),
    };
  } else {
    throw new TypeError("Credential Handle authority binding is invalid");
  }
  const replaces =
    expectation.replaces === null
      ? null
      : {
          handleId: boundedIdentifier(
            expectation.replaces.handleId,
            "replaced Credential Handle ID",
            300
          ),
          generation: positiveVersion(
            expectation.replaces.generation,
            "replaced Credential Handle generation"
          ),
        };
  return { schema: 1, provider, brokerKind, usage, authorityBinding: normalizedBinding, replaces };
}
