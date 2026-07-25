import { isAbsolute, join, normalize } from "node:path";
import type Database from "better-sqlite3";
import {
  BROKER_SOCKET_FILE,
  BROKER_PROXY_SOCKET_FILE,
} from "../../../packages/secret-broker/src/broker-root";
import { createSecretBrokerClient, type SecretBrokerClient } from "./secret-broker-client";
import { createCredentialProxyClient, type CredentialProxyClient } from "./credential-proxy-client";
import {
  createBrokerReceiptVerifier,
  readBrokerVerificationKey,
  type BrokerReceiptVerifier,
} from "./secret-broker-verifier";
import type { ProviderProofExpectation, VerifiedProviderIdentity } from "./authority";
import { verifyTelegramDeepLinkProof } from "./providers/telegram-adapter";
import { verifySlackOidcProof } from "./providers/slack-adapter";

export const SECRET_BROKER_ROOT_ENV = "TERMINALX_SECRET_BROKER_ROOT";
export const SECRET_BROKER_SOCKET_ENV = "TERMINALX_SECRET_BROKER_SOCKET";

/** The configured broker root, or null when no broker is composed (dev default). */
export function configuredSecretBrokerRoot(): string | null {
  const value = process.env[SECRET_BROKER_ROOT_ENV];
  if (typeof value !== "string" || value.length === 0) return null;
  if (!isAbsolute(value) || normalize(value) !== value) return null;
  return value;
}

function configuredSocketPath(rootDir: string): string {
  const override = process.env[SECRET_BROKER_SOCKET_ENV];
  if (typeof override === "string" && override.length > 0) {
    if (!isAbsolute(override) || normalize(override) !== override)
      return join(rootDir, BROKER_SOCKET_FILE);
    return override;
  }
  return join(rootDir, BROKER_SOCKET_FILE);
}

/**
 * Build the synchronous, local receipt verifier from the broker's published
 * verification key. Returns null when no broker is configured or its key is not
 * yet available, so the connection authority keeps failing closed exactly as it
 * does today without a verifier.
 */
export function resolveConfiguredBrokerReceiptVerifier(): BrokerReceiptVerifier | null {
  const rootDir = configuredSecretBrokerRoot();
  if (!rootDir) return null;
  const verificationPublicKey = readBrokerVerificationKey(rootDir);
  if (!verificationPublicKey) return null;
  return createBrokerReceiptVerifier({ verificationPublicKey });
}

/**
 * Build the synchronous, provider-dispatching `verifyProviderProof` for
 * completing identity Link Challenges. It routes on the authority-built
 * `expected.provider` to the Telegram deep-link verifier (proof produced by the
 * authenticated webhook) and the Slack OIDC verifier (proof produced by the
 * in-broker id_token verification in the callback route). Both verifiers are
 * pure and synchronous — the network work (secret-token check, JWKS/id_token
 * verification) already happened upstream — so this is safe to call inside the
 * authority's SQLite transaction. Any provider outside the closed set returns
 * null.
 *
 * Returns null when no Secret Broker is configured, so link completion keeps
 * failing closed exactly as it does today: without a broker there is no active
 * installation credential handle to link against, and the authority also refuses
 * completion when this verifier is absent.
 */
export function resolveConfiguredProviderProofVerifier():
  | ((input: {
      proof: unknown;
      expected: Readonly<ProviderProofExpectation>;
    }) => VerifiedProviderIdentity | null)
  | null {
  if (!configuredSecretBrokerRoot()) return null;
  return ({ proof, expected }) => {
    switch (expected.provider) {
      case "telegram":
        return verifyTelegramDeepLinkProof({ proof, expected });
      case "slack":
        return verifySlackOidcProof({ proof, expected });
      default:
        return null;
    }
  };
}

/** Build the broker socket client, or null when no broker is configured. */
export function resolveConfiguredSecretBrokerClient(): SecretBrokerClient | null {
  const rootDir = configuredSecretBrokerRoot();
  if (!rootDir) return null;
  return createSecretBrokerClient({ socketPath: configuredSocketPath(rootDir) });
}

function configuredProxySocketPath(rootDir: string): string {
  return join(rootDir, BROKER_PROXY_SOCKET_FILE);
}

/**
 * Build the Credential Proxy socket client, or null when no broker is
 * configured. No caller migrates onto this in Slice 8D — it is composed for
 * Slice 8E provider adapters. It is never exposed to a browser HTTP route.
 */
export function resolveConfiguredCredentialProxyClient(): CredentialProxyClient | null {
  const rootDir = configuredSecretBrokerRoot();
  if (!rootDir) return null;
  return createCredentialProxyClient({ socketPath: configuredProxySocketPath(rootDir) });
}

/**
 * Startup gate for the production server. When a Secret Broker is configured it
 * must have published its verification key before any connection surface is
 * served; otherwise startup fails closed rather than exposing a half-composed
 * credential boundary. When no broker is configured this is a no-op and the
 * connection APIs keep failing closed as they do in local development.
 */
export function assertConfiguredSecretBrokerReady(): void {
  const rootDir = configuredSecretBrokerRoot();
  if (!rootDir) return;
  if (!readBrokerVerificationKey(rootDir)) {
    throw new Error(
      "Secret Broker is configured but its verification key is unavailable; refusing to start."
    );
  }
}

/** Read-only check the reconciler uses to detect a committed authority handle. */
export function credentialHandleCommitted(db: Database.Database, handleId: string): boolean {
  const row = db.prepare("SELECT 1 AS present FROM credential_handles WHERE id = ?").get(handleId);
  return row !== undefined;
}
