export {
  createSecretBroker,
  type CreateSecretBrokerOptions,
  type SecretBroker,
  type SecretBrokerAuditEvent,
} from "./broker";
export {
  establishBrokerRoot,
  type BrokerRootContext,
  BROKER_SOCKET_FILE,
  BROKER_DATABASE_FILE,
  BROKER_VERIFICATION_KEY_FILE,
} from "./broker-root";
export {
  openSecretBrokerStateStore,
  type SecretBrokerStateStore,
  type RegistrationRow,
  type RegistrationStatus,
} from "./state-store";
export {
  type SecretManagerAdapter,
  type SecretManagerAdapterRegistry,
  type CredentialBrokerKind,
  type PreparedSecret,
} from "./adapters";
export { createOauthEnvelopeAdapter } from "./adapters/oauth-envelope";
export {
  createOnePasswordConnectAdapter,
  createOnePasswordConnectHttpClient,
  type OnePasswordConnectClient,
  type OnePasswordItemRef,
} from "./adapters/onepassword-connect";
export {
  createPinnedPeerCredentialVerifier,
  assertAllowedPeer,
  type SecretBrokerPeerCredentialVerifier,
  type SecretBrokerPeerCredentials,
} from "./peer-credentials";
export { startSecretBrokerUnixServer, type SecretBrokerUnixServer } from "./unix-socket-transport";
export {
  runSecretBrokerConnection,
  type SecretBrokerRequest,
  type SecretBrokerRequestHandler,
} from "./ndjson";
export {
  signSecretBrokerReceipt,
  verifySecretBrokerReceipt,
  snapshotReceipt,
  snapshotReceiptPayload,
  SECRET_BROKER_RECEIPT_KIND,
  SECRET_BROKER_RECEIPT_SCHEMA,
  type SecretBrokerReceipt,
  type SecretBrokerReceiptPayload,
} from "./receipt-schema";
export {
  SECRET_BROKER_PROTOCOL_VERSION,
  SECRET_BROKER_METHODS,
  SecretBrokerProtocolError,
  assertClosedResponse,
  canonicalJson,
  type SecretBrokerMethod,
  type SecretBrokerProtocolErrorCode,
} from "./protocol";
export { sealAtRest, openAtRest, AT_REST_KEY_BYTES } from "./at-rest";
export { runSecretBrokerDaemon } from "./daemon";
