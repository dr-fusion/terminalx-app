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
export {
  createCredentialProxy,
  openCredentialProxyAccounting,
  type CredentialProxy,
  type CredentialProxyResult,
  type CredentialProxyAuditEvent,
  type CredentialResolver,
  type CreateCredentialProxyOptions,
} from "./proxy/credential-proxy";
export {
  CREDENTIAL_PROXY_OPERATIONS,
  CREDENTIAL_PROXY_ALLOWED_HOSTS,
  OperationInputError,
  type TypedProviderOperation,
  type ProxyProvider,
  type CredentialPlacement,
  type ProxyRequestPlan,
  type ProjectionOutcome,
} from "./proxy/operations";
export {
  createFetchProxyNetworkClient,
  ProxyNetworkError,
  type ProxyNetworkClient,
  type ProxyOutboundRequest,
  type ProxyNetworkResponse,
} from "./proxy/network-client";
export {
  openProxyAccountingStore,
  type ProxyAccountingStore,
  type ProxyAccountingRow,
  type ProxyAccountingInput,
} from "./proxy/accounting-store";
export {
  CREDENTIAL_PROXY_PROTOCOL_VERSION,
  CREDENTIAL_PROXY_METHODS,
  PROXY_ERROR_CODES,
  assertClosedProxyResponse,
  snapshotProxyExecuteRequest,
  snapshotProxyResult,
  isCredentialProxyMethod,
  type ProxyResult,
  type CredentialProxyMethod,
  type ProxyResultClass,
  type ProxyErrorCode,
  type ProxyExecuteRequest,
  type ProxyAuthoritySnapshot,
} from "./proxy/proxy-protocol";
export {
  runCredentialProxyConnection,
  type CredentialProxyRequest,
  type CredentialProxyRequestHandler,
} from "./proxy/proxy-transport";
export { BROKER_PROXY_SOCKET_FILE, BROKER_PROXY_ACCOUNTING_FILE } from "./broker-root";
