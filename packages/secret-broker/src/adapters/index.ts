export type CredentialBrokerKind = "oauth-envelope" | "onepassword-connect";

export interface PreparedSecret {
  /** Adapter-opaque bytes the broker persists; never returned to any peer. */
  readonly material: Buffer;
}

/**
 * The single interface behind every approved secret manager. `prepare` durably
 * transforms caller-supplied secret material into broker-persistable bytes;
 * `destroy` performs any external cleanup when a registration is aborted or
 * revoked. Neither method has a return path that can carry secret material back
 * to the protocol layer — `PreparedSecret.material` is stored, never sent.
 */
export interface SecretManagerAdapter {
  readonly kind: CredentialBrokerKind;
  prepare(secretMaterial: Buffer): Promise<PreparedSecret>;
  destroy(material: Buffer): Promise<void>;
}

export type SecretManagerAdapterRegistry = Readonly<
  Partial<Record<CredentialBrokerKind, SecretManagerAdapter>>
>;
