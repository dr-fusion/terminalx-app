import { join } from "node:path";
import { withConnectionDatabase as defaultWithConnectionDatabase } from "../identity-service";
import { configuredSecretBrokerRoot } from "./secret-broker-composition";
import { createProviderExchangeClient } from "./provider-exchange-client";
import { findActiveInstallationById } from "./read-model";
import {
  handleCompleteSlackOidcLink,
  type SlackOidcLinkDependencies,
  type SlackOidcLinkExpectation,
} from "./http";

const SLACK_OIDC_ISSUER = "https://slack.com";

/**
 * Production composition for the Sign in with Slack (OIDC) identity-link
 * callback (Slice 8E2/8F, decision 5). It resolves the broker exchange client
 * from the configured broker root and the per-installation OIDC expectation from
 * the connection read-model; when either is unavailable the handler fails closed.
 * The route stays thin and mirrors the installation Slack callback discipline.
 */
export async function handleSlackOidcLinkCallback(request: Request): Promise<Response> {
  const rootDir = configuredSecretBrokerRoot();
  const audience = process.env.TERMINALX_SLACK_CLIENT_ID?.trim();
  if (!rootDir || !audience) {
    return new Response(JSON.stringify({ error: { code: "connection-unavailable" } }), {
      status: 503,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
  const exchangeClient = createProviderExchangeClient({
    socketPath: join(rootDir, "broker.sock"),
  });
  const deps: SlackOidcLinkDependencies = {
    exchangeClient,
    resolveSlackOidcExpectation: ({ installationId }): SlackOidcLinkExpectation | null =>
      defaultWithConnectionDatabase((db) => {
        const installation = findActiveInstallationById(db, installationId, "slack");
        if (!installation) return null;
        return {
          expectedIssuer: SLACK_OIDC_ISSUER,
          expectedAudience: audience,
          expectedTenantId: installation.externalTenantId,
          expectedAppId: installation.externalAppId,
        };
      }),
  };
  return handleCompleteSlackOidcLink(request, deps);
}
