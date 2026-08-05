import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import {
  OAuthError,
  OAuthErrorCode,
  oauthMetadataResponse,
  type AuthInfo,
  type FetchLike,
  type OAuthMetadata,
  type OAuthTokenVerifier,
} from "@modelcontextprotocol/server";

import type { AuthBindings, ServeOAuthMetadataOptions } from "./auth-provider";

type WorkOSAuthProviderOptions = {
  authKitDomain: string;
  audience: string | URL;
  jwks?: JWTVerifyGetKey;
};

const remoteJwksByIssuer = new Map<string, JWTVerifyGetKey>();

export class WorkOSAuthProvider implements OAuthTokenVerifier {
  private readonly audience: string;
  private readonly issuer: string;
  private readonly jwks: JWTVerifyGetKey;

  constructor({ authKitDomain, audience, jwks }: WorkOSAuthProviderOptions) {
    this.issuer = normalizeAuthKitDomain(authKitDomain);
    this.audience = normalizeAudience(audience);
    this.jwks = jwks ?? remoteJwksForIssuer(this.issuer);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.audience,
      });

      const clientId = clientIdFromPayload(payload);
      if (!payload.sub || !payload.exp || !clientId) {
        throw invalidToken();
      }

      return {
        token,
        clientId,
        scopes: scopesFromPayload(payload),
        expiresAt: payload.exp,
        resource: new URL(this.audience),
        extra: {
          userId: payload.sub,
          ...(typeof payload.org_id === "string" ? { organizationId: payload.org_id } : {}),
          ...(typeof payload.sid === "string" ? { sessionId: payload.sid } : {}),
        },
      };
    } catch (error) {
      if (OAuthError.isInstance(error)) {
        throw error;
      }

      throw invalidToken();
    }
  }
}

export function tokenVerifier(bindings: AuthBindings, resourceServerUrl: URL): OAuthTokenVerifier {
  return new WorkOSAuthProvider({
    authKitDomain: requiredBinding(bindings.WORKOS_AUTHKIT_DOMAIN, "WORKOS_AUTHKIT_DOMAIN"),
    audience: resourceServerUrl,
  });
}

export async function serveOAuthMetadata(
  bindings: AuthBindings,
  {
    request,
    resourceServerUrl,
    resourceName,
    serviceDocumentationUrl,
    fetchFn = fetch,
  }: ServeOAuthMetadataOptions,
): Promise<Response | undefined> {
  const issuer = normalizeAuthKitDomain(
    requiredBinding(bindings.WORKOS_AUTHKIT_DOMAIN, "WORKOS_AUTHKIT_DOMAIN"),
  );
  const oauthMetadata = await fetchAuthorizationServerMetadata(issuer, fetchFn);

  return oauthMetadataResponse(request, {
    oauthMetadata,
    resourceServerUrl,
    resourceName,
    serviceDocumentationUrl,
  });
}

async function fetchAuthorizationServerMetadata(
  issuer: string,
  fetchFn: FetchLike,
): Promise<OAuthMetadata> {
  const metadataUrl = new URL("/.well-known/oauth-authorization-server", issuer);
  const response = await fetchFn(metadataUrl);
  if (!response.ok) {
    throw new Error(
      `Unable to fetch WorkOS OAuth metadata: ${response.status} ${response.statusText}`,
    );
  }

  return (await response.json()) as OAuthMetadata;
}

function normalizeAuthKitDomain(authKitDomain: string): string {
  if (!authKitDomain) {
    throw new Error("WORKOS_AUTHKIT_DOMAIN is required");
  }

  const url = new URL(authKitDomain);
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("WORKOS_AUTHKIT_DOMAIN must be an HTTPS origin");
  }

  return url.origin;
}

function normalizeAudience(audience: string | URL): string {
  const url = new URL(audience);
  if (url.hash) {
    throw new Error("WorkOS token audience must not include a URL fragment");
  }

  return url.href;
}

function remoteJwksForIssuer(issuer: string): JWTVerifyGetKey {
  const cached = remoteJwksByIssuer.get(issuer);
  if (cached) {
    return cached;
  }

  const jwks = createRemoteJWKSet(new URL("/oauth2/jwks", issuer));
  remoteJwksByIssuer.set(issuer, jwks);
  return jwks;
}

function clientIdFromPayload(payload: JWTPayload): string | undefined {
  if (typeof payload.client_id === "string" && payload.client_id) {
    return payload.client_id;
  }

  if (typeof payload.azp === "string" && payload.azp) {
    return payload.azp;
  }

  // WorkOS documents `sid` as the application-consent identifier on OAuth
  // access tokens, while the MCP SDK requires a client-associated identifier.
  if (typeof payload.sid === "string" && payload.sid) {
    return payload.sid;
  }

  return undefined;
}

function scopesFromPayload(payload: JWTPayload): string[] {
  const scopes = new Set<string>();

  for (const claim of [payload.scope, payload.scp]) {
    if (typeof claim === "string") {
      for (const scope of claim.split(/\s+/)) {
        if (scope) {
          scopes.add(scope);
        }
      }
    } else if (Array.isArray(claim)) {
      for (const scope of claim) {
        if (typeof scope === "string" && scope) {
          scopes.add(scope);
        }
      }
    }
  }

  return [...scopes];
}

function requiredBinding(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function invalidToken() {
  return new OAuthError(OAuthErrorCode.InvalidToken, "Invalid or expired WorkOS access token");
}
