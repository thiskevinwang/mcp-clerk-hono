import { TokenType, verifyMachineAuthToken } from "@clerk/backend/internal";
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

type ClerkAuthProviderOptions = {
  secretKey: string;
  apiUrl?: string;
};

export class ClerkAuthProvider implements OAuthTokenVerifier {
  private readonly secretKey: string;
  private readonly apiUrl?: string;

  constructor({ secretKey, apiUrl }: ClerkAuthProviderOptions) {
    if (!secretKey) {
      throw new Error("CLERK_SECRET_KEY is required");
    }

    this.secretKey = secretKey;
    this.apiUrl = apiUrl;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const result = await verifyMachineAuthToken(token, {
        secretKey: this.secretKey,
        apiUrl: this.apiUrl,
      });

      if (result.errors || result.tokenType !== TokenType.OAuthToken || !result.data) {
        throw invalidToken();
      }

      const verified = result.data;
      if (
        !("clientId" in verified) ||
        verified.revoked ||
        verified.expired ||
        verified.expiration === null ||
        !verified.clientId ||
        !verified.subject
      ) {
        throw invalidToken();
      }

      return {
        token,
        clientId: verified.clientId,
        scopes: verified.scopes,
        expiresAt: Math.floor(verified.expiration / 1000),
        extra: {
          userId: verified.subject,
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

export function tokenVerifier(bindings: AuthBindings, _resourceServerUrl: URL): OAuthTokenVerifier {
  return new ClerkAuthProvider({
    secretKey: requiredBinding(bindings.CLERK_SECRET_KEY, "CLERK_SECRET_KEY"),
    apiUrl: bindings.CLERK_API_URL,
  });
}

export async function serveOAuthMetadata(
  bindings: AuthBindings,
  {
    request,
    resourceServerUrl,
    resourceName,
    serviceDocumentationUrl,
    scopesSupported,
    fetchFn = fetch,
  }: ServeOAuthMetadataOptions,
): Promise<Response | undefined> {
  const oauthMetadata = await fetchAuthorizationServerMetadata(
    requiredBinding(bindings.CLERK_PUBLISHABLE_KEY, "CLERK_PUBLISHABLE_KEY"),
    bindings.CLERK_FAPI_URL,
    fetchFn,
  );

  return oauthMetadataResponse(request, {
    oauthMetadata,
    resourceServerUrl,
    resourceName,
    serviceDocumentationUrl,
    scopesSupported,
  });
}

async function fetchAuthorizationServerMetadata(
  publishableKey: string,
  fapiUrl: string | undefined,
  fetchFn: FetchLike,
): Promise<OAuthMetadata> {
  const publicFapiUrl = fapiUrlFromPublishableKey(publishableKey);
  const metadataBaseUrl = new URL(fapiUrl || publicFapiUrl);
  const metadataUrl = new URL("/.well-known/oauth-authorization-server", metadataBaseUrl);
  const headers = new Headers();

  if (metadataBaseUrl.origin !== publicFapiUrl.origin) {
    headers.set("X-Original-Host", publicFapiUrl.host);
  }

  const response = await fetchFn(metadataUrl, { headers });
  if (!response.ok) {
    throw new Error(
      `Unable to fetch Clerk OAuth metadata: ${response.status} ${response.statusText}`,
    );
  }

  return (await response.json()) as OAuthMetadata;
}

function fapiUrlFromPublishableKey(publishableKey: string) {
  const encodedFrontendApi = publishableKey
    .replace(/^pk_(test|live)_/, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const paddedFrontendApi = encodedFrontendApi.padEnd(
    Math.ceil(encodedFrontendApi.length / 4) * 4,
    "=",
  );
  const frontendApi = atob(paddedFrontendApi).replace(/\$$/, "");

  return new URL(`https://${frontendApi}`);
}

function requiredBinding(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function invalidToken() {
  return new OAuthError(OAuthErrorCode.InvalidToken, "Invalid or expired Clerk OAuth access token");
}
