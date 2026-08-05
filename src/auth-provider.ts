import type { FetchLike, OAuthTokenVerifier } from "@modelcontextprotocol/server";

export type AuthProviderName = "clerk" | "workos";

export type AuthBindings = {
  AUTH_PROVIDER?: AuthProviderName;
  CLERK_PUBLISHABLE_KEY?: string;
  CLERK_SECRET_KEY?: string;
  CLERK_API_URL?: string;
  CLERK_FAPI_URL?: string;
  WORKOS_AUTHKIT_DOMAIN?: string;
};

export type ServeOAuthMetadataOptions = {
  request: Request;
  resourceServerUrl: URL;
  resourceName: string;
  serviceDocumentationUrl?: URL;
  scopesSupported: string[];
  fetchFn?: FetchLike;
};

export type AuthProviderAdapter = {
  tokenVerifier(bindings: AuthBindings, resourceServerUrl: URL): OAuthTokenVerifier;
  serveOAuthMetadata(
    bindings: AuthBindings,
    options: ServeOAuthMetadataOptions,
  ): Promise<Response | undefined>;
};
