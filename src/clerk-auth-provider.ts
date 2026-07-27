import { createClerkClient, type ClerkClient } from "@clerk/backend";
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier,
} from "@modelcontextprotocol/server";

type ClerkAuthProviderOptions = {
  secretKey: string;
};

export class ClerkAuthProvider implements OAuthTokenVerifier {
  private readonly clerk: ClerkClient;

  constructor({ secretKey }: ClerkAuthProviderOptions) {
    if (!secretKey) {
      throw new Error("CLERK_SECRET_KEY is required");
    }

    this.clerk = createClerkClient({ secretKey });
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const verified = await this.clerk.idPOAuthAccessToken.verify(token);
      const runtimeVerified = verified as typeof verified & {
        client_id?: string;
      };
      const clientId = runtimeVerified.clientId || runtimeVerified.client_id;

      if (
        verified.revoked ||
        verified.expired ||
        verified.expiration === null ||
        !clientId ||
        !verified.subject
      ) {
        throw invalidToken();
      }

      return {
        token,
        clientId,
        scopes: verified.scopes,
        expiresAt: toEpochSeconds(verified.expiration),
        extra: {
          userId: verified.subject,
        },
      };
    } catch (error) {
      if (OAuthError.isInstance(error)) {
        throw error;
      }

      if (isRejectedTokenResponse(error)) {
        throw invalidToken();
      }

      throw error;
    }
  }
}

function invalidToken() {
  return new OAuthError(
    OAuthErrorCode.InvalidToken,
    "Invalid or expired Clerk OAuth access token",
  );
}

function isRejectedTokenResponse(error: unknown) {
  if (typeof error !== "object" || error === null || !("status" in error)) {
    return false;
  }

  const status = error.status;
  return status === 400 || status === 404 || status === 422;
}

function toEpochSeconds(expiration: number) {
  // Clerk's JWT resource uses milliseconds, while the access-token
  // verification endpoint can return a Unix timestamp in seconds.
  return expiration >= 100_000_000_000
    ? Math.floor(expiration / 1000)
    : Math.floor(expiration);
}
