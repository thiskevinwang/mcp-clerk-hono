import { TokenType, verifyMachineAuthToken } from "@clerk/backend/internal";
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier,
} from "@modelcontextprotocol/server";

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

function invalidToken() {
  return new OAuthError(OAuthErrorCode.InvalidToken, "Invalid or expired Clerk OAuth access token");
}
