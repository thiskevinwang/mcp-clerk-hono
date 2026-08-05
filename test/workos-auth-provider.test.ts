import { describe, expect, test } from "bun:test";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWTVerifyGetKey } from "jose";

import { WorkOSAuthProvider } from "../src/workos-auth-provider";

const issuer = "https://example.authkit.app";
const audience = "https://mcp.example.com/mcp";

async function signingFixture() {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.alg = "RS256";
  publicJwk.kid = "test-key";
  publicJwk.use = "sig";

  return {
    privateKey,
    jwks: createLocalJWKSet({ keys: [publicJwk] }) as JWTVerifyGetKey,
  };
}

async function tokenFor(
  privateKey: CryptoKey,
  claims: Record<string, unknown> = {},
  tokenAudience = audience,
) {
  return new SignJWT({
    sub: "user_123",
    sid: "app_consent_123",
    org_id: "org_123",
    scope: "openid profile",
    scp: ["profile", "email"],
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(issuer)
    .setAudience(tokenAudience)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("WorkOSAuthProvider", () => {
  test("verifies issuer, audience, signature, and maps WorkOS claims", async () => {
    const { privateKey, jwks } = await signingFixture();
    const token = await tokenFor(privateKey, { client_id: "client_123" });
    const provider = new WorkOSAuthProvider({ authKitDomain: issuer, audience, jwks });

    const authInfo = await provider.verifyAccessToken(token);

    expect(authInfo.clientId).toBe("client_123");
    expect(authInfo.scopes).toEqual(["openid", "profile", "email"]);
    expect(authInfo.resource?.href).toBe(audience);
    expect(authInfo.extra).toEqual({
      userId: "user_123",
      organizationId: "org_123",
      sessionId: "app_consent_123",
    });
  });

  test("uses the documented WorkOS consent id when client_id is absent", async () => {
    const { privateKey, jwks } = await signingFixture();
    const token = await tokenFor(privateKey);
    const provider = new WorkOSAuthProvider({ authKitDomain: issuer, audience, jwks });

    expect((await provider.verifyAccessToken(token)).clientId).toBe("app_consent_123");
  });

  test("rejects a token issued for another MCP resource", async () => {
    const { privateKey, jwks } = await signingFixture();
    const token = await tokenFor(privateKey, {}, "https://other.example.com/mcp");
    const provider = new WorkOSAuthProvider({ authKitDomain: issuer, audience, jwks });

    await expect(provider.verifyAccessToken(token)).rejects.toMatchObject({
      code: "invalid_token",
    });
  });
});
