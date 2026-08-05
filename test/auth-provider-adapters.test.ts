import { describe, expect, test } from "bun:test";

import type { FetchLike } from "@modelcontextprotocol/server";

import * as clerkAuthProvider from "../src/clerk-auth-provider";
import * as workosAuthProvider from "../src/workos-auth-provider";

const resourceServerUrl = new URL("https://mcp.example.com/mcp");
const metadataRequest = new Request(
  "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
);

describe("auth provider adapters", () => {
  test("Clerk owns token-verifier construction and metadata proxying", async () => {
    expect(() => clerkAuthProvider.tokenVerifier({}, resourceServerUrl)).toThrow(
      "CLERK_SECRET_KEY is required",
    );

    let originalHost: string | null = null;
    const fetchFn: FetchLike = async (url, init) => {
      expect(url.toString()).toBe("http://localhost:3001/.well-known/oauth-authorization-server");
      originalHost = new Headers(init?.headers).get("X-Original-Host");

      return Response.json({ issuer: "https://clerk.example.com" });
    };
    const frontendApi = btoa("clerk.example.com$")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const response = await clerkAuthProvider.serveOAuthMetadata(
      {
        CLERK_PUBLISHABLE_KEY: `pk_test_${frontendApi}`,
        CLERK_FAPI_URL: "http://localhost:3001",
      },
      {
        request: metadataRequest,
        resourceServerUrl,
        resourceName: "test-server",
        scopesSupported: ["openid", "tools/list"],
        fetchFn,
      },
    );

    expect(originalHost).toBe("clerk.example.com");
    expect(await response?.json()).toMatchObject({
      resource: resourceServerUrl.href,
      authorization_servers: ["https://clerk.example.com"],
      scopes_supported: ["openid", "tools/list"],
    });
  });

  test("WorkOS owns token-verifier construction and scope-free metadata", async () => {
    expect(() => workosAuthProvider.tokenVerifier({}, resourceServerUrl)).toThrow(
      "WORKOS_AUTHKIT_DOMAIN is required",
    );

    const issuer = "https://example.authkit.app";
    const fetchFn: FetchLike = async (url) => {
      expect(url.toString()).toBe(`${issuer}/.well-known/oauth-authorization-server`);
      return Response.json({ issuer });
    };

    const response = await workosAuthProvider.serveOAuthMetadata(
      { WORKOS_AUTHKIT_DOMAIN: issuer },
      {
        request: metadataRequest,
        resourceServerUrl,
        resourceName: "test-server",
        scopesSupported: ["offline_access"],
        fetchFn,
      },
    );
    const metadata = (await response?.json()) as Record<string, unknown>;

    expect(metadata).toMatchObject({
      resource: resourceServerUrl.href,
      authorization_servers: [issuer],
    });
    expect(metadata).not.toHaveProperty("scopes_supported");
  });
});
