import type { Context, Hono } from "hono";
import { createMcpHonoApp } from "@modelcontextprotocol/hono";
import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  McpServer,
  oauthMetadataResponse,
  requireBearerAuth,
  type OAuthMetadata,
} from "@modelcontextprotocol/server";

import * as z from "zod/v4";

import { ClerkAuthProvider } from "./clerk-auth-provider";

type Bindings = {
  CLERK_PUBLISHABLE_KEY: string;
  CLERK_SECRET_KEY: string;
  CLERK_API_URL?: string;
  CLERK_FAPI_URL?: string;
};

type AppEnv = {
  Bindings: Bindings;
  Variables: {
    /**
     * createMcpHonoApp installs JSON middleware that parses the request body and
     * stores it on the Hono context as "parsedBody".
     */
    parsedBody: unknown;
  };
};

type AppContext = Context<AppEnv>;

const SUPPORTED_SCOPES = [
  "openid",
  "profile",
  "email",
  "public_metadata",
  "offline_access",
  "private_metadata",
  "tools/list",
  "tools/call",
  "prompts/list",
  "prompts/get",
  // "notifications/initialized",
] as const;
type SupportedScope = (typeof SUPPORTED_SCOPES)[number];

const BASE_SCOPES: readonly SupportedScope[] = ["openid"];
const TOOL_SCOPES: Readonly<Record<string, readonly SupportedScope[]>> = {
  get_authenticated_user: ["profile"],
};

const app = createMcpHonoApp({ host: "localhost" }) as unknown as Hono<AppEnv>;

// body logger
app.use(async (c, next) => {
  console.log("request:", c.req.method, c.req.url, c.get("parsedBody"));
  await next();
});

app.get("/", (c) => {
  return c.json({
    name: "mcp-clerk-hono",
    message: "Clerk-protected Hono MCP server",
    mcp: "/mcp",
    oauthProtectedResourceMetadata: "/.well-known/oauth-protected-resource/mcp",
  });
});

app.all("/.well-known/oauth-protected-resource/mcp", serveOAuthMetadata);
app.all("/.well-known/oauth-authorization-server", serveOAuthMetadata);

function createServer() {
  const server = new McpServer({
    name: "mcp-clerk-hono",
    version: "0.1.0",
  });

  server.registerTool(
    "get_authenticated_user",
    {
      description: "Returns the Clerk auth details for the authenticated request.",
      inputSchema: z.object({}),
    },
    async (_, context) => {
      const { token: _token, ...safeAuthInfo } = context.http?.authInfo ?? {};

      return {
        content: [{ type: "text", text: JSON.stringify(safeAuthInfo) }],
      };
    },
  );
  server.registerPrompt(
    "review-code",
    {
      title: "Code Review",
      description: "Review code for best practices",
      argsSchema: z.object({ code: z.string() }),
    },
    ({ code }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Please review this code:\n\n${code}`,
          },
        },
      ],
    }),
  );

  return server;
}

const mcpHandler = createMcpHandler(() => createServer());

app.all("/mcp", async (c: AppContext) => {
  const parsedBody = c.get("parsedBody");
  const mcpServerUrl = new URL("/mcp", c.req.url);
  const auth = await requireBearerAuth({
    verifier: new ClerkAuthProvider({
      secretKey: c.env.CLERK_SECRET_KEY,
      apiUrl: c.env.CLERK_API_URL,
    }),
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
    requiredScopes: requiredScopesForRequest(parsedBody),
  })(c.req.raw);

  if (auth instanceof Response) {
    return auth;
  }

  return mcpHandler.fetch(c.req.raw, {
    authInfo: auth,
    parsedBody,
  });
});

import {
  isJSONRPCRequest,
  type ClientRequest,
  type ListPromptsRequest,
  type CallToolRequest,
  type ListToolsRequest,
} from "@modelcontextprotocol/server";

function isListToolsRequest(request: unknown): request is ListToolsRequest {
  return (
    isJSONRPCRequest(request as ClientRequest) && (request as ClientRequest).method === "tools/list"
  );
}

function isCallToolRequest(request: unknown): request is CallToolRequest {
  return (
    isJSONRPCRequest(request as ClientRequest) && (request as ClientRequest).method === "tools/call"
  );
}

function isListPromptsRequest(request: unknown): request is ListPromptsRequest {
  return (
    isJSONRPCRequest(request as ClientRequest) &&
    (request as ClientRequest).method === "prompts/list"
  );
}

function requiredScopesForRequest(body: unknown): string[] {
  const requiredScopes = new Set<string>(BASE_SCOPES);
  const messages = Array.isArray(body) ? body : [body];

  for (const message of messages) {
    if (isListToolsRequest(message)) {
      requiredScopes.add("tools/list");
    } else if (isListPromptsRequest(message)) {
      requiredScopes.add("prompts/list");
    } else if (isCallToolRequest(message)) {
      requiredScopes.add("tools/call");
    }

    if (!isRecord(message) || message.method !== "tools/call") {
      continue;
    }

    const params = message.params;
    if (!isRecord(params) || typeof params.name !== "string") {
      continue;
    }

    for (const scope of TOOL_SCOPES[params.name] ?? []) {
      requiredScopes.add(scope);
    }
  }

  return [...requiredScopes];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const clerkOAuthMetadata = new Map<string, Promise<OAuthMetadata>>();

async function serveOAuthMetadata(c: AppContext) {
  const mcpServerUrl = new URL("/mcp", c.req.url);
  const oauthMetadata = await getClerkOAuthMetadata(
    c.env.CLERK_PUBLISHABLE_KEY,
    c.env.CLERK_FAPI_URL,
  );

  return (
    oauthMetadataResponse(c.req.raw, {
      oauthMetadata,
      resourceServerUrl: mcpServerUrl,
      resourceName: "mcp-clerk-hono",
      serviceDocumentationUrl: new URL("/", c.req.url),
      scopesSupported: [...SUPPORTED_SCOPES],
    }) ?? c.notFound()
  );
}

function getClerkOAuthMetadata(publishableKey: string, fapiUrl?: string) {
  const cacheKey = JSON.stringify([publishableKey, fapiUrl]);
  const cached = clerkOAuthMetadata.get(cacheKey);
  if (cached) {
    return cached;
  }

  const pending = fetchClerkAuthorizationServerMetadata(publishableKey, fapiUrl);

  clerkOAuthMetadata.set(cacheKey, pending);
  pending.catch(() => clerkOAuthMetadata.delete(cacheKey));

  return pending;
}

async function fetchClerkAuthorizationServerMetadata(
  publishableKey: string,
  fapiUrl?: string,
): Promise<OAuthMetadata> {
  const publicFapiUrl = fapiUrlFromPublishableKey(publishableKey);
  const metadataBaseUrl = new URL(fapiUrl || publicFapiUrl);
  const metadataUrl = new URL("/.well-known/oauth-authorization-server", metadataBaseUrl);
  const headers = new Headers();

  if (metadataBaseUrl.origin !== publicFapiUrl.origin) {
    headers.set("X-Original-Host", publicFapiUrl.host);
  }

  const response = await fetch(metadataUrl, { headers });
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

export default app;
