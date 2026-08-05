import type { Context, Hono } from "hono";
import { createMcpHonoApp } from "@modelcontextprotocol/hono";
import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  McpServer,
  requireBearerAuth,
} from "@modelcontextprotocol/server";

import * as z from "zod/v4";

import type { AuthBindings, AuthProviderAdapter, AuthProviderName } from "./auth-provider";
import * as clerkAuthProvider from "./clerk-auth-provider";
import * as workosAuthProvider from "./workos-auth-provider";

const AUTH_PROVIDERS = {
  clerk: clerkAuthProvider,
  workos: workosAuthProvider,
} satisfies Record<AuthProviderName, AuthProviderAdapter>;

type AppEnv = {
  Bindings: AuthBindings;
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
    name: "mcp-hono-auth-providers",
    message: "OAuth-protected Hono MCP server",
    mcp: "/mcp",
    oauthProtectedResourceMetadata: "/.well-known/oauth-protected-resource/mcp",
  });
});

app.all("/.well-known/oauth-protected-resource/mcp", serveOAuthMetadata);
app.all("/.well-known/oauth-authorization-server", serveOAuthMetadata);

function createServer() {
  const server = new McpServer({
    name: "mcp-hono-auth-providers",
    version: "0.1.0",
  });

  server.registerTool(
    "get_authenticated_user",
    {
      description: "Returns the auth details for the authenticated request.",
      inputSchema: z.object({}),
    },
    async (_, context) => {
      const { token: _token, ...safeAuthInfo } = context.http?.authInfo ?? {};

      return {
        content: [{ type: "text", text: JSON.stringify(safeAuthInfo) }],
      };
    },
  );

  return server;
}

const mcpHandler = createMcpHandler(() => createServer());

app.all("/mcp", async (c: AppContext) => {
  const parsedBody = c.get("parsedBody");
  const mcpServerUrl = new URL("/mcp", c.req.url);
  const authProviderName = selectedAuthProviderName(c.env);
  const authProvider = AUTH_PROVIDERS[authProviderName];
  const auth = await requireBearerAuth({
    verifier: authProvider.tokenVerifier(c.env, mcpServerUrl),
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
    requiredScopes: authProviderName === "clerk" ? requiredScopesForRequest(parsedBody) : [],
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

async function serveOAuthMetadata(c: AppContext) {
  const mcpServerUrl = new URL("/mcp", c.req.url);
  const authProvider = AUTH_PROVIDERS[selectedAuthProviderName(c.env)];

  return (
    (await authProvider.serveOAuthMetadata(c.env, {
      request: c.req.raw,
      resourceServerUrl: mcpServerUrl,
      resourceName: "mcp-hono-auth-providers",
      serviceDocumentationUrl: new URL("/", c.req.url),
      scopesSupported: [...SUPPORTED_SCOPES],
    })) ?? c.notFound()
  );
}

function selectedAuthProviderName(bindings: AuthBindings): AuthProviderName {
  if (!bindings.AUTH_PROVIDER || bindings.AUTH_PROVIDER === "clerk") {
    return "clerk";
  }

  if (bindings.AUTH_PROVIDER === "workos") {
    return "workos";
  }

  throw new Error(`Unsupported AUTH_PROVIDER: ${bindings.AUTH_PROVIDER}`);
}

export default app;
