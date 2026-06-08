/**
 * Tenant Context Middleware
 * 
 * Extracts user identity from JWT or API key and attaches to request context.
 * This is the CRITICAL security boundary for multi-tenant isolation.
 * 
 * Every request MUST have req.context.userId set before provider credential access.
 */

import { NextRequest } from "next/server";
import { jwtVerify } from "jose";
import { createHash } from "crypto";
import { getDbInstance } from "@/lib/db/core";

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || "fallback-dev-secret-min-32-chars"
);

/**
 * Tenant context attached to every request
 */
export interface TenantContext {
  userId: string;      // PK in users table
  email?: string;      // Email address (for audit)
  scopes?: string[];   // API key scopes (for fine-grained access)
  apiKeyId?: string;   // If auth via API key, which key
}

/**
 * Extract userId from JWT token
 * 
 * Security: JWT_SECRET must be >32 chars and rotated periodically
 */
async function extractUserFromJWT(token: string): Promise<TenantContext | null> {
  try {
    const verified = await jwtVerify(token, JWT_SECRET);
    const sub = verified.payload.sub as string | undefined;
    const email = verified.payload.email as string | undefined;

    if (!sub) {
      console.warn("[TenantContext] JWT missing 'sub' claim");
      return null;
    }

    return {
      userId: sub,
      email: email,
      scopes: (verified.payload.scopes as string[]) || [],
    };
  } catch (err) {
    console.warn(`[TenantContext] JWT verification failed: ${String(err)}`)
    return null;
  }
}

/**
 * Extract userId from API key
 * 
 * Security: API key hash stored in DB, never plaintext
 */
async function extractUserFromAPIKey(apiKey: string): Promise<TenantContext | null> {
  if (!apiKey || typeof apiKey !== "string" || apiKey.length === 0) {
    return null;
  }

  // Hash the API key (same algo as storage)
  const keyHash = createHash("sha256").update(apiKey).digest("hex");

  try {
    const db = getDbInstance();
    const stmt = db.prepare<{ id: string; user_id: string; scopes?: string }>(
      "SELECT id, user_id, scopes FROM api_keys_v2 WHERE key_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))"
    );
    const row = stmt.get(keyHash);

    if (!row) {
      console.warn("[TenantContext] API key not found or expired");
      return null;
    }

    let scopes: string[] = [];
    if (row.scopes && typeof row.scopes === "string") {
      try {
        scopes = JSON.parse(row.scopes);
      } catch {
        scopes = [];
      }
    }

    return {
      userId: row.user_id,
      apiKeyId: row.id,
      scopes: scopes,
    };
  } catch (err) {
    console.error(`[TenantContext] API key lookup failed: ${String(err)}`);
    return null;
  }
}

/**
 * Extract Authorization header
 * 
 * Supports:
 * - Bearer <jwt>
 * - Bearer <api-key>
 */
function extractAuthToken(req: NextRequest): string | null {
  const authHeader = req.headers.get("authorization");
  if (!authHeader) return null;

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  return match[1].trim();
}

/**
 * Main middleware: Extract tenant context
 * 
 * Returns null if auth fails (caller must return 401)
 */
export async function extractTenantContext(
  req: NextRequest
): Promise<TenantContext | null> {
  const token = extractAuthToken(req);
  if (!token) {
    console.debug("[TenantContext] No authorization header");
    return null;
  }

  // Try JWT first (faster, cached validation)
  let context = await extractUserFromJWT(token);
  if (context) {
    console.debug(`[TenantContext] User authenticated via JWT: ${context.userId}`);
    return context;
  }

  // Fall back to API key (DB lookup)
  context = await extractUserFromAPIKey(token);
  if (context) {
    console.debug(`[TenantContext] User authenticated via API key: ${context.userId}`);
    return context;
  }

  console.warn("[TenantContext] Authentication failed");
  return null;
}

/**
 * Attach tenant context to request
 * 
 * Usage: Call this in route handlers before any credential access
 * 
 * @example
 * const context = await attachTenantContext(req);
 * if (!context) return Response.json({ error: "Unauthorized" }, { status: 401 });
 * 
 * // Now safe to use context.userId for credential lookups
 */
export async function attachTenantContext(
  req: NextRequest
): Promise<TenantContext | null> {
  return extractTenantContext(req);
}

/**
 * Type-safe wrapper for route handlers
 */
export interface RequestWithTenant extends NextRequest {
  context: TenantContext;
}
