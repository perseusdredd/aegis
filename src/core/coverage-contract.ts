import { createHash, randomBytes } from "node:crypto";

export type ClientArtifactCoverageStatus =
  | "assessed-static-and-heuristic-cost-amplification"
  | "not-protected";

export type ServerAuthorizationCoverageStatus =
  | "not-assessed/external-control-required"
  | "verified-local-reference-fixture";

export interface ThreatPremiseBoundary {
  readonly id:
    | "authenticated-low-privilege-session"
    | "controlled-client-same-origin-fetch"
    | "authorized-user-response-observation";
  readonly coveredByClientArtifactShield: false;
  readonly authoritativeControlLocation: "server-side-application";
  readonly explanation: string;
}

export interface DefenseCoverageContract {
  readonly clientArtifact: {
    readonly status: ClientArtifactCoverageStatus;
    readonly scope: "static-reverse-engineering-and-automated-inspection-friction";
    readonly guaranteesConfidentialityOfShippedData: false;
    readonly enforcesAccessControl: false;
  };
  readonly serverAuthorization: {
    readonly status: ServerAuthorizationCoverageStatus;
    readonly responsibility: "external-application-backend";
    readonly summary: string;
  };
  readonly threatPremises: readonly ThreatPremiseBoundary[];
}

export function buildDefenseCoverageContract(options?: {
  readonly clientProtected?: boolean;
  readonly localServerFixtureVerified?: boolean;
}): DefenseCoverageContract {
  const clientProtected = options?.clientProtected ?? true;
  const serverVerified = options?.localServerFixtureVerified ?? false;

  return {
    clientArtifact: {
      status: clientProtected
        ? "assessed-static-and-heuristic-cost-amplification"
        : "not-protected",
      scope: "static-reverse-engineering-and-automated-inspection-friction",
      guaranteesConfidentialityOfShippedData: false,
      enforcesAccessControl: false,
    },
    serverAuthorization: {
      status: serverVerified
        ? "verified-local-reference-fixture"
        : "not-assessed/external-control-required",
      responsibility: "external-application-backend",
      summary: serverVerified
        ? "Verified against local synthetic multi-tenant reference fixture only; production backends must enforce per-request identity, object/tenant authorization, session revocation, and response data minimization independently."
        : "Server-side authentication, object/tenant authorization, session invalidation, and CSRF/replay controls are outside BLA client-artifact scope and must be enforced by the backend service.",
    },
    threatPremises: [
      {
        id: "authenticated-low-privilege-session",
        coveredByClientArtifactShield: false,
        authoritativeControlLocation: "server-side-application",
        explanation:
          "An active browser scenario (e.g., Playwright same-origin fetch) can reuse an existing low-privilege session cookie/token. Hiding UI buttons or obfuscating client bundles does not prevent direct API requests; the server must authorize every request against the session's tenant and role.",
      },
      {
        id: "controlled-client-same-origin-fetch",
        coveredByClientArtifactShield: false,
        authoritativeControlLocation: "server-side-application",
        explanation:
          "BLA runtime globals and AST shields execute inside the untrusted client context and carry no server identity or resource authorization authority.",
      },
      {
        id: "authorized-user-response-observation",
        coveredByClientArtifactShield: false,
        authoritativeControlLocation: "server-side-application",
        explanation:
          "BLA cannot prevent a user from recording network responses or data that their session is legitimately permitted to receive. Sensitive fields that the client does not strictly need must be omitted by the server before serialization (data minimization).",
      },
    ],
  };
}

// ============================================================================
// Self-Contained Local Reference Service & Client (Synthetic Multi-Tenant Fixture)
// ============================================================================

export type SyntheticRole = "viewer" | "admin";

export interface SyntheticSessionRecord {
  readonly sessionId: string;
  readonly userId: string;
  readonly tenantId: string;
  readonly role: SyntheticRole;
  readonly csrfToken: string;
  readonly expiresAtMs: number;
  revoked: boolean;
}

export interface InternalTenantDocumentRecord {
  readonly docId: string;
  readonly tenantId: string;
  title: string;
  quotaLimit: number;
  /** Sensitive backend-only field that must NEVER be serialized to client responses. */
  readonly internalSigningKeyMaterial: string;
  readonly internalBillingWebhookSecret: string;
}

export interface MinimizedClientDocumentDto {
  readonly docId: string;
  readonly tenantId: string;
  readonly title: string;
  readonly quotaLimit: number;
}

export interface SyntheticHttpRequest {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly origin: string;
  readonly sessionId?: string;
  readonly csrfToken?: string;
  readonly requestNonce?: string;
  readonly body?: Record<string, unknown>;
}

export interface SyntheticHttpResponse<T = unknown> {
  readonly status: number;
  readonly ok: boolean;
  readonly errorCode?:
    | "UNAUTHENTICATED"
    | "SESSION_EXPIRED_OR_REVOKED"
    | "CROSS_ORIGIN_REJECTED"
    | "CSRF_OR_REPLAY_REJECTED"
    | "FORBIDDEN_TENANT_OR_ROLE"
    | "NOT_FOUND";
  readonly data?: T;
}

/**
 * Small self-contained local reference service demonstrating authoritative server-side
 * session verification, tenant/object isolation, CSRF + replay protection, and
 * response data minimization (Issue #20).
 */
export class ReferenceTenantAuthorizationService {
  private readonly allowedOrigin: string;
  private readonly sessions = new Map<string, SyntheticSessionRecord>();
  private readonly documents = new Map<string, InternalTenantDocumentRecord>();
  private readonly consumedNonces = new Set<string>();
  private nowFn: () => number;

  constructor(options?: { allowedOrigin?: string; nowFn?: () => number }) {
    this.allowedOrigin = options?.allowedOrigin ?? "https://app.local.fixture";
    this.nowFn = options?.nowFn ?? (() => Date.now());
  }

  public issueSession(params: {
    readonly userId: string;
    readonly tenantId: string;
    readonly role: SyntheticRole;
    readonly ttlMs?: number;
  }): SyntheticSessionRecord {
    const sessionId = `sess_${randomBytes(12).toString("hex")}`;
    const csrfToken = `csrf_${randomBytes(12).toString("hex")}`;
    const record: SyntheticSessionRecord = {
      sessionId,
      userId: params.userId,
      tenantId: params.tenantId,
      role: params.role,
      csrfToken,
      expiresAtMs: this.nowFn() + (params.ttlMs ?? 60_000),
      revoked: false,
    };
    this.sessions.set(sessionId, record);
    return record;
  }

  public revokeSession(sessionId: string): boolean {
    const sess = this.sessions.get(sessionId);
    if (!sess) return false;
    sess.revoked = true;
    return true;
  }

  public seedDocument(doc: InternalTenantDocumentRecord): void {
    this.documents.set(doc.docId, { ...doc });
  }

  public snapshotDocumentState(docId: string): { title: string; quotaLimit: number } | undefined {
    const doc = this.documents.get(docId);
    if (!doc) return undefined;
    return { title: doc.title, quotaLimit: doc.quotaLimit };
  }

  private minimizeDocument(doc: InternalTenantDocumentRecord): MinimizedClientDocumentDto {
    // Data minimization: never include internalSigningKeyMaterial or internalBillingWebhookSecret
    return {
      docId: doc.docId,
      tenantId: doc.tenantId,
      title: doc.title,
      quotaLimit: doc.quotaLimit,
    };
  }

  public handleRequest(req: SyntheticHttpRequest): SyntheticHttpResponse {
    // 1. Validate session existence and active status on every request
    if (!req.sessionId) {
      return { status: 401, ok: false, errorCode: "UNAUTHENTICATED" };
    }
    const session = this.sessions.get(req.sessionId);
    if (!session || session.revoked || this.nowFn() >= session.expiresAtMs) {
      return { status: 401, ok: false, errorCode: "SESSION_EXPIRED_OR_REVOKED" };
    }

    // 2. Parse route `/api/tenants/:tenantId/documents/:docId`
    const match = /^\/api\/tenants\/([^/]+)\/documents\/([^/]+)$/.exec(req.path);
    if (!match) {
      return { status: 404, ok: false, errorCode: "NOT_FOUND" };
    }
    const [, requestedTenantId, requestedDocId] = match;

    // 3. Enforce tenant boundary before inspecting or mutating any object
    if (requestedTenantId !== session.tenantId) {
      return { status: 403, ok: false, errorCode: "FORBIDDEN_TENANT_OR_ROLE" };
    }

    const doc = this.documents.get(requestedDocId!);
    if (!doc || doc.tenantId !== session.tenantId) {
      return { status: 403, ok: false, errorCode: "FORBIDDEN_TENANT_OR_ROLE" };
    }

    if (req.method === "GET") {
      return {
        status: 200,
        ok: true,
        data: this.minimizeDocument(doc),
      };
    }

    // 4. State-changing request (POST): enforce origin, CSRF token, replay nonce, and role
    if (req.origin !== this.allowedOrigin) {
      return { status: 403, ok: false, errorCode: "CROSS_ORIGIN_REJECTED" };
    }
    if (
      !req.csrfToken ||
      req.csrfToken !== session.csrfToken ||
      !req.requestNonce ||
      req.requestNonce.trim().length < 8
    ) {
      return { status: 403, ok: false, errorCode: "CSRF_OR_REPLAY_REJECTED" };
    }
    const nonceKey = createHash("sha256")
      .update(`${session.sessionId}:${req.requestNonce}`)
      .digest("hex");
    if (this.consumedNonces.has(nonceKey)) {
      return { status: 403, ok: false, errorCode: "CSRF_OR_REPLAY_REJECTED" };
    }

    // Role check MUST happen before committing any state or consuming business state
    if (session.role !== "admin") {
      return { status: 403, ok: false, errorCode: "FORBIDDEN_TENANT_OR_ROLE" };
    }

    this.consumedNonces.add(nonceKey);

    if (typeof req.body?.title === "string" && req.body.title.trim().length > 0) {
      doc.title = req.body.title.trim();
    }
    if (typeof req.body?.quotaLimit === "number" && Number.isSafeInteger(req.body.quotaLimit)) {
      doc.quotaLimit = req.body.quotaLimit;
    }

    return {
      status: 200,
      ok: true,
      data: this.minimizeDocument(doc),
    };
  }
}
