// SPDX-License-Identifier: Apache-2.0
// Generated from v1.yaml by the Scoplen OpenAPI generator.

export interface components {
  schemas: {
    Resource: Resource;
    ResourcePage: ResourcePage;
    ProblemDetails: ProblemDetails;
    ListQuery: ListQuery;
    WriteRequest: WriteRequest;
    DecisionRequest: DecisionRequest;
    PolicyEvaluationRequest: PolicyEvaluationRequest;
    PolicyEvaluationResponse: PolicyEvaluationResponse;
    CertificateRequest: CertificateRequest;
    CertificateResponse: CertificateResponse;
    Account: Resource;
    Device: Resource;
    Organization: Resource;
    Member: Resource;
    Invitation: Resource;
    Group: Resource;
    IdentityProvider: Resource;
    ServicePrincipal: Resource;
    Host: Resource;
    AccessProfile: Resource;
    Route: Resource;
    HostGroup: Resource;
    Snippet: Resource;
    TrustRecord: Resource;
    GatewayNetwork: Resource;
    InventoryImport: Resource;
    Policy: Resource;
    Role: Resource;
    Grant: Resource;
    AccessRequest: Resource;
    AccessDecision: Resource;
    CertificateAuthority: Resource;
    Certificate: Resource;
    Gateway: Resource;
    JoinToken: Resource;
    GatewayTicket: Resource;
    Credential: Resource;
    HostAgent: Resource;
    Session: Resource;
    Recording: Resource;
    AuditEvent: Resource;
    AuditExport: Resource;
    Integration: Resource;
  };
}

export interface Resource {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: Record<string, unknown>;
}
export interface ResourcePage { items: Resource[]; next_cursor: string | null; }
export interface ProblemDetails {
  type: string; title: string; status: number; code: string;
  detail?: string; instance?: string; changed?: boolean;
  [extension: string]: unknown;
}
export interface ListQuery { limit?: number; cursor?: string; filter?: string; sort?: string; }
export interface WriteRequest { data: Record<string, unknown>; }
export interface DecisionRequest { decision: "approve" | "deny"; reason?: string; }
export interface PolicyEvaluationRequest { action: string; resource: Record<string, unknown>; context: Record<string, unknown>; }
export interface PolicyEvaluationResponse { decision: "allow" | "deny"; policies: string[]; }
export interface CertificateRequest { public_key: string; hosts?: string[]; host_groups?: string[]; remote_user: string; ttl_seconds: number; }
export interface CertificateResponse { certificate: string; valid_after: string; valid_before: string; }

export interface paths {
  [path: string]: {
    get?: unknown; post?: unknown; patch?: unknown; delete?: unknown;
  };
}
