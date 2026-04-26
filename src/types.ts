export type McpCapabilityRisk =
  | 'read'
  | 'write'
  | 'network'
  | 'shell'
  | 'filesystem'
  | 'secrets'
  | 'identity'
  | 'browser'
  | 'memory_mutation'
  | 'cross_agent_sharing'
  | 'unknown';

export type GuardOutcome = 'allow' | 'allow_with_projection' | 'require_approval' | 'deny';

export type GuardAction =
  | 'validate'
  | 'verify'
  | 'read'
  | 'write'
  | 'share'
  | 'project'
  | 'execute';

export type SensitivityLabel = 'public' | 'internal' | 'confidential' | 'restricted';

export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  serverId?: string;
}

export interface McpServerManifest {
  serverId: string;
  name?: string;
  version?: string;
  publisher?: string;
  transport?: 'stdio' | 'http' | 'sse' | 'streamable-http' | 'unknown';
  tools: McpToolDescriptor[];
}

export interface SignatureEnvelope {
  algorithm: 'none' | 'ed25519' | 'ecdsa-p256' | 'rsa-pss-sha256';
  keyId?: string;
  signature?: string;
  signedAt?: string;
}

export interface ManifestCertificate {
  kind: 'manifest_certificate';
  subject: McpServerManifest;
  issuer: string;
  issuedAt: string;
  expiresAt?: string;
  fingerprint: string;
  signature: SignatureEnvelope;
}

export interface CapabilityCertificate {
  kind: 'capability_certificate';
  subjectId: string;
  capabilities: McpCapabilityRisk[];
  issuer: string;
  issuedAt: string;
  expiresAt?: string;
  signature: SignatureEnvelope;
}

export interface ApprovalGrant {
  kind: 'approval_grant';
  subjectId: string;
  action: GuardAction;
  audience?: string;
  scope?: string[];
  reason?: string;
  issuedBy: string;
  issuedAt: string;
  expiresAt?: string;
  digest?: string;
  signature: SignatureEnvelope;
}

export interface SecureContextPolicy {
  audience?: string[];
  allowedActions?: string[];
  sensitivity?: SensitivityLabel;
  expiresAt?: string;
  ttlSeconds?: number;
  reshareAllowed?: boolean;
  leastPrivilegeScope?: string[];
}

export interface GuardPolicy {
  defaultOutcome: GuardOutcome;
  allowRisks: McpCapabilityRisk[];
  requireApprovalRisks: McpCapabilityRisk[];
  denyRisks: McpCapabilityRisk[];
  allowActions: GuardAction[];
  requireApprovalActions: GuardAction[];
  requireProjectionForRead: boolean;
}

export interface GuardDecision {
  outcome: GuardOutcome;
  risks: McpCapabilityRisk[];
  reasons: string[];
  action: GuardAction;
  requiredApproval?: ApprovalGrant | undefined;
}

export interface EvaluateMcpCallInput {
  tool: McpToolDescriptor;
  action?: GuardAction;
  audience?: string;
  now?: Date;
  contextPolicy?: SecureContextPolicy;
  guardPolicy?: GuardPolicy;
  capabilityCertificate?: CapabilityCertificate;
  approvalGrant?: ApprovalGrant;
}

export interface UntrustedMcpSource {
  serverId?: string;
  toolName?: string;
  resourceUri?: string;
  outputDigest?: string;
  observedAt?: string;
}

export interface UntrustedMcpOutput<T = unknown> {
  kind: 'untrusted_mcp_output';
  value: T;
  source: UntrustedMcpSource;
  risks: McpCapabilityRisk[];
}

export interface ContextPacketProjectionInput<T = unknown> {
  output: T;
  source: UntrustedMcpSource;
  policy: SecureContextPolicy;
  packetId?: string;
  createdBy?: string;
  now?: Date;
}

export interface ProjectedContextPacket<T = unknown> {
  schema: 'mcp-secure-context.container.v0.1';
  containerType: 'knowledge_object';
  id: string;
  version: string;
  payload: {
    title: string;
    body: T;
    format: 'untrusted-mcp-output';
  };
  policy: SecureContextPolicy;
  provenance: {
    createdAt: string;
    createdBy: string;
    sourceRefs: UntrustedMcpSource[];
    derivation: 'mcp_trust_gate_projection';
  };
  ext: {
    'mcp-trust-gate': {
      tainted: true;
      instructionUse: 'forbidden';
    };
  };
}
