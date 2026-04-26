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

export interface SessionGrant {
  kind: 'session_grant';
  grantId: string;
  clientId: string;
  serverId: string;
  audience?: string;
  purpose: string;
  allowedActions: GuardAction[];
  issuedBy: string;
  issuedAt: string;
  expiresAt?: string;
  manifestFingerprint?: string;
  capabilityCertificateIds?: string[];
  signature: SignatureEnvelope;
}

export interface SessionEnvelope {
  kind: 'session_envelope';
  sessionId: string;
  grantId: string;
  clientId: string;
  serverId: string;
  audience?: string;
  purpose: string;
  transport: 'stdio' | 'http' | 'sse' | 'streamable-http' | 'unknown';
  createdAt: string;
  expiresAt?: string;
  lastSequence: number;
  keyAgreement?: {
    algorithm: 'none' | 'x25519' | 'p256';
    publicKey?: string;
  };
}

export interface MessageEnvelope<T = unknown> {
  kind: 'message_envelope';
  sessionId: string;
  messageId: string;
  sequence: number;
  nonce: string;
  direction: 'client_to_server' | 'server_to_client' | 'gate_internal';
  method?: string;
  toolName?: string;
  payload?: T;
  payloadDigest: string;
  encrypted: boolean;
  signature?: SignatureEnvelope;
}

export type AuditEventType =
  | 'session_created'
  | 'message_observed'
  | 'decision_recorded'
  | 'approval_used'
  | 'context_projected';

export interface AuditRecord {
  kind: 'audit_record';
  recordId: string;
  eventType: AuditEventType;
  sessionId?: string;
  messageId?: string;
  decisionId?: string;
  approvalGrantId?: string;
  projectedContextPacketId?: string;
  previousRecordDigest?: string;
  eventDigest: string;
  recordDigest: string;
  timestamp: string;
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

export type QuarantineFindingCategory =
  | 'prompt_injection'
  | 'policy_bypass'
  | 'tool_escalation'
  | 'secret_exfiltration'
  | 'command_execution'
  | 'filesystem_mutation'
  | 'network_exfiltration'
  | 'auth_or_identity'
  | 'memory_mutation';

export interface QuarantineFinding {
  category: QuarantineFindingCategory;
  severity: 'low' | 'medium' | 'high';
  excerpt: string;
  reason: string;
}

export interface QuarantinePromptInput {
  content: string;
  source?: UntrustedMcpSource;
  task?: string;
}

export interface QuarantineAssessment {
  kind: 'quarantine_assessment';
  contentDigest: string;
  source?: UntrustedMcpSource;
  findings: QuarantineFinding[];
  recommendedAction: 'allow' | 'project_only' | 'block' | 'needs_human_review';
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
    derivation: 'mcp_stargate_projection';
  };
  ext: {
    'mcp-stargate': {
      tainted: true;
      instructionUse: 'forbidden';
    };
  };
}
