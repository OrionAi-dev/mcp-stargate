export * from './types.js';

import { createHash } from 'node:crypto';
import type {
  ApprovalGrant,
  CapabilityCertificate,
  ContextPacketProjectionInput,
  EvaluateMcpCallInput,
  GuardAction,
  GuardDecision,
  GuardOutcome,
  GuardPolicy,
  ManifestCertificate,
  McpCapabilityRisk,
  McpServerManifest,
  McpToolDescriptor,
  ProjectedContextPacket,
  SecureContextPolicy,
  UntrustedMcpOutput,
  UntrustedMcpSource
} from './types.js';

export const DEFAULT_GUARD_POLICY: GuardPolicy = {
  defaultOutcome: 'deny',
  allowRisks: ['read'],
  requireApprovalRisks: ['write', 'filesystem', 'network', 'cross_agent_sharing'],
  denyRisks: ['shell', 'secrets', 'identity', 'browser', 'memory_mutation', 'unknown'],
  allowActions: ['validate', 'verify', 'read', 'project'],
  requireApprovalActions: ['write', 'share', 'execute'],
  requireProjectionForRead: true
};

const RISK_PATTERNS: Array<[McpCapabilityRisk, RegExp]> = [
  ['shell', /\b(shell|bash|zsh|cmd|powershell|process|exec|spawn|terminal)\b/i],
  ['secrets', /\b(secret|token|credential|password|api[-_ ]?key|private[-_ ]?key)\b/i],
  ['identity', /\b(oauth|identity|account|session|login|impersonat|permission)\b/i],
  ['browser', /\b(browser|playwright|puppeteer|webpage|dom|click|navigate)\b/i],
  ['memory_mutation', /\b(memory|remember|forget|vector|embedding|persist)\b/i],
  ['cross_agent_sharing', /\b(share|handoff|delegate|agent|broadcast|send)\b/i],
  ['network', /\b(http|https|fetch|request|webhook|url|internet|network|download|upload)\b/i],
  ['filesystem', /\b(file|filesystem|path|directory|readfile|writefile|delete|rename)\b/i],
  ['write', /\b(write|create|update|delete|mutate|patch|commit|send|post|publish)\b/i],
  ['read', /\b(read|get|list|search|query|fetch|inspect|view)\b/i]
];

export function classifyMcpTool(tool: McpToolDescriptor): McpCapabilityRisk[] {
  const text = `${tool.serverId ?? ''} ${tool.name} ${tool.description ?? ''}`;
  const risks = new Set<McpCapabilityRisk>();

  for (const [risk, pattern] of RISK_PATTERNS) {
    if (pattern.test(text)) {
      risks.add(risk);
    }
  }

  if (risks.size === 0) {
    risks.add('unknown');
  }

  if (risks.has('write')) {
    risks.delete('read');
  }

  return [...risks];
}

export function fingerprintMcpManifest(manifest: McpServerManifest): string {
  return sha256Hex({
    serverId: manifest.serverId,
    name: manifest.name,
    version: manifest.version,
    publisher: manifest.publisher,
    transport: manifest.transport ?? 'unknown',
    tools: manifest.tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
      outputSchema: tool.outputSchema
    }))
  });
}

export function createUnsignedManifestCertificate(
  manifest: McpServerManifest,
  input: { issuer: string; issuedAt?: string; expiresAt?: string }
): ManifestCertificate {
  const certificate: ManifestCertificate = {
    kind: 'manifest_certificate',
    subject: manifest,
    issuer: input.issuer,
    issuedAt: input.issuedAt ?? new Date().toISOString(),
    fingerprint: fingerprintMcpManifest(manifest),
    signature: {
      algorithm: 'none'
    }
  };
  if (input.expiresAt) {
    certificate.expiresAt = input.expiresAt;
  }
  return certificate;
}

export function validateManifestCertificate(
  certificate: ManifestCertificate,
  input: { now?: Date } = {}
): string[] {
  const reasons: string[] = [];
  const now = input.now ?? new Date();

  if (certificate.fingerprint !== fingerprintMcpManifest(certificate.subject)) {
    reasons.push('manifest certificate fingerprint does not match subject');
  }

  if (isExpired(certificate.expiresAt, now)) {
    reasons.push('manifest certificate is expired');
  }

  return reasons;
}

export function evaluateMcpCall(input: EvaluateMcpCallInput): GuardDecision {
  const action = input.action ?? inferAction(input.tool);
  const policy = input.guardPolicy ?? DEFAULT_GUARD_POLICY;
  const risks = classifyMcpTool(input.tool);
  const reasons: string[] = [];

  const policyEvaluationInput: { action: GuardAction; audience?: string; now?: Date } = {
    action
  };
  if (input.audience) {
    policyEvaluationInput.audience = input.audience;
  }
  if (input.now) {
    policyEvaluationInput.now = input.now;
  }
  reasons.push(...evaluateSecureContextPolicy(input.contextPolicy, policyEvaluationInput));

  if (!policy.allowActions.includes(action) && !policy.requireApprovalActions.includes(action)) {
    reasons.push(`action '${action}' is not allowed by the guard profile`);
  }

  const certificateEvaluationInput: { now?: Date } = {};
  if (input.now) {
    certificateEvaluationInput.now = input.now;
  }
  reasons.push(
    ...evaluateCapabilityCertificate(input.capabilityCertificate, risks, certificateEvaluationInput)
  );

  const deniedRisk = risks.find((risk) => policy.denyRisks.includes(risk));
  if (deniedRisk) {
    reasons.push(`risk '${deniedRisk}' is denied by the guard profile`);
    return decision('deny', action, risks, reasons);
  }

  const approvalRisk = risks.find((risk) => policy.requireApprovalRisks.includes(risk));
  if (reasons.length > 0) {
    return decision('deny', action, risks, reasons);
  }

  if (approvalRisk) {
    const approvalInput: { action: GuardAction; audience?: string; now?: Date } = { action };
    if (input.audience) {
      approvalInput.audience = input.audience;
    }
    if (input.now) {
      approvalInput.now = input.now;
    }
    const approvalReasons = evaluateApprovalGrant(input.approvalGrant, approvalInput);
    if (approvalReasons.length === 0 && input.approvalGrant) {
      return decision('allow', action, risks, ['signed approval grant permits this call']);
    }
    return decision('require_approval', action, risks, [
      `risk '${approvalRisk}' requires explicit approval`,
      ...approvalReasons
    ], input.approvalGrant);
  }

  if (action === 'read' && policy.requireProjectionForRead) {
    return decision('allow_with_projection', action, risks, [
      'read output must be projected before trusted use'
    ]);
  }

  if (risks.every((risk) => policy.allowRisks.includes(risk))) {
    return decision('allow', action, risks, ['risk profile is allowed']);
  }

  return decision(policy.defaultOutcome, action, risks, ['no explicit allow rule matched']);
}

export function evaluateSecureContextPolicy(
  policy: SecureContextPolicy | undefined,
  input: { action: GuardAction; audience?: string; now?: Date }
): string[] {
  if (!policy) {
    return [];
  }

  const reasons: string[] = [];
  const now = input.now ?? new Date();

  if (policy.expiresAt) {
    const expiresAt = new Date(policy.expiresAt);
    if (!Number.isNaN(expiresAt.getTime()) && expiresAt <= now) {
      reasons.push('context policy is expired');
    }
  }

  if (policy.allowedActions && !policy.allowedActions.includes(input.action)) {
    reasons.push(`context policy does not allow action '${input.action}'`);
  }

  if (
    input.audience &&
    policy.audience &&
    policy.audience.length > 0 &&
    !policy.audience.includes(input.audience)
  ) {
    reasons.push(`context policy does not allow audience '${input.audience}'`);
  }

  if (input.action === 'share' && policy.reshareAllowed === false) {
    reasons.push('context policy forbids resharing');
  }

  return reasons;
}

export function evaluateCapabilityCertificate(
  certificate: CapabilityCertificate | undefined,
  risks: McpCapabilityRisk[],
  input: { now?: Date } = {}
): string[] {
  if (!certificate) {
    return [];
  }

  const reasons: string[] = [];
  const now = input.now ?? new Date();

  if (isExpired(certificate.expiresAt, now)) {
    reasons.push('capability certificate is expired');
  }

  for (const risk of risks) {
    if (!certificate.capabilities.includes(risk)) {
      reasons.push(`capability certificate does not permit risk '${risk}'`);
    }
  }

  return reasons;
}

export function evaluateApprovalGrant(
  grant: ApprovalGrant | undefined,
  input: { action: GuardAction; audience?: string; now?: Date }
): string[] {
  if (!grant) {
    return ['no approval grant supplied'];
  }

  const reasons: string[] = [];
  const now = input.now ?? new Date();

  if (grant.action !== input.action) {
    reasons.push(`approval grant does not permit action '${input.action}'`);
  }

  if (input.audience && grant.audience && grant.audience !== input.audience) {
    reasons.push(`approval grant does not permit audience '${input.audience}'`);
  }

  if (isExpired(grant.expiresAt, now)) {
    reasons.push('approval grant is expired');
  }

  return reasons;
}

export function markUntrustedMcpOutput<T>(
  value: T,
  source: UntrustedMcpSource,
  risks: McpCapabilityRisk[] = ['unknown']
): UntrustedMcpOutput<T> {
  return {
    kind: 'untrusted_mcp_output',
    value,
    source: {
      ...source,
      observedAt: source.observedAt ?? new Date().toISOString()
    },
    risks
  };
}

export function projectMcpOutputToContextPacket<T>(
  input: ContextPacketProjectionInput<T>
): ProjectedContextPacket<T> {
  const now = input.now ?? new Date();
  return {
    schema: 'mcp-secure-context.container.v0.1',
    containerType: 'knowledge_object',
    id: input.packetId ?? `mcp-trust-gate-${now.getTime()}`,
    version: '0.1.0',
    payload: {
      title: 'Projected MCP output',
      body: input.output,
      format: 'untrusted-mcp-output'
    },
    policy: input.policy,
    provenance: {
      createdAt: now.toISOString(),
      createdBy: input.createdBy ?? 'mcp-trust-gate',
      sourceRefs: [input.source],
      derivation: 'mcp_trust_gate_projection'
    },
    ext: {
      'mcp-trust-gate': {
        tainted: true,
        instructionUse: 'forbidden'
      }
    }
  };
}

function inferAction(tool: McpToolDescriptor): GuardAction {
  const text = `${tool.name} ${tool.description ?? ''}`;
  if (/\b(share|send|handoff|delegate)\b/i.test(text)) {
    return 'share';
  }
  if (/\b(write|create|update|delete|mutate|patch|commit|publish|post)\b/i.test(text)) {
    return 'write';
  }
  if (/\b(exec|execute|run|shell|process)\b/i.test(text)) {
    return 'execute';
  }
  return 'read';
}

function decision(
  outcome: GuardOutcome,
  action: GuardAction,
  risks: McpCapabilityRisk[],
  reasons: string[],
  requiredApproval?: ApprovalGrant
): GuardDecision {
  return {
    outcome,
    action,
    risks,
    reasons,
    requiredApproval
  };
}

function isExpired(expiresAt: string | undefined, now: Date): boolean {
  if (!expiresAt) {
    return false;
  }
  const parsed = new Date(expiresAt);
  return !Number.isNaN(parsed.getTime()) && parsed <= now;
}

function sha256Hex(value: unknown): string {
  return createHash('sha256').update(stableStringify(value)).digest('hex');
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(',')}}`;
}
