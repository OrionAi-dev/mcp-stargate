# MCP Trust Gate

MCP Trust Gate is a certificate-backed trust boundary for Model Context Protocol tool, resource, and context flows.

MCP can connect agents to useful tools and data, but MCP output should not be treated as trusted instructions. MCP Trust Gate makes the safe path deterministic: pin capabilities, verify signed trust artifacts, enforce local policy, taint untrusted output, and project selected data into bounded context packets.

## Positioning

MCP Trust Gate protects the MCP boundary.

`mcp-secure-context-sharing` defines safe handoff artifacts: context containers, policy metadata, provenance, verification, and digests.

StarConsole and other clients consume verified context packets. They should not consume raw MCP output as trusted instructions.

## Default Rule

MCP support is optional. Trusted MCP is required whenever MCP is enabled.

The default profile:

- verifies signed MCP server manifests when available
- detects tool schema or description drift
- allows narrow read/reference flows when policy permits them
- denies shell/process, secrets, identity, browser, broad network, and memory-mutation capabilities by default
- requires signed approval grants for write, share, and high-risk operations
- marks MCP output as untrusted until projected into a context packet
- preserves provenance for projected context

## Current Package

This initial package contains the alpha trust-gate primitives:

- MCP server manifest fingerprints
- capability certificates
- approval grants
- MCP tool risk classification
- default guard policy
- call decision evaluation
- secure-context policy checks
- untrusted MCP output wrappers
- context packet projection helpers

It intentionally does not implement a full MCP proxy yet. Gateway behavior with live transport mediation, remote attestation, revocation lists, and audit ledgers belongs in the next phase.

## Install

```sh
pnpm add mcp-trust-gate
```

## Example

```ts
import { evaluateMcpCall, projectMcpOutputToContextPacket } from 'mcp-trust-gate';

const decision = evaluateMcpCall({
  tool: {
    name: 'filesystem.readFile',
    description: 'Read a local file selected by the user'
  },
  action: 'read',
  audience: 'starconsole'
});

if (decision.outcome !== 'allow' && decision.outcome !== 'allow_with_projection') {
  throw new Error(decision.reasons.join('; '));
}

const packet = projectMcpOutputToContextPacket({
  output: 'untrusted tool result',
  source: {
    serverId: 'local-files',
    toolName: 'filesystem.readFile'
  },
  policy: {
    audience: ['starconsole'],
    allowedActions: ['read'],
    sensitivity: 'internal'
  }
});
```

## Trust Artifacts

MCP Trust Gate is built around signed or signable artifacts:

- `ManifestCertificate`: pins a server identity, tool surface, transport, publisher, and expiration.
- `CapabilityCertificate`: describes which capability classes a server or tool is allowed to expose.
- `SessionGrant`: scopes confidential, auditable agent-to-tool sessions.
- `ApprovalGrant`: records a human-approved exception with scope, subject, action, audience, expiration, and digest.
- `ProjectedContextPacket`: converts selected untrusted MCP output into a policy-scoped handoff artifact.

The first implementation computes stable fingerprints and validates structure. Real signature providers and revocation stores are planned next.

## Security Thesis

Prompt injection is the first visible MCP risk. The deeper problem is that MCP lacks a durable trust layer for identity, capability, session confidentiality, provenance, and replayable audit.

MCP Trust Gate is designed to grow toward secure MCP session envelopes: signed session grants, client/server identity, per-message sequence numbers, replay prevention, optional payload encryption, and hash-chained audit records.

## Relationship To Secure Context Sharing

MCP Trust Gate should use `@mcp-secure-context/core` container semantics when the secure-context packages are available. The trust gate remains dependency-light so clients can classify and deny unsafe MCP behavior before loading larger adapter stacks.

## Development

```sh
pnpm install
pnpm verify
```
