# Threat Model

## Primary Risk

MCP can move untrusted text, tool metadata, resource content, and tool output into an agent context where it may be treated as instructions.

MCP Stargate treats this as a boundary problem, not only a content-filtering problem.

## Threats

- Tool description poisoning: malicious instructions hidden in tool metadata.
- Tool schema poisoning: malicious or misleading instructions in schemas or annotations.
- Runtime output injection: tool results ask the model to call tools, reveal secrets, alter memory, or ignore policy.
- Tool surface drift: a reviewed server changes tools, descriptions, schemas, or transports later.
- Capability overclaiming: a server exposes broader authority than the client intended.
- Cross-server escalation: an untrusted server influences calls to a more privileged server.
- Context laundering: untrusted output is summarized and later treated as trusted context.
- Approval ambiguity: a human approves one action but the runtime applies that approval too broadly.
- Silent observation: another agent, proxy, or compromised transport observes MCP traffic without being represented in provenance.
- Message replay: a valid tool request, response, or approval is reused in a later session.
- Message mutation: MCP traffic is altered between client, gate, and server.
- Session confusion: context from one agent/tool session is introduced into another without identity or audience checks.

## Controls

- Stable manifest fingerprints.
- Signable manifest certificates.
- Capability certificates.
- Approval grants with scope, audience, action, and expiration.
- Session grants with scoped client/server identity.
- Per-message sequence numbers and nonces.
- Optional payload encryption for remote or multi-agent sessions.
- Conservative default policy.
- Untrusted output tainting.
- Context packet projection with provenance.
- Later: revocation, live proxying, transport mediation, and replayable hash-chained audit logs.

## Non-Goals

- Replacing MCP.
- Acting as a full agent runtime.
- Proving arbitrary text is safe.
- Using model judgment as the only security boundary.
