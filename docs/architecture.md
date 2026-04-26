# Architecture

## Boundary

MCP Stargate owns runtime security decisions around MCP tools, resources, prompts, and outputs.

It does not own context container schemas. Those belong to `mcp-secure-context-sharing`.

It does not own workflow loops, checkpointing, decisions, or release records. Those belong to clients such as StarConsole.

## Alpha Flow

1. Client discovers or proposes an MCP tool/resource call.
2. MCP Stargate fingerprints the server/tool manifest and checks any supplied trust artifacts.
3. MCP Stargate classifies the capability risk.
4. MCP Stargate evaluates the call against the default profile and any supplied context policy.
5. Denied calls stop before execution.
6. Approved or allowed calls may execute through the client MCP layer.
7. MCP output is wrapped as untrusted data.
8. Selected output is projected into a bounded context packet with provenance and policy.
9. The client consumes the context packet, not raw MCP output.

## Phase 2 Gateway

The later gateway should add:

- MCP server manifest pinning
- tool-description hashing and drift detection
- signed approval records
- secure session envelopes
- optional payload encryption
- replay prevention
- call and projection audit ledger
- server capability inventory
- compatibility adapters for MCP clients and servers

The gateway should build on the alpha guard primitives instead of replacing them.

## Secure Session Envelope

Prompt-injection defense is not enough for multi-agent or remote MCP deployments. A separate agent, proxy, or compromised transport could silently observe, replay, or mutate MCP traffic unless the session itself is bound to identity and audit.

A secure MCP session should include:

- client identity
- server identity
- session id
- signed session grant
- purpose and audience
- issued and expiration times
- per-message sequence numbers
- nonces
- message digests
- optional signatures or MACs
- optional payload encryption
- hash-chained audit records

Context packets projected from MCP output should preserve the session id and source message id in provenance so downstream clients can prove where context came from.
