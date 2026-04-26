# Architecture

## Boundary

MCP Trust Gate owns runtime security decisions around MCP tools, resources, prompts, and outputs.

It does not own context container schemas. Those belong to `mcp-secure-context-sharing`.

It does not own workflow loops, checkpointing, decisions, or release records. Those belong to clients such as StarConsole.

## Alpha Flow

1. Client discovers or proposes an MCP tool/resource call.
2. MCP Trust Gate fingerprints the server/tool manifest and checks any supplied trust artifacts.
3. MCP Trust Gate classifies the capability risk.
4. MCP Trust Gate evaluates the call against the default profile and any supplied context policy.
4. Denied calls stop before execution.
5. Approved or allowed calls may execute through the client MCP layer.
6. MCP output is wrapped as untrusted data.
7. Selected output is projected into a bounded context packet with provenance and policy.
8. The client consumes the context packet, not raw MCP output.

## Phase 2 Gateway

The later gateway should add:

- MCP server manifest pinning
- tool-description hashing and drift detection
- signed approval records
- call and projection audit ledger
- server capability inventory
- compatibility adapters for MCP clients and servers

The gateway should build on the alpha guard primitives instead of replacing them.
