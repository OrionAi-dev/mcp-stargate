# Secure Session Envelopes

## Problem

MCP security work often starts with prompt injection, but multi-agent MCP deployments also need protection from silent observation, replay, mutation, and session confusion.

A secure session envelope binds MCP traffic to identity, purpose, sequence, and audit.

## Primitives

### SessionGrant

A signed grant that says one client may communicate with one server for a bounded purpose.

Fields should include:

- grant id
- client id
- server id
- audience
- purpose
- allowed actions
- issued by
- issued at
- expires at
- optional manifest certificate fingerprint
- optional capability certificate ids
- signature

### SessionEnvelope

The runtime session wrapper.

Fields should include:

- session id
- grant id
- client id
- server id
- created at
- expires at
- transport
- key agreement metadata when encryption is enabled

### MessageEnvelope

The per-message wrapper.

Fields should include:

- session id
- message id
- sequence number
- nonce
- direction
- method or tool name
- payload digest
- optional encrypted payload
- optional signature or MAC

### AuditRecord

A hash-chained record for decisions, messages, approvals, and projections.

Fields should include:

- record id
- previous record digest
- event type
- session id
- message id when applicable
- decision id when applicable
- approval grant id when applicable
- projected context packet id when applicable
- digest
- timestamp

## Alpha Approach

Start with typed records, deterministic digests, sequence validation, and provenance linking. Add encryption and concrete signing providers after the object model and tests are stable.
