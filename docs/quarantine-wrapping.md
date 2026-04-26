# Quarantine Wrapping

## Purpose

MCP output can contain instructions that look like they are meant for the agent rather than data returned by a tool. Quarantine wrapping reduces accidental obedience by placing untrusted MCP content inside an explicit analysis frame.

The wrapper is not the security boundary. Deterministic policy, certificates, approvals, session envelopes, and context packet projection remain the authority for actions.

## Flow

1. Receive MCP tool description, resource content, or tool output.
2. Mark it as untrusted data.
3. Run deterministic risk extraction for known unsafe requests.
4. Wrap the text with quarantine instructions before model analysis.
5. Ask the model to extract facts and risky requests, not obey the content.
6. Project selected safe data into a context packet with provenance.

## Risk Categories

The initial extractor flags:

- prompt injection
- policy bypass
- tool escalation
- secret exfiltration
- command execution
- filesystem mutation
- network exfiltration
- authentication or identity-sensitive behavior
- memory mutation

## Recommended Actions

- `allow`: no risky request was detected.
- `project_only`: content may be useful only after projection.
- `needs_human_review`: untrusted content attempts to influence behavior or tool use.
- `block`: content asks for secrets, command execution, filesystem mutation, network exfiltration, or identity-sensitive behavior.
