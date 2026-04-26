# Security

MCP Stargate is security-sensitive software. Please report suspected vulnerabilities privately instead of opening a public issue with exploit details.

## Scope

Security reports may include:

- policy bypasses
- unsafe default behavior
- prompt-injection or tool-poisoning bypasses
- manifest fingerprint collisions or drift-detection failures
- approval-grant bypasses
- context packet provenance or tainting failures

## Reporting

Until a dedicated security contact is published, open a private GitHub security advisory for this repository.

## Design Principle

MCP output is untrusted by default. If behavior conflicts with this principle, treat it as security-relevant.
