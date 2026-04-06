# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in the Sentari agent, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@sentari.dev** with:

- A description of the vulnerability
- Steps to reproduce
- The version(s) affected
- Any suggested fix (optional)

We will acknowledge your report within 2 business days and provide a timeline for a fix within 5 business days.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor release | Yes (security fixes only) |
| Older versions | No |

## Security design

The Sentari agent is designed with security as a primary concern:

- **Zero binary invocation** — the agent never executes `pip`, `conda`, `python`, or any other binary. All data is read from metadata files on the filesystem.
- **Static binary** — no runtime dependencies, no dynamic linking, no shared libraries.
- **mTLS** — all agent-server communication uses TLS 1.3 with mutual certificate authentication.
- **Private key isolation** — the agent generates its ECDSA P-256 keypair locally. The private key never leaves the endpoint.
- **Audit trail** — every action is recorded in a local SHA-256 hash-chained audit log.
- **No inbound connections** — the agent only initiates outbound HTTPS connections.
