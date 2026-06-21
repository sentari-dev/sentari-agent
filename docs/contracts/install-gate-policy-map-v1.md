# Install-Gate Policy-Map Envelope — v1

> **Status:** implemented on both sides. The server signs and serves the
> policy-map envelope (this repo); the agent-side per-ecosystem writers that
> consume the `auth` block per trusted registry have shipped in the
> `sentari-agent` repo (`installgate/` — pip/uv/npm/yarn/maven/gradle/sbt/
> nuget/pdm writers, with `*_credentials` consumers). This file and
> `install-gate-policy-map-v1.json` are mirrored **byte-identical** into the
> agent repo's `docs/contracts/`, same convention as `agent-scan-payload-v3.*`
> and `agent-audit-ship-v1.*`; keep the two copies in sync on any change.

## Why

The install-gate feature lets a Sentari operator deny / allow / pin specific
packages across the fleet and, optionally, redirect installs through one or
more **trusted registry** URLs (corporate Nexus / Artifactory mirrors) instead
of the default Sentari-Proxy. The signed policy-map envelope is the
machine-readable transport for that intent: the server signs a snapshot,
agents fetch and verify it, and per-ecosystem writers translate it into native
package-manager config files (`pip.conf`, `.npmrc`, `settings.xml`,
`NuGet.Config`).

This document pins the wire shape so the server, the agent, and any third
party consuming the envelope can agree on the contract independent of
internal refactors on either side.

## Endpoint

```
GET /api/v1/agent/policy-map
```

- **Auth:** mTLS client certificate; role `agent` or `proxy`.
- **Returns:** signed envelope `{payload, signature, key_id}` — the same
  shape as `/license-map` and `/vuln-map`. `signature` is the base64-
  encoded Ed25519 signature over the canonical-JSON serialisation of
  `payload`. `key_id` identifies which install-gate key pair was used
  (rotation-friendly).
- **Gating:** when the install-gate master switch is disabled, returns
  `404` + `X-Sentari-Install-Gate-Disabled: true` so agents tear down
  any cached policy immediately. This explicit-disable signal is
  distinct from a plain/transient `404` or an unreachable server, on
  which the agent fails **closed** — it keeps enforcing its last-good
  cached policy indefinitely rather than dropping enforcement. (There
  is no time-based fail-open grace window.)
- **503** on signing-key access failure or payload-size cap overrun —
  agent retains its last-good cached envelope.
- A machine-checkable JSON Schema lives alongside this doc
  ([`install-gate-policy-map-v1.json`](./install-gate-policy-map-v1.json)); it
  is the validation source of truth — keep it byte-identical across repos.

## `payload` shape

```jsonc
{
  "version": 1717250000,                 // int epoch of latest mutation
  "ecosystems": {                        // always present; per-ecosystem rule sets
    "pypi":  { "mode": "deny_list", "entries": [/* InstallGatePolicy rows */] },
    "npm":   { "mode": "deny_list", "entries": [] },
    "maven": { "mode": "deny_list", "entries": [] },
    "nuget": { "mode": "deny_list", "entries": [] },
    "apt":   { "mode": "deny_list", "entries": [] },
    "yum":   { "mode": "deny_list", "entries": [] }
  },
  "proxy_endpoints": {                   // always present; one per ecosystem
    "pypi":  "https://proxy.example.com/pypi/simple/",
    "npm":   "https://proxy.example.com/npm/",
    "maven": "https://proxy.example.com/maven2/",
    "nuget": "https://proxy.example.com/nuget/v3/index.json",
    "apt":   "https://proxy.example.com/apt/",
    "yum":   "https://proxy.example.com/yum/"
  },
  "trusted_registries": {                // OMITTED when empty (no rows configured)
    "pypi": [
      {
        "url":   "https://nexus.acme.com/repository/pypi/",
        "label": "ACME internal PyPI mirror",
        "auth": {                        // OMITTED per-entry when no auth configured
          "mode":  "bearer",             // "bearer" | "basic"
          "token": "<JWT or PAT>"        // present iff mode=bearer
          // "username", "password"      // present iff mode=basic
        }
      }
    ],
    "npm": [
      { "url": "https://nexus.acme.com/repository/npm/", "label": "ACME npm" }
    ]
  }
}
```

### Field semantics

| Field | Type | Notes |
|---|---|---|
| `version` | integer | Epoch (UNIX seconds) of the latest mutation of the effective policy set, computed as the **max-fold** of: (1) `max(updated_at)` over all policy rows (active or not — deactivation/soft-delete bump it via `onupdate`); (2) `max(expires_at)` over rows whose expiry boundary has passed; (3) `max(effective_at)` over rows whose activation boundary has passed; and (4) the trusted-registries document's `updated_at` **whenever that document exists** — including the non-empty → empty clearing write, so tearing down a corporate-mirror override always bumps the version (IG-CORR-S1-02). Agents apply an envelope only when `version` is **strictly greater** than their cached value and otherwise skip the apply step. `0` means no rules ever existed and no trusted-registries document has ever been written (fresh install). |
| `ecosystems.<eco>.mode` | string | `"deny_list"` or `"allow_list"`. When two rules in the same ecosystem disagree, the most-recently-updated one wins server-side; the value here reflects that resolution. |
| `ecosystems.<eco>.entries[]` | object[] | One per active rule. Each has `pattern` (glob/exact package coordinate), `version_range` (PEP 440 / semver / nullable), `severity` (one of `critical` / `high` / `medium` / `low` — the same four-level scale used by the policy engine; the JSON Schema types it as nullable string), `reason`, `scope_env_tag`, `expires_at` (ISO-8601 or null). |
| `proxy_endpoints.<eco>` | string \| null | Base URL of the Sentari-Proxy fallback per ecosystem; agent's writer points at this URL when no trusted registry is configured for that ecosystem. `null` when the operator hasn't enabled Sentari-Proxy for that ecosystem. |
| `trusted_registries` | object | Optional. When present, **per-ecosystem override** of `proxy_endpoints` — the agent's writer must prefer one of the URLs in this list over the proxy endpoint. Up to 6 entries per ecosystem (`_MAX_REGISTRIES_PER_ECOSYSTEM`). |
| `trusted_registries.<eco>[].url` | string | Required. Capped at 500 chars. |
| `trusted_registries.<eco>[].label` | string | Optional. Operator-supplied human label; may be empty. Capped at 80 chars. |
| `trusted_registries.<eco>[].auth` | object | Optional. **Cleartext credentials** the agent's writer applies to the native config file. Omitted when no auth is configured for the entry; omitted when decryption failed server-side (logged at ERROR, entry ships without auth so the writer fails closed against the mirror). |
| `trusted_registries.<eco>[].auth.mode` | string | `"bearer"` or `"basic"`. Future modes (`"oauth"`, `"mtls"`) need a v2 contract bump. |
| `trusted_registries.<eco>[].auth.token` | string | Present iff `mode == "bearer"`. Capped at 4096 chars (set at PUT time). |
| `trusted_registries.<eco>[].auth.username` | string | Present iff `mode == "basic"`. |
| `trusted_registries.<eco>[].auth.password` | string | Present iff `mode == "basic"`. |

### Credential lifecycle (informational)

Credentials are stored encrypted at rest in `system_config` with AES-256-GCM
+ AAD bound to the row key (see `server/services/secret_store.py`); the
encrypted sibling rows are addressed by a UUID stored on the public
`install_gate.trusted_registries` document. This envelope is the **only
egress point** at which the cleartext is reconstituted, and it appears only
inside the signed `payload` returned to the verifying agent. No audit-log
row, no server log line, and no other API response ever surfaces the
cleartext.

### Compatibility rules

- **`trusted_registries` is optional.** Agents predating PR #118 ignore it
  unconditionally; servers configured without any trusted registries omit
  the field. Both directions interoperate.
- **`auth` is optional per entry.** Agents predating this PR (PR-A of the
  credentials track) ignore the field — they apply the URL without
  credentials, which means private mirrors return 401 to them. This is
  intentional: the operator opting into a credentialed mirror MUST roll out
  the agent half before the credentials flow through. (Pre-rollout, GET
  `/policy-map` still returns the envelope with `auth` blocks; older
  agents just skip them.)
- **Field additions** to an entry (e.g. a future `priority` or `scope`
  field) MUST be additive; renames or removals are a v2 bump.
- **Mode additions** (e.g. `"oauth"`) MUST be additive — the agent's
  writer ignores unknown modes and falls back to URL-only application
  rather than failing the apply.
- **Signature scope.** `signature` covers the canonical-JSON
  serialisation of `payload` byte-for-byte; any modification by an
  intermediate must re-sign or be rejected.

## Verification by the agent

1. Fetch `GET /api/v1/agent/policy-map` via mTLS.
2. If 404 with `X-Sentari-Install-Gate-Disabled: true`, immediately
   tear down any local policy state (remove writer-managed config
   blocks); cache nothing.
3. If 200, verify `signature` over `canonical_json(payload)` with the
   public key learned at `/register` (`install_gate_pubkey`, identified
   by `key_id`).
4. On verification success, compare `payload.version` with the cached
   envelope's `version`. Skip the apply when equal.
5. Otherwise, hand `payload` to the per-ecosystem writers; each writer
   selects a trusted-registry URL (with optional `auth` block), falls
   back to `proxy_endpoints.<eco>`, and rewrites its native config
   file. Writers MUST emit credential files with `0600` permissions
   (POSIX) / ACL-restricted equivalent (Windows).

## Anti-patterns

- **Do not log the `payload` field at INFO or higher.** Credentials are
  inside it. The agent's apply path should debug-log _per-writer_
  outcomes ("wrote `/etc/pip.conf` with 1 source") and never the
  envelope contents.
- **Do not retain the verified `payload` past the apply step.** Once
  the writers have rewritten their config files, the payload is
  derivable from those files (modulo the credentials, which are
  intentionally not recoverable). Holding the parsed payload in
  memory beyond the apply leaves cleartext credentials live for an
  attacker who later snapshots the agent process.
- **Do not export the envelope unchanged to a third party.** It is
  scoped to the local apply; relaying it sideways re-exposes
  credentials outside the audited path.
