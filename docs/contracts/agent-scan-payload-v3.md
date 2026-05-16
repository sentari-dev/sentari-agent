# Agent Scan Payload — v3

Phase 3 of the multi-ecosystem workspace contract bumps the
`/agent/scan` payload from v2 to v3 by adding 4 new array fields:
`dep_edges`, `lockfiles`, `supply_chain_signals`, `license_evidence`.

## Versioning

The Go agent sets request header `X-Sentari-Payload-Version: 3` on
every scan upload. Server accepts both v2 and v3 during the rollout
window. Agents older than v3 continue working — server treats missing
fields as empty arrays.

## Fields

### `dep_edges: DepEdge[]`

One entry per direct or transitive dependency edge in any project the
agent discovered. Direct edges have `type='direct'` and `depth=0`.
Transitive edges have `type='transitive'` and `depth>=1`, with an
`introduced_by_path` chain of intermediate package names that link
the transitive back to a direct dependency.

```json
{
  "parent_name": "myapp",
  "parent_version": "1.0.0",
  "child_name": "lodash",
  "child_version": "4.17.21",
  "ecosystem": "npm",
  "type": "transitive",
  "scope": "runtime",
  "depth": 2,
  "introduced_by_path": ["myapp", "express", "lodash"],
  "resolved": true
}
```

`resolved=false` is reserved for Maven BOM-imported deps that the
agent could not fully resolve without a `mvn` invocation (out of
scope per the no-binary-invocation constraint).

### `lockfiles: LockfileMeta[]`

One entry per discovered lockfile. The agent does NOT upload lockfile
contents — only the metadata. The server uses sha256 to detect drift
between scans.

```json
{
  "path": "/home/dev/project/package-lock.json",
  "format": "package_lock_v3",
  "ecosystem": "npm",
  "sha256": "abc123...",
  "last_modified": "2026-05-15T10:00:00Z",
  "declared_packages_count": 247,
  "drift_status": "in_sync"
}
```

Format enum: `package_lock_v2`, `package_lock_v3`, `yarn_v1`,
`yarn_berry`, `pnpm_lock`, `pom_xml`, `packages_lock_json`,
`project_assets_json`, `poetry_lock`, `uv_lock`, `pipfile_lock`,
`requirements_txt`.

### `supply_chain_signals: SupplyChainSignal[]`

One entry per agent-detected supply-chain signal. Agent-side signals
are limited to what local file inspection can determine:
postinstall/preinstall/install scripts in `package.json`, signed-pkg
state (npm sigstore, Maven `.asc`, NuGet `.signature.p7s`), PyPI
yanked-version flag (from local pip metadata cache).

Server-side enrichment (deprecation flags, maintainer changes,
typosquat heuristics, GHSA Malware advisories) is added by Celery
tasks and stored in the same table — they do NOT come from the
agent payload.

Signal-type enum (agent subset):
`postinstall_script`, `preinstall_script`, `install_script`,
`unsigned`, `provenance_attested`, `yanked`.

### `license_evidence: LicenseEvidence[]`

Per-package license rows collected agent-side per ecosystem. Replaces
Phase 2's Trove-only backfill with the real per-ecosystem sources:
PyPI PEP 639 license-expression (preferred over Trove), npm
`package.json` license/licenses, Maven POM `<licenses>`, NuGet
`.nuspec` license/licenseUrl. Server's `package_licenses` table
ingests these rows directly — see `services/license_ingest.py`.

```json
{
  "package_name": "requests",
  "package_version": "2.31.0",
  "ecosystem": "pypi",
  "spdx_id": "Apache-2.0",
  "source": "spdx_pkg",
  "confidence": 0.95,
  "raw_text": "Apache-2.0"
}
```

## Backwards compatibility

- Old agents (no v3 fields) → server stores empty arrays; the workspace
  pages render the Phase-2 empty state honestly.
- New agents talking to old servers (rollback scenario) → server logs
  warnings about unknown fields but accepts the payload (Pydantic
  models use `extra='ignore'`).
