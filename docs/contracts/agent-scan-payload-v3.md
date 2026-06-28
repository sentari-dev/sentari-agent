# Agent Scan Payload — v3

Phase 3 of the multi-ecosystem workspace contract bumps the
`/agent/scan` payload from v2 to v3 by adding 4 new array fields:
`dep_edges`, `lockfiles`, `supply_chain_signals`, `license_evidence`.
Phase 4 adds a 5th v3 array field, `installed_runtimes`, transported
under the same v3 payload version.

## Versioning

The Go agent sets request header `X-Sentari-Payload-Version: 3` on
every scan upload. Server accepts both v2 and v3 during the rollout
window. Agents older than v3 continue working — server treats missing
fields as empty arrays.

## Fields

### `dep_edges: DepEdge[]`

One entry per direct or transitive dependency edge in any project the
agent discovered. `depth` is the number of nodes in
`introduced_by_path` minus one — equivalently, the count of edges
traversed from the root project down to the child. Direct edges
(root → child) have `type='direct'`, a two-element path, and
`depth=1`. Transitive edges have `type='transitive'` and `depth>=2`.
The `introduced_by_path` field is the full resolution path from root
to leaf, **inclusive of both endpoints** — for the example below,
`["myapp", "express", "lodash"]` means: root project (`myapp`) →
`express` → `lodash`, a transitive edge at `depth=2`.

npm-specific edge types `peer`, `optional`, `dev`, and `test` (the
latter rare; npm has no first-class `test` scope but the contract
reserves it for Maven `test` scope and similar) follow the same
`depth` and `introduced_by_path` rules as `direct`/`transitive`.

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

`scope` is an ecosystem-specific free-form string. Expected values
include `runtime`, `dev`, `optional`, `peer` for npm;
`compile`/`runtime`/`test`/`provided` for Maven; the contract does
not enforce an enum so each scanner emits the native scope label.

`resolved=false` is reserved for Maven BOM-imported deps that the
agent could not fully resolve without a `mvn` invocation (out of
scope per the no-binary-invocation constraint). When `resolved=false`,
`parent_version` and/or `child_version` may be the empty string `""`
if the agent could not determine the version from local files; the
JSON Schema still requires the keys to be present so downstream
consumers can rely on the field shape.

### `lockfiles: LockfileMeta[]`

One entry per discovered lockfile. The agent does NOT upload lockfile
contents — only the metadata. The server uses sha256 to detect drift
between scans.

```json
{
  "path": "/home/dev/project/package-lock.json",
  "format": "package_lock_v3",
  "ecosystem": "npm",
  "sha256": "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4",
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
`unsigned`, `provenance_attested`, `yanked`,
`maven_checksum_mismatch`, `maven_snapshot_in_release`,
`maven_untrusted_repo`.

The JSON Schema enum additionally includes server-only values
(`deprecated`, `maintainer_changed`, `typosquat_suspect`, and the
per-ecosystem GHSA-Malware variants `npm_malware_advisory`,
`pypi_malware_advisory`, `maven_malware_advisory`,
`nuget_malware_advisory`) that Celery enrichment tasks write to the
same table. The GHSA Malware database is multi-ecosystem, so the
enrichment path emits `<ecosystem>_malware_advisory` to keep the
ecosystem label correct rather than mislabelling every hit as `npm_*`.
Agents MUST NOT emit any of these.

The three Maven-specific agent signals (`maven_checksum_mismatch`,
`maven_snapshot_in_release`, `maven_untrusted_repo`) are emitted by
the agent's JVM scanner when it detects a checksum verification failure,
SNAPSHOT artifacts in a release environment, or packages fetched from
non-central / untrusted repositories. They are NOT server-only.

`source` is a free-form string. Agent-emitted signals should set it
to the scanner module name (e.g. `npm-postinstall-scanner`,
`pypi-yanked-cache`); the literal `agent` is reserved as a generic
fallback when no more specific module name applies.

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

`source` enum:

- Agent-emitted in Phase 3: `spdx_pkg` (npm `package.json`, PyPI PEP
  639), `trove` (PyPI Trove classifiers), `pom` (Maven), `nuspec`
  (NuGet).
- Reserved for the OS-package scan paths (APT/YUM agents — Phase 1):
  `copyright_file` (Debian DEP-5), `rpm_header` (RPM spec metadata).
  Agents for the 4 Phase-3 ecosystems MUST NOT emit these.
- Reserved for server-side enrichment writes (Celery tasks against
  `package_licenses`): `server_enriched`. Agents MUST NOT emit it.

### `installed_runtimes: InstalledRuntime[]`

Per-device runtime detections. Covers language runtimes (`python`, `node`,
`jdk`) and JVM application servers (`wildfly`, `jboss-eap`, `tomcat`,
`jetty`, `payara`, and presence-only `weblogic`/`websphere`). Other
runtimes are reserved for future phases.

```json
{
  "name": "jdk",
  "version": "17.0.5+8",
  "cycle": "17",
  "distro": "Temurin",
  "install_path": "/usr/lib/jvm/temurin-17"
}
```

`cycle` is derived agent-side using the regex documented per runtime:

| Runtime | Version example | Cycle | Rule |
|---------|-----------------|-------|------|
| python  | `3.11.5`        | `3.11` | First two dot-separated components. |
| node    | `20.10.0`       | `20`   | Major version only. |
| jdk     | `17.0.5+8`      | `17`   | Major version only. |
| jdk     | `1.8.0_392`     | `8`    | Legacy `1.X` → `X`. |
| wildfly   | `40.0.1.Final`  | `40`   | Leading major. |
| jboss-eap | `7.4.0.GA`      | `7.4`  | Major.minor. |
| tomcat    | `10.1.18`       | `10`   | Leading major. |
| jetty     | `12.0.5`        | `12.0` | Major.minor. |
| payara    | `6.2024.5`      | `6`    | Leading major. |
| weblogic / websphere | `unknown` | `unknown` | Presence-only; no public EOL feed. |

Server re-derives `cycle` independently and logs a warning when the
agent's value disagrees, but always uses the server-derived value.

`distro` is emitted only for JDK installs, normalized from the
`IMPLEMENTOR` field of `<JAVA_HOME>/release`. Recognized canonical
values: `Temurin` (normalized from `Eclipse Adoptium` / `AdoptOpenJDK`),
`Corretto` (Amazon), `Zulu` (Azul), `Microsoft`, `Oracle`. Unknown
vendor strings pass through unchanged so the dashboard can surface
whatever the JDK reports. For Python and Node runtimes, the field is
omitted entirely (the Go struct uses `omitempty`); JSON Schema
permits `null` for back-compat with consumers that read the field
unconditionally.

## Backwards compatibility

- Old agents (no v3 fields) → server stores empty arrays; the workspace
  pages render the Phase-2 empty state honestly.
- New agents talking to old servers (rollback scenario) → server logs
  warnings about unknown fields but accepts the payload (Pydantic
  models use `extra='ignore'`).

## Base-payload additions (apt/yum CVE-correctness slice)

Two **optional** fields were added to the base scan payload (the
device + `packages[]` shape defined by the Go structs `scanner/types.go`
and the Pydantic models `server/api/v1/agent.py` — there is no JSON
Schema file for the base payload; this v3 schema covers only the five
additive arrays above). Both are additive and backward-compatible, so
the payload version stays **v3** (header `X-Sentari-Payload-Version: 3`).

- **`os_release`** — top-level object `{"id": string, "version_id": string}`,
  from the host's `/etc/os-release`. The server derives a release-keyed
  distro CVE partition (`debian:12`, `rocky:9`) for `system_deb` /
  `system_rpm` packages from it. **Omitted** on non-Linux hosts or when
  `/etc/os-release` is unreadable; a missing key, `null`, or empty
  `version_id` are all treated identically as "release unknown", and the
  server falls back to a release-less sentinel partition (no false PyPI
  correlation). Scan-only — NOT part of the registration contract.
- **`source_package`** — optional string on each `packages[]` record
  (`system_deb` / `system_rpm` only). dpkg `Source:` / rpm `SOURCERPM`
  source name, so the server can match a binary like `libssl3` against a
  source-keyed advisory (`openssl`). Absent, `null`, or `""` all mean
  "no source".

Both degrade gracefully both directions: an old agent omits them
(server → sentinel partition); a new agent talking to an old server has
them dropped by Pydantic `extra='ignore'`.
