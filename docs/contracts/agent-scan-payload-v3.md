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
traversed from the root project down to the child. The identity
`depth == len(introduced_by_path) - 1` holds for **every** edge,
without exception.

`type='direct'` means the dependency is declared in the manifest of
the root project **or** of a workspace / reactor module belonging to it
(npm/pnpm/yarn workspaces, a Maven reactor's modules). A direct edge on
the root project itself is `["root", "child"]` at `depth=1`. A direct
edge contributed by a reactor module traces `root → module → dependency`
and therefore **may have `depth>1`** — e.g. `depth=2` with the
three-element path `["root", "module", "child"]`. There is thus no
blanket `direct ⟺ depth=1` rule; only `depth == len(introduced_by_path)
- 1` is invariant. `type='transitive'` edges are pulled in indirectly
and always have `depth>=2`. The `introduced_by_path` field is the full
resolution path from root to leaf, **inclusive of both endpoints** — for
the example below, `["myapp", "express", "lodash"]` means: root project
(`myapp`) → `express` → `lodash`, a transitive edge at `depth=2`.

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

When a scanner cannot determine the root project's name (no manifest
name field, or a bare `node_modules` / `packages.lock.json` /
installed-package set with no owning project), it substitutes the
literal sentinel `(unknown)` as the synthetic root node. Such edges
still obey the `depth` / `introduced_by_path` rules — a direct child of
an unknown root is `["(unknown)", "<child>"]` at `depth=1`. Consumers
should treat `(unknown)` as "root project name unavailable", not as a
real package name (`scanner/deptree/{npm_yarn,nuget,pypi}.go`).

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
`jdk`), JVM application servers (`wildfly`, `jboss-eap`, `tomcat`,
`jetty`, `payara`, `glassfish`, and presence-only `weblogic`/`websphere`),
web servers (`nginx`, `apache-httpd`, `iis`), and message brokers
(`rabbitmq`, `kafka`, `activemq`, `activemq-artemis`).
Other runtimes are reserved for future phases.

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
| wildfly   | `40.0.1.Final`  | `40.0`   | Major.minor, then major.¹ |
| jboss-eap | `7.4.0.GA`      | `7.4`    | Major.minor, then major.¹ |
| tomcat    | `10.1.18`       | `10.1`   | Major.minor, then major.¹ |
| jetty     | `12.0.5`        | `12.0`   | Major.minor, then major.¹ |
| payara    | `6.2024.5`      | `6.2024` | Major.minor, then major.¹ |
| glassfish | `7.0.11`        | `7.0`    | Major.minor, then major.¹ Eclipse GlassFish (upstream of Payara). |
| weblogic / websphere | `14.1.1.0` / `unknown` | `14.1` / `unknown`¹ | Presence-only; no public EOL feed. |
| nginx         | `1.24.0`        | `1.24`   | Major.minor, then major.¹ |
| apache-httpd  | `2.4.58`        | `2.4`    | Major.minor, then major.¹ |
| iis           | `10.0`          | `10.0`   | Major.minor, then major.¹ |
| rabbitmq         | `3.12.0`  | `3.12` | Major.minor, then major.¹ |
| kafka            | `3.7.0`   | `3.7`  | Major.minor, then major.¹ |
| activemq         | `5.18.3`  | `5.18` | Major.minor, then major.¹ |
| activemq-artemis | `2.33.0`  | `2.33` | Major.minor, then major.¹ |

¹ For application servers, web servers, and message brokers the
agent-derived `cycle` is **advisory**.
endoflife.date cohort granularity is inconsistent per product (Tomcat `10.1`
but also `7`; JBoss EAP `7` but also `4.3`; Jetty `12.0` but also `11`), so the
server resolves the authoritative cohort against the synced feed by
longest-dotted-prefix at ingest (`runtime_eol_cycle.resolve_feed_cycle`).

Server re-derives `cycle` independently and logs a warning when the
agent's value disagrees, but always uses the server-derived value.

`distro` carries the runtime vendor. For **JDK** installs it is
normalized from the `IMPLEMENTOR` field of `<JAVA_HOME>/release`.
Recognized canonical JDK values: `Temurin` (normalized from
`Eclipse Adoptium` / `AdoptOpenJDK`), `Corretto` (Amazon), `Zulu`
(Azul), `Microsoft`, `Oracle`. Unknown vendor strings pass through
unchanged so the dashboard can surface whatever the JDK reports.

For **JVM application servers** the agent also emits a fixed vendor
`distro` per product (`scanner/runtimeversions/appserver.go`,
`scanner/jvm`): `Red Hat` for `wildfly` / `jboss-eap`, `Apache` for
`tomcat`, `Eclipse` for `jetty`, `Payara` for `payara`,
`Eclipse GlassFish` for `glassfish`, `Oracle` for
`weblogic`, `IBM` for `websphere`. Server tests assert these vendor
values are preserved end-to-end.

For **Python and Node** runtimes the field is omitted entirely (the Go
struct uses `omitempty`); JSON Schema permits `null` for back-compat
with consumers that read the field unconditionally.

## Backwards compatibility

- Old agents (no v3 fields) → server stores empty arrays; the workspace
  pages render the Phase-2 empty state honestly.
- New agents talking to old servers (rollback scenario) → server logs
  warnings about unknown fields but accepts the payload (Pydantic
  models use `extra='ignore'`).

## Base-payload additions

Several **optional** fields were added to the base scan payload over
successive slices (the device + `packages[]` shape defined by the Go
structs `scanner/types.go` and the Pydantic models
`server/api/v1/agent.py`). There is **no JSON Schema file for the base
payload** — the `agent-scan-payload-v3.json` schema covers only the five
additive v3 arrays above, and its top-level object does not model
`packages[]` at all (packages are open objects on the wire), so
per-package additions below do NOT require a schema change. All fields
here are additive and backward-compatible, so the payload version stays
**v3** (header `X-Sentari-Payload-Version: 3`). Each degrades both
directions: an old agent omits the field; a new agent talking to an old
server has it dropped by Pydantic `extra='ignore'`.

### apt/yum CVE-correctness slice

- **`os_release`** — top-level object `{"id": string, "version_id": string,
  "kernel"?: string}`, from the host's `/etc/os-release` plus the kernel
  release. The server derives a release-keyed distro CVE partition
  (`debian:12`, `rocky:9`) for `system_deb` / `system_rpm` packages from
  `id`/`version_id`. `id`/`version_id` are **omitted** on non-Linux hosts or
  when `/etc/os-release` is unreadable; a missing key, `null`, or empty
  `version_id` are all treated identically as "release unknown", and the
  server falls back to a release-less sentinel partition (no false PyPI
  correlation). `kernel` is an optional kernel release string (`uname -r`
  equivalent: `/proc/sys/kernel/osrelease` on Linux, `kern.osrelease` on
  macOS, `major.minor.build` on Windows), max 64 chars, **absent on older
  agents**; the server stores it per-device and represents it as a
  `linux_kernel` component in generated SBOMs (Linux only). Because `kernel`
  can be carried on its own, `os_release` may now be present on non-Linux (or
  degraded-Linux) hosts with **empty** `id`/`version_id` purely to convey
  `kernel`; an empty `id` means "distro not reported" and never clears the
  server's stored distro identity. Scan-only — NOT part of the registration
  contract.
- **`source_package`** — optional string on each `packages[]` record
  (`system_deb` / `system_rpm` only). dpkg `Source:` / rpm `SOURCERPM`
  source name, so the server can match a binary like `libssl3` against a
  source-keyed advisory (`openssl`). Absent, `null`, or `""` all mean
  "no source".

### Container-origin package fields

Populated only when the scan ran inside a container's merged rootfs
(Sprint-17 container-image scanner, opt-in via the agent's
`ScanContainers` config); empty/absent on every host-filesystem record.
The server models these on `PackageRecord` so they survive into the
archived `scan_results.raw_json` for the planned container-origin
inventory UI — there are **no dedicated DB columns yet** (archive-only
persistence). Field names mirror the Go json tags in `scanner/types.go`
exactly:

- **`container_image_id`** — string, image digest/ID the package's rootfs
  came from. Server-side "show me CVEs inside containers" filters key on
  this being non-empty.
- **`container_image_tags`** — array of strings, human-readable image
  tags. **Nil/omitted** when the agent has no tags (Go `omitempty` on the
  slice → server models it as `list[str] | None`); `[]` and `null` both
  mean "no tags".
- **`container_id`** — string, the running container's ID (empty for
  image-only scans).
- **`container_name`** — string, the running container's name (empty for
  image-only scans).
- **`container_runtime`** — string, the container runtime that produced
  the image/container (`docker`, `containerd`, `podman`, …).

### per-artifact evidence slice

Two optional fields on each `packages[]` record carry per-artifact evidence
for two NTIA SBOM minimum elements (artifact hash + supplier). Both are open-
object package additions (no v3-schema change; old servers drop them via
Pydantic `extra='ignore'`), so there is **no 422 hazard** on an older server.

- **`sha256`** — optional string, lowercase 64-hex SHA-256 of the installed
  artifact **file**, emitted only when exactly one concrete file exists.
  **Omitted** for multi-file OS packages (`system_deb` / `system_rpm` — a
  file *set*, no single artifact; the server then omits the SBOM hash key
  rather than fake one), for unhashable installs, and by agents that predate this field.
  Server behavior: the value is validated and case-normalized at persist time
  (valid 64-hex → stored lowercased; wrong length / non-hex / empty → stored
  NULL, and the scan is **never rejected** for a malformed value). Emitted in
  the SBOM as CycloneDX `hashes:[{"alg":"SHA-256",...}]` / SPDX
  `checksums:[{"algorithm":"SHA256",...}]`; on a fleet SBOM a coordinate's
  hash is emitted only when every device that reported one agrees (consensus).
- **`supplier`** — optional string, supplier from **locally readable**
  metadata only (deb `Maintainer:`, the installed `package.json` `author`,
  the IDE extension `Publisher`) — never a registry lookup (air-gap,
  constraint #2). Absent, `null`, or `""` all mean "not derivable" (common for
  language ecosystems); the server stores NULL and the SBOM omits the field.
  Server behavior: stripped and truncated to 255 characters at persist time.
  Emitted as CycloneDX `supplier:{"name":...}` / SPDX
  `supplier:"Organization: <value>"`. Self-declared and unauthenticated — not
  a provenance attestation.

### Go binary module records

Go compilers embed the complete module dependency graph inside every
module-built executable. The agent reads this metadata directly from the
binary file (it never executes a scanned binary) and emits one `packages[]`
record per embedded module.

- **`env_type: "go_binary"`** — the literal reported on each such record. One
  record is emitted for the binary's **main module**, one for **each
  dependency**, and one for the Go **standard library** (name `stdlib`, version
  set to the embedded toolchain version, e.g. `go1.23.4`). Servers ingest
  `go_binary` records under the `go` ecosystem.
- **`install_path`** — the absolute path of the binary the module was read
  from. The same module compiled into two binaries yields two records with
  distinct `install_path` values, so an operator can tell which binary to
  rebuild; fleet-level de-duplication is a server concern.
- **Versions** are recorded verbatim: released dependencies as `vX.Y.Z`,
  unreleased ones as Go pseudo-versions
  (`v0.0.0-<timestamp>-<revision>`). A locally-built main module reports its
  VCS revision when the build recorded one, otherwise the toolchain's `(devel)`
  placeholder. **Replace directives** are resolved to the replacement — the
  module actually compiled in — and only the replacement is emitted.
- Open-object addition: like the other `packages[]` fields above, this is
  **not** part of the v3 JSON schema and requires no schema change; a server
  that predates the `go` ecosystem drops these records via Pydantic
  `extra='ignore'` (no 422). **Absent on older agents** that lack the detector.

### Device-level base fields

- **`tags`** — top-level array of operator-supplied host tags from
  `[agent] tags = …`. **Tri-state** on the wire (Go `*[]string`):
  `nil`/omitted ⇒ field absent (older agent / no `[agent]` section) ⇒
  server leaves `device.tags_agent` untouched; `[]` ⇒ operator wrote
  `tags =` with no values ⇒ server **clears** all agent-sourced tags;
  `[...]` ⇒ server applies the canonical list. Plain `omitempty` would
  conflate the first two, so the distinction is deliberate.
- **`runtime`** — top-level string host classification, one of
  `bare_metal`, `container`, `k8s`, `unknown`. Sent on every scan; the
  server runs a propose-then-approve workflow (first detection
  auto-accepts, later changes create an admin proposal). Empty string /
  omitted is back-compat for older agents ⇒ server leaves
  `device.runtime` untouched.
- **`container_targets`** — top-level array summarising every
  container/image the agent's container discoverer enumerated this scan
  cycle (`{runtime, image_id, image_tags[], container_id, container_name,
  layer_count, layer_digests[]}`). Promoted server-side into the
  `device_containers` current-state table and emitted as a `container`
  SBOM component (base-image digest + layer chain). Populated only when
  `ScanContainers` is true or the discoverer is explicitly invoked;
  otherwise nil/omitted.
  - **`layer_digests`** — optional ordered array of the image's layer
    `diff_ids`, **bottom-to-top** (the OCI image-config `rootfs.diff_ids`
    order; semantic — never sorted). Each entry is a `sha256:<64-hex>`
    string. Absent on pre-Phase-7 agents and on engines whose local store
    does not expose digests (containerd; podman chains missing a
    `diff-digest`). For a **running container** the list carries only the
    base image's chain, so it may be **shorter than `layer_count`** (the
    writable upper layer has no digest) — the two fields are deliberately
    not tied together. The server sanitizes defensively (drops non-sha256
    entries, caps the list) and never rejects a scan over this field.
