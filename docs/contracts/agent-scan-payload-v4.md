# Agent Scan Payload — v4

v4 is the shared, **additive** successor to v3. Per the compliance-expansion
index **R1** there is exactly **one** v4 payload:

```
v4 = v3
   + host_facts            (optional object)   — asset-register spec (NOT YET LANDED)
   + os_applications        (optional array)    — asset-register spec (NOT YET LANDED)
   + hardening_observations (optional array)    — hardening-posture spec (THIS block)
```

All three blocks are **optional**, so a v4 agent that emits only one of them is
valid and a **mixed v3/v4 fleet coexists indefinitely**. This file currently
defines the v3 fields plus the **`hardening_observations`** block only; the
`host_facts` / `os_applications` blocks are appended to this same pair (never a
v5) by the asset-register PR when it lands. The `.json` JSON Schema is the
**source of truth** and must stay **byte-identical** in `docs/contracts/` of
both repos (`sentari` + `sentari-agent`) — the contract-sync review gate on both
PRs enforces this.

> **Cross-repo status (this wave):** the server side of the
> `hardening_observations` block lands first; the byte-identical copy in
> `../sentari-agent/docs/contracts/` and the Go collectors that emit the block
> are a **follow-up** (hardening PR B, sibling repo). No agent code is in this
> wave.

## Versioning

The Go agent sets the **advisory** request header `X-Sentari-Payload-Version: 4`
on every scan upload that carries a v4 block. The accepted header set is
`{"2", "3", "4"}` and the version is **advisory only** — ingestion is **not**
gated on the header. Instead each block is **shape-gated** on the server: a
`has_v4_payload` guard (mirroring v3's `has_v3_payload`) keys off the body
shape, so `hardening_observations` is ingested independently of the other v4
blocks and of the v3 arrays.

Back-compat is total in both directions:

- An **old v3 agent** omits `hardening_observations` ⇒ the server treats it as
  an empty list (standard missing-field rule).
- A **new v4 agent talking to an old server** has the array silently dropped by
  the server's Pydantic `extra="ignore"` — no 422 hazard.

Server accepts v2, v3 and v4 headers **indefinitely** (same policy as v2/v3).

## Privacy posture (read by customer DPOs)

**No file contents, no secrets, no user data cross the wire.** Each
`hardening_observation` carries only the **named keyword value** the check
consumes (e.g. `ssh.permit_root_login = "prohibit-password"`), its
`source_path`, and the `source_sha256` of the parsed file. The SHA lets the
server detect configuration drift between scans **without the file body ever
leaving the device** — the exact `lockfiles` metadata pattern from v3 (path +
sha256, never the file body). This keeps the payload defensible in front of
works-councils / DPOs (constraint #2 posture). Every read is a file / `/proc` /
registry-API / plist read through the agent's existing `safeio` read-cap +
symlink discipline — never a binary invocation (`sshd -T`, `fdesetup`,
`auditpol`, `nft`, CIS-CAT are all forbidden, constraint #7).

## Fields

### `hardening_observations: HardeningObservation[]`

Optional flat list of **raw observed values** — facts, not verdicts. The agent
emits what it read; the **server** evaluates each fact against the bundled,
versioned `hardening-v1` baseline catalog (CIS Benchmark + DISA STIG rule-id
cross-references + NIS2/DORA/CRA mappings). This "facts on the agent, judgement
on the server" split is deliberate: a catalog bump re-scores the whole fleet
from already-collected facts, with **no agent release and no rescan** (the same
"server is authoritative" split proven by runtime `cycle` re-derivation in v3).

Example entry:

```json
{
  "key": "ssh.permit_root_login",
  "family": "ssh",
  "value": "prohibit-password",
  "default_assumed": false,
  "source_path": "/etc/ssh/sshd_config",
  "source_sha256": "a3b4…64hex",
  "error": null
}
```

| Field | Type | Notes |
|---|---|---|
| `key` | string, ≤128 | Namespaced observation id `<family>.<slug>`. The v1 vocabulary is documented below but the enum is **not closed** — an unknown key is **dropped with a warning at ingest, never 422** (a deliberate deviation from `installed_runtimes`' strict name validation: this vocabulary grows every catalog cycle and a newer agent must never lose a whole scan to an older server). |
| `family` | string, ≤32 | One of the v1 families below. Free-form at ingest (length-capped, **no** DB CHECK) so a future family value never 500s a scan — the `DeviceContainer.runtime` tolerance precedent. |
| `value` | string ≤2048 \| null | Observed value as a canonical string (booleans `"true"`/`"false"`, lists comma-joined in source order), or `null` when the source was unreadable. Server **clamps** to 2048, never rejects. |
| `default_assumed` | boolean | `true` when the keyword was **absent** and the emitted `value` is the documented platform default (SSH/Schannel cases). The server surfaces this so an auditor can distinguish "explicitly configured" from "inherited default". Defaults `false` when omitted. |
| `source_path` | string \| null | Provenance path. Registry/API-sourced observations carry a stable pseudo-path like `registry:HKLM\...` and a null sha. |
| `source_sha256` | string \| null | Lowercase 64-hex SHA-256 of the parsed source file (drift detection). A malformed value is stored `NULL` at ingest, never rejected. |
| `error` | string ≤255 \| null | Short reason when `value` is null (`"permission denied"`, `"not found"`, `"conditional (Match block)"`). ⇒ the check evaluates to **`unknown`**, never a guess. |

**Payload cap:** ≤256 observations per scan (schema `maxItems`; the server also
enforces this defensively at ingest).

### v1 observation vocabulary (families + representative keys)

Observability tiers are explicit and honest: **full** = authoritative local
source; **partial** = enablement-evidence-only or system-level-only; anything
unreadable or absent ⇒ the observation is emitted with `value: null` + `error`,
and the server evaluates it to **`unknown`** (never a guess). Every partial /
unknown tier is recorded in the server catalog's honesty ledger
(`not_assessed_refs`).

| Family | Representative keys | Tier notes |
|---|---|---|
| `disk_encryption` | `disk_encryption.root_encrypted` | Linux dm-crypt/LUKS (full); Windows BitLocker via raw PhysicalDrive read — absent signature ⇒ `unknown`, never FAIL (partial); macOS FileVault enablement-evidence only ⇒ absence is `unknown` (partial). |
| `ssh` | `ssh.permit_root_login`, `ssh.password_authentication`, `ssh.permit_empty_passwords`, `ssh.ciphers`, `ssh.macs`, `ssh.kex_algorithms`, `ssh.protocol`, `ssh.x11_forwarding`, `ssh.max_auth_tries`, `ssh.login_grace_time`, `ssh.client_alive_interval` | Parse `sshd_config` + `Include` globs, first-obtained-wins; a keyword seen only inside a `Match` block is emitted with `error:"conditional (Match block)"` ⇒ `unknown`. Unset ⇒ `value:"(default)"`, `default_assumed:true`. |
| `tls` | `tls.min_version`, `tls.ciphers` | From detected nginx/httpd conf or IIS Schannel registry (config-derived, not runtime-negotiated — partial). Never opens a socket (constraint #4). |
| `firewall` | `firewall.enabled` | ufw/firewalld/nftables config+enablement (partial — not the live kernel ruleset); Windows FirewallPolicy registry (full); macOS ALF plist (partial, version-dependent). |
| `auth_policy` | `auth_policy.pass_max_days`, `auth_policy.pass_min_days`, `auth_policy.pass_min_len`, `auth_policy.pass_min_class`, `auth_policy.faillock_deny`, `auth_policy.faillock_unlock_time` | `/etc/login.defs` + pwquality + faillock (full Linux); Windows account policy lives in the locked SECURITY hive ⇒ `unknown` (partial, ledgered). |
| `audit_daemon` | `audit_daemon.enabled` | Linux auditd unit + rules (full); Windows/macOS `unknown` in v1 (ledgered). |
| `auto_update` | `auto_update.enabled` | apt `20auto-upgrades` / dnf-automatic (full Linux); Windows WindowsUpdate\AU registry (full); macOS SoftwareUpdate plist (full). |
| `screen_lock` | `screen_lock.enabled`, `screen_lock.timeout_secs` | Linux system dconf (partial — system-level only); Windows `unknown` in v1 (user-scoped ADMX, ledgered); macOS screensaver plist (partial). |
| `kernel` | `kernel.randomize_va_space`, `kernel.ip_forward`, `kernel.accept_redirects`, `kernel.send_redirects`, `kernel.tcp_syncookies`, `kernel.protected_symlinks`, `kernel.kptr_restrict`, `kernel.rp_filter` | Linux `/proc/sys` reads (full); `not_applicable` on Windows/macOS. |

> The exact key set the server catalog consumes is the source of truth in
> `server/services/hardening/catalog.py` (`hardening-v1`). A lock-step server
> test asserts every catalog `observation_keys` entry is documented here — a
> contract-drift tripwire.

> **Conservative default handling (intentional deviation from §1.1):** §1.1
> permits scoring an *unset* keyword against the modern-OpenSSH compiled-in
> default when that default is baseline-safe. The `hardening-v1` server
> evaluator does **not** do this — an unset keyword arrives as the `(default)`
> sentinel and scores **`unknown`**, never a synthesized PASS. This is stricter
> than the spec allows and never green-washes an unconfigured host; if a future
> catalog revision opts into baseline-safe defaults it must bump
> `catalog_version`.
