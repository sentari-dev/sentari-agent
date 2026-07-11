# Agent Audit-Log Ship Contract — v1

> **Status:** implemented on **both** sides. Server: `POST /api/v1/agent/audit-log`
> (`server/api/v1/agent.py` → `server/services/agent_audit_ingest.py`). Agent:
> `comms.Client.ShipAudit` drains `audit.UnshippedEntries()` → POST →
> `MarkShipped` after each successful batch (`sentari-agent`, enterprise serve
> loop). This file and `agent-audit-ship-v1.json` are mirrored **byte-identical**
> across the `sentari` and `sentari-agent` repos, same as `agent-scan-payload-v3.*`;
> the `.json` schema is the validation source of truth.

## Why

The agent keeps a local, append-only SHA-256 hash chain of its own actions
(`audit/audit.go`). On a device that may be locally compromised, on-device
append-only triggers are **not** a security boundary — a root attacker can
drop the triggers and recompute a self-consistent chain. The chain only
becomes genuinely tamper-*evident* once an independent party witnesses it.

This endpoint is that party. The agent periodically ships its un-shipped
entries; the server re-verifies them and stores them as append-only
forensic records. Any divergence between what the server already witnessed
and a later re-ship (or a broken/forked chain within a batch) raises an
integrity alert.

## Endpoint

```
POST /api/v1/agent/audit-log
```

- **Auth:** mTLS client certificate (same as `/scan`); role `agent`.
- **Device binding:** when mTLS is enforced, `device_id` MUST equal the
  device bound to the client certificate. A mismatch returns `403` — an
  agent cannot ship audit evidence attributed to a *different* device.
  (When `SENTARI_MTLS_REQUIRED=false`, there is no cert identity to bind
  to and the declared `device_id` is used as-is.)
- **Always returns `202 Accepted`** — even when verification fails. A
  detected violation is reported in the response body and raised as an
  alert, never rejected, so the evidence is preserved server-side.
- Resolution order: `device_id` is parsed (`422` if not a UUID), then the
  device is resolved (`403` on cert mismatch, else `404` if unknown),
  *then* entries are processed. An empty `entries` array is a valid `202`
  no-op; a malformed entry is a `422` at request binding.
- A machine-checkable schema lives alongside this doc
  ([`agent-audit-ship-v1.json`](./agent-audit-ship-v1.json)) — it is the
  validation source of truth; keep it byte-identical across repos.

### Request body

```jsonc
{
  "device_id": "f1e2d3c4-...",        // UUID of the registered device
  "entries": [
    {
      "entry_id": 1,                   // agent-local row id (>= 1, monotonic)
      "event_type": "scan_started",
      "detail": "envs=3",
      "content_hash": "<64 hex>",      // see "Hash encodings" below
      "prev_hash": "",                 // previous entry's content_hash; "" for genesis
      "created_at": "2026-05-23T10:00:00.000000001Z", // EXACT RFC3339Nano string hashed
      "hash_version": 2                // encoding of content_hash; optional, default 1
    }
  ]
}
```

**Critical:** `created_at` must be the *exact* string the agent fed into
the hash. The server recomputes `content_hash` byte-for-byte; any
reformatting (e.g. truncating nanoseconds) breaks verification.

### Hash encodings (`hash_version`)

`hash_version` names the encoding of `content_hash`. It is **optional and
additive**: entries shipped by a pre-v2 agent omit it and the server defaults
to **1**. New agents send **2**. Values are constrained to `1..2`. Linkage
(`prev_hash` chaining) is scheme-independent, so a single chain may mix v1 and
v2 rows and still verify.

- **v1 — legacy plain concatenation** (default when absent):

  ```
  content_hash = sha256(event_type + detail + prev_hash + created_at)
  ```

  The fields are concatenated with **no delimiters**, so the field boundaries
  are ambiguous: moving trailing bytes from the end of one field to the start
  of the next (e.g. `event_type="scan"`,`detail="started"` →
  `event_type="sca"`,`detail="nstarted"`) yields byte-identical hash input and
  therefore the **same** digest — a forgery by construction. Retained only so
  entries written by older agents keep verifying.

- **v2 — length-prefixed** (current):

  For each field in the fixed order `event_type, detail, prev_hash,
  created_at`, the hash input is an **8-byte big-endian unsigned integer**
  giving the byte-length of that field's UTF-8 encoding, immediately followed
  by those bytes:

  ```
  content_hash = sha256(
      u64be(len(event_type)) || event_type ||
      u64be(len(detail))     || detail     ||
      u64be(len(prev_hash))  || prev_hash  ||
      u64be(len(created_at)) || created_at
  )
  ```

  Prefixing every field with its exact byte length makes the boundaries
  unambiguous — no rearrangement of bytes across fields can reproduce the same
  digest — which closes the v1 field-shift forgery. This mirrors the
  multi-scheme approach the server's own `audit_log` took (migrations
  034/051): each row records the scheme it was written with and is re-derived
  under that scheme.

### Rollout / version compatibility

**The server MUST be upgraded to a `hash_version`-aware release before any
agent that writes v2 (length-prefixed) rows is rolled out.** The two halves are
independent binaries and a mixed-version fleet is expected during a rollout, so
ordering matters:

- A `hash_version`-aware server recomputes each entry under the scheme named by
  its `hash_version` field (absent → v1), so it verifies v1 and v2 rows alike.
- A **pre-`hash_version`** server ignores the field and recomputes **every**
  entry with the v1 plain-concat recipe. A v2 row's `content_hash` will not
  match that recomputation, so the server raises a false
  `alert_type = "audit_integrity"` (severity `high`) alert **on every shipped
  batch** for the duration of the rollout — noise that masks genuine tampering.

Upgrade the server first. This mirrors the install-gate contract's rollout note
(`install-gate-policy-map-v1.md`, "Compatibility rules": roll out the consuming
half before the producing half changes what it emits). The field is deliberately
additive (optional, default 1) so that once the server is `hash_version`-aware
the ordering constraint is one-directional — newer servers keep verifying older
v1-only agents indefinitely. No negotiation handshake is defined or required;
the rollout order is the operator's responsibility.

### Response body

```jsonc
{
  "received": 3,        // entries in the request
  "stored": 3,          // newly stored (re-ships are idempotent → 0)
  "verified_ok": true,  // false if ANY anomaly was detected
  "anomalies": []        // human-readable strings when verified_ok is false
}
```

## Server-side verification

For each batch (entries sorted by `entry_id`):

1. **Per-entry hash** — recompute `content_hash` using the entry's own
   `hash_version` encoding (see "Hash encodings" above; absent → v1); must
   equal `content_hash`.
2. **Intra-batch linkage** — each entry's `prev_hash` must equal the
   previous entry's `content_hash`.
3. **Tamper-after-ship** — if an `(device_id, entry_id)` was already
   witnessed, its `content_hash` must not have changed.
4. **Continuity** — the first not-yet-witnessed entry must chain onto the
   last witnessed entry for the device (no gaps, no fork).

Any failure: the offending entry is stored with `chain_ok = false`, a
single `alert_type = "audit_integrity"` (severity `high`, `ecosystem =
"all"`) alert is raised, and one `agent_audit_integrity_violation` row is
written to the server's own (independently hash-chained) `audit_log`.

## Storage

Table `agent_audit_entries` (migration `037_agent_audit_entries`) is itself
append-only (BEFORE UPDATE/DELETE trigger), so the server's witness of the
agent chain is as immutable as the primary `audit_log`.

## Idempotency / retries

De-duplication is on `(device_id, agent_entry_id)`. The agent may safely
re-ship overlapping ranges (e.g. after a crash before `MarkShipped`):
already-witnessed entries are skipped (`stored` excludes them) and, as long
as their content is unchanged, raise no alarm.
