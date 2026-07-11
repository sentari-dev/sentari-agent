// Signed license-map verification.
//
// The agent fetches license-map updates from the server as signed
// envelopes — {payload, signature, key_id} — and verifies the ed25519
// signature against a pinned public key before applying the overlay.
// The same verification runs when loading a cached envelope from disk,
// so disk-tampering (replacing license_map.json) cannot silently
// reclassify licenses fleet-wide.
//
// Canonical JSON rules: sorted keys at every level, no insignificant
// whitespace, UTF-8 with non-ASCII preserved, HTML chars not escaped.
// The server-side Python canonicalizer in server/services/signing.py
// produces identical bytes for the license-map schema.

package scanner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// MaxMapPayloadBytes is the hard cap on the canonical-JSON size of a
// license-map payload.  Matches server/services/signing.py constant.
const MaxMapPayloadBytes = 5 * 1024 * 1024 // 5 MiB

// TrustedMapKeys is the registry of ed25519 public keys the agent will
// accept as license-map signers, keyed by key_id.  Populated via
// RegisterTrustedMapKey at init time (from the pinned-keys file or a
// dev env override) — never mutated at runtime.
//
// trustedMapKeysMu guards the map: registration happens at init and on
// trust bootstrap (writers), while the verify hot path and diagnostic
// listing read it.  Without the lock, a register racing a verify is a
// concurrent map read/write (fatal in Go) — see audit finding 1.
var (
	trustedMapKeysMu sync.RWMutex
	trustedMapKeys   = map[string]ed25519.PublicKey{}
)

// RegisterTrustedMapKey pins a public key under a given key_id.  Intended
// to be called from package init blocks (trustkeys.go) and from dev-only
// env-var bootstrapping.  Silently no-ops on invalid key length so a
// bad env-var cannot crash the agent at startup.
func RegisterTrustedMapKey(keyID string, pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	trustedMapKeysMu.Lock()
	defer trustedMapKeysMu.Unlock()
	trustedMapKeys[keyID] = pub
}

// lookupTrustedMapKey returns the pinned key for keyID under a read lock.
func lookupTrustedMapKey(keyID string) (ed25519.PublicKey, bool) {
	trustedMapKeysMu.RLock()
	defer trustedMapKeysMu.RUnlock()
	pub, ok := trustedMapKeys[keyID]
	return pub, ok
}

// TrustedMapKeyIDs returns the list of pinned key IDs.  Exported for
// diagnostics and dev tooling; not used on the hot path.
func TrustedMapKeyIDs() []string {
	trustedMapKeysMu.RLock()
	defer trustedMapKeysMu.RUnlock()
	ids := make([]string, 0, len(trustedMapKeys))
	for k := range trustedMapKeys {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return ids
}

// signedEnvelope matches the server's signed-envelope JSON shape.
// Fields are decoded as json.RawMessage / string so the signature
// check can re-canonicalize the payload byte-for-byte rather than
// trusting Go's map-iteration order.
type signedEnvelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
	KeyID     string          `json:"key_id"`
}

// VerifyMapEnvelope parses a signed-envelope byte slice and returns the
// inner LicenseMap on success.  Returns a typed error on any failure
// so callers can log without leaking internals.
//
// Size cap, signature, and schema are all enforced here — callers
// should not apply any data that bypassed this function.
func VerifyMapEnvelope(data []byte) (*LicenseMap, error) {
	if len(data) == 0 {
		return nil, errors.New("envelope: empty input")
	}
	if len(data) > MaxMapPayloadBytes {
		return nil, fmt.Errorf("envelope: exceeds max size (%d > %d)", len(data), MaxMapPayloadBytes)
	}

	var env signedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("envelope: malformed JSON: %w", err)
	}
	if len(env.Payload) == 0 || env.Signature == "" || env.KeyID == "" {
		return nil, errors.New("envelope: missing required field")
	}

	pub, ok := lookupTrustedMapKey(env.KeyID)
	if !ok {
		return nil, fmt.Errorf("envelope: unknown signing key_id %q", env.KeyID)
	}

	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("envelope: signature not base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("envelope: signature wrong length (%d)", len(sig))
	}

	// Re-canonicalize the payload: Go's json.Marshal sorts map keys
	// alphabetically, and with HTML escaping disabled produces the
	// same bytes as the server's canonicalizer.  Decode via
	// canonicalizePayload (json.Number / UseNumber) so integer fields
	// at or above 2^53 round-trip exactly — a plain
	// map[string]interface{} would coerce every number to float64 and
	// break ed25519.Verify on an otherwise-valid envelope.
	canonical, err := canonicalizePayload(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: canonicalize: %w", err)
	}

	if !ed25519.Verify(pub, canonical, sig) {
		return nil, errors.New("envelope: signature verification failed")
	}

	// Schema-validate the payload into a LicenseMap.
	var m LicenseMap
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		return nil, fmt.Errorf("envelope: payload schema: %w", err)
	}
	if m.SPDXMap == nil || m.TierMap == nil {
		return nil, errors.New("envelope: missing spdx_map or tier_map")
	}
	// Reject if EITHER map is empty: a payload with a populated TierMap
	// but an empty SPDXMap (or vice-versa) is a partial-downgrade attack
	// that the old && check let through (audit finding 3).
	if len(m.SPDXMap) == 0 || len(m.TierMap) == 0 {
		return nil, errors.New("envelope: empty maps (possible downgrade)")
	}

	return &m, nil
}

// canonicalizePayload re-serializes a raw signed payload into its
// canonical form (sorted keys, no insignificant whitespace, no HTML
// escaping, no trailing newline) WITHOUT losing integer precision.
//
// It decodes with json.Decoder + UseNumber so every JSON number is
// held as a json.Number (its exact source text) rather than a float64.
// json.Marshal then emits json.Number values verbatim, so an integer
// such as the install-gate version epoch (>= 2^53) round-trips byte-
// for-byte instead of being coerced to a float and re-rendered with
// lost precision.  This keeps the agent's canonical bytes identical to
// the Python server's signing.canonical_json output.  Mirrors
// scanner/update/update.go:canonicalizePayload.
func canonicalizePayload(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("payload not valid JSON: %w", err)
	}
	if _, ok := v.(map[string]interface{}); !ok {
		return nil, errors.New("payload not a JSON object")
	}
	return canonicalJSON(v)
}

// canonicalJSON produces the canonical byte representation used for
// signing.  Sorted keys via json.Marshal on map[string]interface{},
// no whitespace, HTML escaping disabled.  Must match
// server.services.signing.canonical_json exactly.
//
// Go's encoding/json UNCONDITIONALLY escapes U+2028 (LINE SEPARATOR) to
// `\u2028` and U+2029 (PARAGRAPH SEPARATOR) to `\u2029` — SetEscapeHTML
// only governs <, >, & — whereas the server signs over
// json.dumps(ensure_ascii=False), which emits those runes as RAW UTF-8
// (E2 80 A8 / E2 80 A9).  Left uncorrected, any signed map whose payload
// contained one of those code points in a string would canonicalize to
// different bytes on the agent and its valid signature would be REJECTED.
// unescapeLineSeparators rewrites the escapes Go's encoder produced back
// to raw UTF-8 so the two canonical forms match byte-for-byte.
func canonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder appends a trailing '\n' which the Python
	// canonicalizer does not emit.  Strip it.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return unescapeLineSeparators(out), nil
}

// lineSepUTF8 / paragraphSepUTF8 are the raw UTF-8 encodings of U+2028 and
// U+2029 — the bytes Python's json.dumps(ensure_ascii=False) emits and the
// bytes we must substitute for Go's `\u2028` / `\u2029` escapes.
var (
	lineSepUTF8      = []byte{0xe2, 0x80, 0xa8}
	paragraphSepUTF8 = []byte{0xe2, 0x80, 0xa9}
)

// unescapeLineSeparators rewrites the `\u2028` / `\u2029` escape sequences
// that Go's json encoder emits for real U+2028 / U+2029 runes into their raw
// UTF-8 encodings, so the agent's canonical bytes match Python's
// ensure_ascii=False output.
//
// It is backslash-run aware, which a naive bytes.Replace is NOT: Go only
// emits `\u2028` for an actual rune, while a source string that literally
// contains the six characters `\u2028` is escaped to `\\u2028` (and Python
// emits the same `\\u2028`).  A blind replace of the substring `\u2028`
// would corrupt that `\\u2028` into `\`+U+2028 and DIVERGE from Python.  The
// discriminator: an escape Go produced for a rune has its `u2028` preceded
// by an ODD run of backslashes (the trailing one being the escape
// introducer); a literal `u2028` sits behind an EVEN run.  We only rewrite
// the odd-run (genuine escape) case.
func unescapeLineSeparators(b []byte) []byte {
	// Fast path: neither escape present, nothing to rewrite.
	if !bytes.Contains(b, []byte(`\u2028`)) && !bytes.Contains(b, []byte(`\u2029`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	backslashes := 0 // consecutive backslashes immediately before index i
	for i := 0; i < len(b); {
		c := b[i]
		if c == '\\' {
			// A genuine rune escape starts with a backslash whose run length
			// INCLUDING itself is odd, i.e. the count of preceding backslashes
			// is even.
			if backslashes%2 == 0 && i+5 < len(b) &&
				b[i+1] == 'u' && b[i+2] == '2' && b[i+3] == '0' && b[i+4] == '2' &&
				(b[i+5] == '8' || b[i+5] == '9') {
				if b[i+5] == '8' {
					out = append(out, lineSepUTF8...)
				} else {
					out = append(out, paragraphSepUTF8...)
				}
				i += 6
				backslashes = 0
				continue
			}
			backslashes++
			out = append(out, c)
			i++
			continue
		}
		backslashes = 0
		out = append(out, c)
		i++
	}
	return out
}

// mapVersionHWM records the highest license-map version this agent has
// ever verified-and-applied, persisted next to the on-disk cache.  It is
// the rollback floor: a validly-signed but STALE cached map (an attacker
// who swaps license_map.json for an older, still-signed envelope) is
// refused rather than silently downgrading entitlements.
//
// It mirrors scanner/update/state.go's freshness high-water mark: the
// update/install-gate paths already persist a monotonic version to defeat
// replay; the license-map disk-cache load path had no equivalent floor
// (audit security-3), so a signed-but-old map loaded straight from disk.
type mapVersionHWM struct {
	Version int `json:"version"`
}

// hwmSidecarPath is the marker file for the cache at cachePath — the same
// name with a ".hwm" suffix, so it lives beside the cache under the agent
// data dir and shares its 0600 handling.
func hwmSidecarPath(cachePath string) string {
	return cachePath + ".hwm"
}

// readMapVersionHWM returns the persisted floor for cachePath.  A missing
// or unreadable/malformed sidecar returns 0 (no floor) — fail-safe: a
// first-ever load, or a wiped marker, must not be blocked, and the worst
// case is that we accept a map we would otherwise have floored, never
// that we reject a legitimate newer map.
func readMapVersionHWM(cachePath string) int {
	raw, err := os.ReadFile(hwmSidecarPath(cachePath))
	if err != nil {
		return 0
	}
	var hw mapVersionHWM
	if err := json.Unmarshal(raw, &hw); err != nil {
		return 0
	}
	if hw.Version < 0 {
		return 0
	}
	return hw.Version
}

// writeMapVersionHWM advances the persisted floor for cachePath to
// version, atomically (temp file + rename) so a crash mid-write cannot
// corrupt it.  Only ever called with a version we have just verified and
// applied.  Best-effort: a write failure is returned for the caller to
// log, but never blocks applying the (already-verified) map.
func writeMapVersionHWM(cachePath string, version int) error {
	raw, err := json.Marshal(mapVersionHWM{Version: version})
	if err != nil {
		return fmt.Errorf("hwm: marshal: %w", err)
	}
	dst := hwmSidecarPath(cachePath)
	tmp := dst + ".tmp"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("hwm: create dir: %w", err)
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("hwm: write: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hwm: commit: %w", err)
	}
	return nil
}

// LoadVerifiedOverlayFromFile loads a signed envelope cached on disk,
// verifies it, and applies the overlay.  Returns false (without error)
// on any failure so callers can fall back to the baked-in defaults.
// Verification failures are the expected case after a signing-key
// rotation or disk tampering — callers should log at warning level.
//
// Rollback floor (audit security-3): even a validly-signed cached map is
// REFUSED if its Version is below the persisted high-water mark, so an
// attacker who replaces the cache with an older-but-still-signed envelope
// cannot roll the agent back to stale entitlements.  A successful load at
// or above the floor advances the mark.  The signature check alone does
// not catch this — the old map was legitimately signed once — so the
// monotonic version floor is the only defence.
func LoadVerifiedOverlayFromFile(path string) bool {
	// Bounded, symlink-/special-file-refusing read.  A plain os.ReadFile
	// would slurp a multi-GiB corrupt cache into memory (OOM) or block
	// forever on a FIFO before VerifyMapEnvelope's size cap could fire
	// (audit finding 2).  safeio.ReadFile stat-checks the size and the
	// file type up front.  Cap at MaxMapPayloadBytes — VerifyMapEnvelope
	// re-applies the same cap defensively.
	data, err := safeio.ReadFile(path, MaxMapPayloadBytes)
	if err != nil {
		return false
	}
	m, err := VerifyMapEnvelope(data)
	if err != nil {
		return false
	}

	// Refuse a downgrade: a cached map older than the floor is a rollback
	// attempt (or a stale cache left after an update elsewhere).  Fail
	// safe — treat as no overlay so the compiled-in defaults or a
	// previously-applied in-memory overlay stand.
	if floor := readMapVersionHWM(path); m.Version < floor {
		slog.Warn("refusing rolled-back license map from cache",
			slog.Int("cached_version", m.Version),
			slog.Int("floor_version", floor),
			slog.String("path", path))
		return false
	}

	ApplyOverlay(*m)

	// Advance the floor so a later swap to any older signed map is
	// refused.  Best-effort: the overlay is already applied; a marker
	// write failure only weakens the NEXT load's floor, so log and move on.
	if err := writeMapVersionHWM(path, m.Version); err != nil {
		slog.Warn("failed to persist license-map version floor",
			slog.Int("version", m.Version), slog.String("err", err.Error()))
	}
	return true
}

// SaveVerifiedEnvelopeToFile persists the full signed envelope for
// offline reuse.  The envelope bytes (not the decoded LicenseMap) are
// what gets stored, so LoadVerifiedOverlayFromFile can re-verify on
// every load.  File mode 0600 — the envelope includes admin-curated
// mappings that may embed vendor IP.
//
// This is the online-update persistence twin of LoadVerifiedOverlayFromFile:
// the fetch path applies a freshly-verified map (ApplyOverlay) and then
// caches its envelope here.  To keep the rollback floor monotonic across
// BOTH entry points, this advances the version high-water mark to the
// newly-cached map's version, so a subsequent disk swap to an older
// signed envelope is refused on the next load.
func SaveVerifiedEnvelopeToFile(path string, envelope []byte) error {
	if len(envelope) > MaxMapPayloadBytes {
		return fmt.Errorf("envelope: exceeds max size")
	}
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		return err
	}
	// Advance the floor to the just-cached map's version.  Re-verify the
	// envelope to extract a trustworthy version (never trust an unverified
	// parse for a security floor); on any verification issue, skip the
	// bump rather than fail the save — the envelope itself is already
	// safely persisted and Load re-verifies regardless.  Only advance,
	// never lower, the mark.
	if m, err := VerifyMapEnvelope(envelope); err == nil {
		if m.Version > readMapVersionHWM(path) {
			if err := writeMapVersionHWM(path, m.Version); err != nil {
				slog.Warn("failed to persist license-map version floor on save",
					slog.Int("version", m.Version), slog.String("err", err.Error()))
			}
		}
	}
	return nil
}
