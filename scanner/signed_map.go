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
	"os"
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
	return out, nil
}

// LoadVerifiedOverlayFromFile loads a signed envelope cached on disk,
// verifies it, and applies the overlay.  Returns false (without error)
// on any failure so callers can fall back to the baked-in defaults.
// Verification failures are the expected case after a signing-key
// rotation or disk tampering — callers should log at warning level.
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
	ApplyOverlay(*m)
	return true
}

// SaveVerifiedEnvelopeToFile persists the full signed envelope for
// offline reuse.  The envelope bytes (not the decoded LicenseMap) are
// what gets stored, so LoadVerifiedOverlayFromFile can re-verify on
// every load.  File mode 0600 — the envelope includes admin-curated
// mappings that may embed vendor IP.
func SaveVerifiedEnvelopeToFile(path string, envelope []byte) error {
	if len(envelope) > MaxMapPayloadBytes {
		return fmt.Errorf("envelope: exceeds max size")
	}
	return os.WriteFile(path, envelope, 0o600)
}
